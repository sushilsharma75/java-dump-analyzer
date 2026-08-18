"""LLM layer: payload trimming, unified bundling, and current model id.

No network calls — exercises only the pure helpers and request-shaping config.
"""
import inspect

from app.analyzers import llm


def test_default_model_is_current():
    # The parameter defaults to None so an explicit per-request override wins;
    # the actual default lives in DEFAULT_MODEL (ANTHROPIC_MODEL-overridable).
    sig = inspect.signature(llm.generate_llm_summary)
    assert sig.parameters["model"].default is None
    assert llm.DEFAULT_MODEL == "claude-opus-5"


def test_trim_thread_drops_raw_keeps_top_frames():
    analysis = {
        "threads": [{
            "name": "t1", "state": "RUNNABLE", "daemon": False,
            "raw": "x" * 10_000,
            "stack": [{"class_name": "com.example.A", "method": "m"}] * 8,
            "locks": [{"op": "locked", "address": "0x1", "class_name": "C"}],
        }],
        "stack_groups": list(range(50)),
    }
    out = llm._trim_for_llm(analysis, "thread")
    t = out["threads"][0]
    assert "raw" not in t
    assert t["top_frames"] == ["com.example.A.m"] * 5  # capped at 5
    assert len(out["stack_groups"]) == 10


def test_trim_heap_caps_histograms():
    analysis = {
        "top_classes_by_count": [{"class_name": f"C{i}"} for i in range(50)],
        "top_classes_by_size": [{"class_name": f"C{i}"} for i in range(50)],
    }
    out = llm._trim_for_llm(analysis, "heap")
    assert len(out["top_classes_by_count"]) == 20
    assert len(out["top_classes_by_size"]) == 20


def test_trim_unified_bundles_three():
    bundle = {
        "heap": {"top_classes_by_size": [], "top_classes_by_count": [], "findings": []},
        "thread": {"threads": [], "stack_groups": [], "findings": []},
        "correlation": {"summary": "1 matched", "matched_classes": 1, "findings": []},
    }
    out = llm._trim_for_llm(bundle, "unified")
    assert set(out) == {"heap", "thread", "correlation"}
    assert out["correlation"]["summary"] == "1 matched"


def test_prompts_present():
    assert llm.SYSTEM_PROMPT.strip()
    assert llm.UNIFIED_SYSTEM_PROMPT.strip()
    # The unified prompt enforces the entry-level structure.
    for heading in ("Verdict", "Evidence", "Where in your code", "The fix"):
        assert heading in llm.UNIFIED_SYSTEM_PROMPT
    # Both prompts must forbid over-claiming on a partial or gated analysis.
    for prompt in (llm.SYSTEM_PROMPT, llm.UNIFIED_SYSTEM_PROMPT):
        assert "truncated" in prompt and "skipped_analyses" in prompt


# --- error surfacing -------------------------------------------------------
# A rejected request used to reach the UI as "Client error '400 Bad Request'",
# which says nothing about what to change. These pin the message through.

import asyncio

import httpx


def _resp(status, payload):
    return httpx.Response(
        status, json=payload,
        request=httpx.Request("POST", llm.API_URL),
    )


def test_api_error_carries_the_api_message():
    r = _resp(400, {"type": "error", "error": {
        "type": "invalid_request_error",
        "message": "model: claude-opus-5 not found",
    }})
    err = llm._api_error(r, "claude-opus-5")
    assert err.status == 400
    assert "claude-opus-5 not found" in err.api_message
    # and it must say what to do about it
    assert "ANTHROPIC_MODEL" in err.hint


def test_api_error_hints_are_status_specific():
    assert "key" in llm._api_error(
        _resp(401, {"error": {"message": "invalid x-api-key"}}), "m").hint.lower()
    assert "rate" in llm._api_error(
        _resp(429, {"error": {"message": "rate_limit_error"}}), "m").hint.lower()
    assert "anthropic-side" in llm._api_error(
        _resp(503, {"error": {"message": "overloaded"}}), "m").hint.lower()


def test_api_error_survives_a_non_json_body():
    r = httpx.Response(502, text="<html>bad gateway</html>",
                       request=httpx.Request("POST", llm.API_URL))
    err = llm._api_error(r, "m")
    assert "bad gateway" in err.api_message


def test_generate_raises_llm_request_error_with_detail(monkeypatch):
    class _Client:
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, url, headers=None, json=None):
            return _resp(400, {"error": {"message": "max_tokens: exceeds model limit"}})

    monkeypatch.setattr(llm.httpx, "AsyncClient", lambda **kw: _Client())
    try:
        asyncio.run(llm.generate_llm_summary({"findings": []}, "heap", "sk-ant-test"))
    except llm.LLMRequestError as e:
        assert "max_tokens" in e.api_message
    else:
        raise AssertionError("expected LLMRequestError")


def test_model_override_is_sent(monkeypatch):
    seen = {}

    class _Client:
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, url, headers=None, json=None):
            seen.update(json)
            return _resp(200, {"content": [{"type": "text", "text": "ok"}]})

    monkeypatch.setattr(llm.httpx, "AsyncClient", lambda **kw: _Client())
    out = asyncio.run(llm.generate_llm_summary(
        {"findings": []}, "heap", "sk-ant-test", model="claude-sonnet-5"))
    assert out == "ok"
    assert seen["model"] == "claude-sonnet-5"
    assert seen["thinking"] == {"type": "adaptive"}
