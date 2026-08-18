"""
Optional, pluggable LLM-powered diagnosis layer.

Takes a structured analysis result and asks Claude to translate it into
prescriptive, plain-English remediation guidance written for the engineer
who has to fix the problem.

The API key is supplied per-request (never stored). If no key is provided,
the endpoint returns enabled=False and the UI falls back to rule-based
findings only.
"""
from __future__ import annotations
import json
import os
from typing import Dict, Any, Optional
import httpx


SYSTEM_PROMPT = """You are a senior JVM performance engineer. You are given a structured
analysis of a Java thread dump or heap dump. Produce a concise diagnostic write-up for the
engineer fixing the issue.

Rules:
- Lead with the single most likely root cause in one sentence.
- Then 3-5 bullet points: what's happening, evidence from the data, what to check next.
- Then concrete remediation steps, ordered by impact.
- Use plain English, no JVM jargon unless it adds clarity.
- Reference specific thread names, class names, or counts from the data so the reader trusts the diagnosis.
- Be honest about uncertainty: if the data doesn't conclusively point to one cause, list the top two hypotheses.
- Check `truncated` and `skipped_analyses` before you commit to a conclusion. If `truncated` is
  true the numbers describe a sampled prefix, not the heap — say so and rank hypotheses instead of
  naming a root cause. If `skipped_analyses` is non-empty, the absence of a leak suspect is not
  evidence of no leak; name the stage that didn't run and what re-running it would settle.
- Never present a shallow size as a retained size. Shallow is the object itself; retained is what
  its collection would free, and only `dominators` / `reachable_bytes` carry that.
- Keep it under 250 words."""


# Unified diagnosis: synthesizes heap + thread + correlation + source into one
# report written so an entry-level developer can find and fix the bug.
UNIFIED_SYSTEM_PROMPT = """You are a senior JVM performance engineer mentoring a junior developer.
You are given a combined post-mortem: a heap dump analysis, a thread dump analysis, and a
cross-correlation that links classes filling the heap to live thread stack frames. A GC-log
analysis may also be present (`gc`): its `heap_after_trend_mb_per_min` tells you whether the
live set is genuinely growing over time (a leak) versus merely large — cite it when it
confirms or contradicts the heap snapshot. When a source repo was attached, findings carry
`source_locations` with `repo_path`, `line`, and a code `snippet` — these are the exact lines
responsible.

Write a single diagnosis a developer with ~1 year of Java experience can act on. Explain any
JVM jargon in a few words the first time you use it. Use this exact structure with these
markdown headings:

## Verdict
One sentence: the single most likely root cause, followed by a confidence level — **(Confidence: High|Medium|Low)**.

## What's happening
2-4 short bullets in plain English: what the evidence shows and why it's a problem.

## Evidence
3-5 bullets citing concrete numbers and names from the data — class names, instance counts,
percentages of heap, thread names, and (when correlation matched) the fact that the same class
appears in both dumps. This is what makes the diagnosis trustworthy.

## Where in your code
The exact `file:line` to open, taken from the findings' source_locations (prefer correlation,
then heap static-field suspects). If no source was attached, give the class/method/line tuple
and say to attach the source repo for precise lines.

## The fix
Numbered, concrete steps ordered by impact. Include a SHORT before/after code sketch in a
```java code block when it clarifies the fix (e.g. a bounded cache, pagination, or
try-with-resources). Name specific tools where relevant (Caffeine, Guava CacheBuilder).

## How to verify
1-2 sentences: how to confirm the fix worked (e.g. re-take a heap dump and check the class
dropped, or watch GC logs).

Be honest about uncertainty: if two causes are plausible, say so and rank them. Do not invent
file paths, line numbers, or counts that aren't in the data.

Two fields on the heap analysis govern how confident you are allowed to be. `truncated` means only
a prefix of the dump was read — every count and percentage describes that prefix, so downgrade the
verdict's confidence and say which number you would want from a full parse. `skipped_analyses`
lists the stages that were gated out; a quiet dominator section means nothing if the dominator
stage is in that list, so name it rather than concluding the heap is healthy. Also keep shallow and
retained size distinct: only `dominators` and `reachable_bytes` are retained sizes.

Keep the whole thing under 450 words."""


DEFAULT_MODEL = os.environ.get("ANTHROPIC_MODEL") or "claude-opus-5"

API_URL = "https://api.anthropic.com/v1/messages"


class LLMRequestError(Exception):
    """An API rejection, carrying what the API actually said.

    httpx's own HTTPStatusError message is only the status line, which turns
    every rejection into an unactionable "400 Bad Request". The API always
    explains itself in the response body; this carries that through to the UI.
    """

    def __init__(self, status: int, message: str, hint: Optional[str] = None):
        self.status = status
        self.api_message = message
        self.hint = hint
        super().__init__(" ".join(p for p in (message, hint) if p))


async def generate_llm_summary(
    analysis: Dict[str, Any],
    kind: str,
    api_key: str,
    model: Optional[str] = None,
) -> str:
    """Call the Anthropic API directly. Returns the markdown summary."""
    model = model or DEFAULT_MODEL
    # Trim the analysis payload so we don't blow context: drop raw thread bodies
    trimmed = _trim_for_llm(analysis, kind)

    if kind == "unified":
        system = UNIFIED_SYSTEM_PROMPT
        user_message = (
            "Here is a combined JVM post-mortem — a heap dump analysis, a thread dump "
            "analysis, and their cross-correlation. Produce one unified diagnosis using the "
            "required structure.\n\n"
            f"```json\n{json.dumps(trimmed, indent=2)[:120_000]}\n```"
        )
    else:
        system = SYSTEM_PROMPT
        user_message = (
            f"Here is a structured {kind} dump analysis. Diagnose the most likely problem "
            f"and recommend remediation.\n\n"
            f"```json\n{json.dumps(trimmed, indent=2)[:60_000]}\n```"
        )

    # Adaptive thinking on every kind: these are diagnostic judgements, and the
    # headroom costs nothing when the model decides it doesn't need it.
    payload = {
        "model": model,
        "max_tokens": 8000,
        "system": system,
        "thinking": {"type": "adaptive"},
        "messages": [{"role": "user", "content": user_message}],
    }

    async with httpx.AsyncClient(timeout=120.0) as client:
        resp = await client.post(
            API_URL,
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json=payload,
        )
        if resp.status_code >= 400:
            raise _api_error(resp, model)
        data = resp.json()
        # Anthropic returns content blocks; join all text blocks (skip thinking blocks)
        text = "".join(
            block.get("text", "")
            for block in data.get("content", [])
            if block.get("type") == "text"
        )
        if not text.strip():
            stop = data.get("stop_reason")
            raise LLMRequestError(
                200,
                f"The model returned no text (stop_reason: {stop}).",
                "Retry, or set ANTHROPIC_MODEL on the backend to use a different model."
                if stop == "refusal" else None,
            )
        return text


def _api_error(resp: httpx.Response, model: str) -> LLMRequestError:
    """Turn an error response into something the user can act on."""
    try:
        body = resp.json()
        err = body.get("error") or {}
        message = err.get("message") or body.get("message") or ""
    except Exception:
        message = (resp.text or "")[:400]
    if not message:
        message = f"HTTP {resp.status_code} with no error body."

    hint = None
    low = message.lower()
    if resp.status_code in (400, 403, 404) and ("model" in low or "not_found" in low):
        hint = (
            f"The request asked for `{model}`. If this key's organisation can't use that "
            "model, set ANTHROPIC_MODEL on the backend to one it can (e.g. claude-opus-4-8 "
            "or claude-sonnet-5) and retry."
        )
    elif resp.status_code == 401:
        hint = "The API key was rejected — check it was pasted in full."
    elif resp.status_code == 429:
        hint = "Rate limited. Wait a moment and retry."
    elif resp.status_code >= 500:
        hint = "That's an Anthropic-side error; retrying usually clears it."

    return LLMRequestError(resp.status_code, message, hint)


def _trim_for_llm(analysis: Dict[str, Any], kind: str) -> Dict[str, Any]:
    """Strip noisy fields and oversized arrays before sending to the LLM."""
    a = dict(analysis)  # shallow copy
    if kind == "unified":
        # Bundle of {heap, thread, correlation}; trim each sub-analysis with its
        # own rules and keep the (already-small) correlation result intact.
        out: Dict[str, Any] = {}
        if a.get("heap"):
            out["heap"] = _trim_for_llm(a["heap"], "heap")
        if a.get("thread"):
            out["thread"] = _trim_for_llm(a["thread"], "thread")
        if a.get("correlation"):
            out["correlation"] = a["correlation"]
        if a.get("gc"):
            out["gc"] = _trim_for_llm(a["gc"], "gc")
        return out
    if kind == "gc":
        # The per-event series is for charting; the metrics + findings carry the
        # signal, so keep only a small sample of events for the model.
        a["events"] = (a.get("events") or [])[:60]
        return a
    if kind == "thread":
        # Drop raw thread text - the findings already capture the signal
        threads = a.get("threads") or []
        a["threads"] = [
            {
                "name": t.get("name"),
                "state": t.get("state"),
                "daemon": t.get("daemon"),
                "top_frames": [f"{f.get('class_name')}.{f.get('method')}"
                               for f in (t.get("stack") or [])[:5]],
                "wanted_lock": t.get("wanted_lock"),
                "held_locks": [{"address": l.get("address"), "class_name": l.get("class_name")}
                               for l in (t.get("locks") or []) if l.get("op") == "locked"][:5],
            }
            for t in threads[:80]
        ]
        # Cap stack groups too
        a["stack_groups"] = (a.get("stack_groups") or [])[:10]
    elif kind == "heap":
        a["top_classes_by_count"] = (a.get("top_classes_by_count") or [])[:20]
        a["top_classes_by_size"] = (a.get("top_classes_by_size") or [])[:20]
    return a
