"""LLM narration of findings — a narrator, never an analyst.

Per finding: one API call whose prompt contains ONLY the rule title, the
evidence dict, the engine, and the rule's template action text. A digit
guard post-validates the output: any number that does not appear in the
prompt inputs rejects the paragraph (retry once, then fall back to the
rule's deterministic template text). Responses are cached by finding hash;
the whole product works offline on template text if the API is down.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path

from app.vendor.dbdoctor.engine.rules.base import Finding

DEFAULT_MODEL = "claude-opus-4-8"
MAX_TOKENS = 400

SYSTEM_PROMPT = (
    "You are writing one paragraph for a database audit report, addressed to a "
    "developer without DBA experience. Use ONLY the numbers provided in the "
    "evidence — never introduce a number that is not given to you. Never promise "
    "a specific performance improvement. Be concrete and plain-spoken. End with "
    "one concrete next step."
)

RETRY_REMINDER = (
    "Your previous draft contained a number that is not in the evidence. Rewrite "
    "the paragraph using ONLY the numbers given above, or no numbers at all."
)


def finding_key(finding: Finding) -> str:
    """Stable identity of a finding for caching and cross-referencing."""
    payload = json.dumps(
        [finding.rule_id, finding.affected_object, finding.engine, finding.evidence],
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


# --------------------------------------------------------------------------
# Digit guard
# --------------------------------------------------------------------------

_DIGIT_GROUP = re.compile(r"\d[\d,]*(?:\.\d+)?")


def _normalize(token: str) -> str:
    return token.replace(",", "")


def allowed_numbers(*sources: str) -> tuple[set[str], set[float]]:
    """Every number appearing in the prompt inputs, as strings and floats.

    Formatting variants are tolerated: '6,300.9' matches evidence '6300.9',
    and the integer part ('6300') of any allowed number is also allowed.
    """
    strings: set[str] = set()
    floats: set[float] = set()
    for source in sources:
        for token in _DIGIT_GROUP.findall(source):
            norm = _normalize(token)
            strings.add(norm)
            try:
                value = float(norm)
            except ValueError:
                continue
            floats.add(value)
            strings.add(str(int(value)))  # integer part as a variant
            floats.add(float(int(value)))
    return strings, floats


def digit_violations(text: str, strings: set[str], floats: set[float]) -> list[str]:
    """Numbers in *text* that are not grounded in the prompt inputs."""
    bad = []
    for token in _DIGIT_GROUP.findall(text):
        norm = _normalize(token)
        if norm in strings:
            continue
        try:
            if float(norm) in floats:
                continue
        except ValueError:
            pass
        bad.append(token)
    return bad


# --------------------------------------------------------------------------
# Explainer
# --------------------------------------------------------------------------


class AiExplainer:
    """Explains findings via the Anthropic API with cache + offline fallback.

    Pass a pre-built client for tests; otherwise one is created lazily only
    when an API key is available. Without a key every finding gets its
    rule's template text — the product must work fully offline.
    """

    def __init__(
        self,
        model: str | None = None,
        cache_dir: str | Path = ".cache/ai_explain",
        client=None,
    ):
        self.model = model or os.environ.get("DBDOCTOR_AI_MODEL", DEFAULT_MODEL)
        self.cache_dir = Path(cache_dir)
        self._client = client
        self._client_initialized = client is not None

    # -- plumbing ----------------------------------------------------------

    def _get_client(self):
        if not self._client_initialized:
            self._client_initialized = True
            if os.environ.get("ANTHROPIC_API_KEY"):
                import anthropic

                self._client = anthropic.Anthropic()
        return self._client

    def _cache_path(self, finding: Finding) -> Path:
        return self.cache_dir / f"{finding_key(finding)}-{self.model}.txt"

    # -- public API --------------------------------------------------------

    def explain(self, finding: Finding) -> str:
        """One grounded paragraph for *finding*; template text on any failure."""
        cache = self._cache_path(finding)
        if cache.exists():
            return cache.read_text(encoding="utf-8")

        client = self._get_client()
        if client is None:
            return finding.suggested_action  # offline: deterministic template text

        prompt = self._prompt_for(finding)
        strings, floats = allowed_numbers(prompt)

        text = self._ask(client, prompt)
        if text is not None and digit_violations(text, strings, floats):
            text = self._ask(client, f"{prompt}\n\n{RETRY_REMINDER}")
        if text is None or digit_violations(text, strings, floats):
            return finding.suggested_action  # reject: fall back, never publish

        self.cache_dir.mkdir(parents=True, exist_ok=True)
        cache.write_text(text, encoding="utf-8")
        return text

    def explain_all(self, findings: list[Finding]) -> dict[str, str]:
        return {finding_key(f): self.explain(f) for f in findings}

    # -- internals ----------------------------------------------------------

    def _prompt_for(self, finding: Finding) -> str:
        evidence = json.dumps(finding.evidence, indent=2, default=str)
        return (
            f"Finding: {finding.title}\n"
            f"Database engine: {finding.engine}\n"
            f"Affected object: {finding.affected_object}\n"
            f"Evidence (the ONLY numbers you may use):\n{evidence}\n\n"
            f"Suggested action from our rule engine:\n{finding.suggested_action}\n\n"
            "Write the paragraph now."
        )

    def _ask(self, client, prompt: str) -> str | None:
        try:
            response = client.messages.create(
                model=self.model,
                max_tokens=MAX_TOKENS,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
            )
        except Exception:
            return None  # API down / rate limited: caller falls back
        if getattr(response, "stop_reason", None) == "refusal":
            return None
        for block in response.content:
            if block.type == "text":
                return block.text
        return None
