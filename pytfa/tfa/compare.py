"""Pairwise reference comparison: one known-GOOD flow vs one known-BAD flow.

This is the complement to the population baseline. Where `analyze` asks "what did
the other N runs do?", `compare` asks "how does this one run differ from that one
run?" - so it works with exactly two reference ids and no population at all.

It surfaces the four ways a flow breaks:

  1. business logic   - the bad flow took a different branch (sequence diff)
  2. exception        - an ERROR/stack trace present in one flow and not the other
  3. missing param    - a payload field present in good, absent in bad
  4. wrong payload    - a payload field whose value differs between the flows

Records are grouped by a literal reference id found anywhere in the line, so no
correlation pattern needs configuring.
"""
from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field
from typing import Iterable, Optional

from .ingest import epoch_millis
from .model import Episode, LogRecord

# key=value, tolerating quoted strings and {...} blocks: payload={item=laptop, quantity=1}
_KV = re.compile(r'([A-Za-z_][A-Za-z0-9_.]*)\s*=\s*("[^"]*"|\{[^}]*\}|\[[^\]]*\]|[^\s,;}\])]+)')
# fields that legitimately differ between any two runs and are not defects
_NOISE_KEYS = {"trace_id", "traceid", "span_id", "spanid", "requestid", "request_id",
               "orderid", "order_id", "paymentid", "payment_id", "id", "timestamp", "ts"}


def extract_payload(message: str) -> dict[str, str]:
    """key=value pairs from a log message, flattening nested {a=1, b=2} blocks."""
    out: dict[str, str] = {}
    if not message:
        return out
    for key, value in _KV.findall(message):
        value = value.strip()
        if value.startswith("{") and value.endswith("}"):
            for k2, v2 in _KV.findall(value[1:-1]):
                out[k2] = v2.strip().strip('"')
            continue
        out[key] = value.strip('"')
    return out


def significant_payload(message: str) -> dict[str, str]:
    return {k: v for k, v in extract_payload(message).items() if k.lower() not in _NOISE_KEYS}


@dataclass
class FieldDiff:
    key: str
    good: Optional[str]
    bad: Optional[str]

    @property
    def kind(self) -> str:
        if self.bad is None:
            return "MISSING_IN_BAD"      # parameter missed in the request payload
        if self.good is None:
            return "EXTRA_IN_BAD"
        return "VALUE_DIFFERS"           # payload is wrong


@dataclass
class StepDiff:
    kind: str                            # SAME | ONLY_IN_GOOD | ONLY_IN_BAD
    call_site: str
    good: Optional[LogRecord] = None
    bad: Optional[LogRecord] = None
    fields: list[FieldDiff] = field(default_factory=list)

    def has_payload_issue(self) -> bool:
        return bool(self.fields)


@dataclass
class ComparisonResult:
    good_id: str
    bad_id: str
    good: Episode
    bad: Episode
    steps: list[StepDiff]
    break_index: Optional[int]           # index into steps where they first diverge
    errors_only_in_bad: list[LogRecord]
    good_duration_ms: int
    bad_duration_ms: int

    @property
    def break_step(self) -> Optional[StepDiff]:
        return self.steps[self.break_index] if self.break_index is not None else None

    def payload_issues(self) -> list[StepDiff]:
        return [s for s in self.steps if s.has_payload_issue()]


def _duration(e: Episode) -> int:
    if e.start is None or e.end is None:
        return 0
    return max(0, epoch_millis(e.end) - epoch_millis(e.start))


def validate_reference_id(ref: str) -> str:
    """A reference id is a single token: no spaces, matched exactly."""
    ref = (ref or "").strip()
    if not ref:
        raise ValueError("reference id must not be empty")
    if any(ch.isspace() for ch in ref):
        raise ValueError(f"reference id must not contain spaces: {ref!r}")
    return ref


def _exact_token(ref: str) -> re.Pattern:
    """Match the id as a WHOLE token, never as part of a longer id."""
    return re.compile(r"(?<![0-9A-Za-z_-])" + re.escape(ref) + r"(?![0-9A-Za-z_-])")


def episodes_for_ids(records: Iterable[LogRecord], good_id: str, bad_id: str
                     ) -> tuple[Episode, Episode]:
    """Collect every record whose line contains each reference id as an exact token."""
    good_id = validate_reference_id(good_id)
    bad_id = validate_reference_id(bad_id)
    if good_id == bad_id:
        raise ValueError("the two reference ids are identical - nothing to compare")
    patterns = {good_id: _exact_token(good_id), bad_id: _exact_token(bad_id)}
    buckets: dict[str, list[LogRecord]] = {good_id: [], bad_id: []}
    for r in records:
        text = r.message or ""
        for ref, pat in patterns.items():
            if pat.search(text):
                buckets[ref].append(r)
    out = []
    for ref in (good_id, bad_id):
        rs = sorted(buckets[ref], key=lambda r: (r.timestamp is None, r.timestamp))
        e = Episode(ref)
        for r in rs:
            e.add(r)
        out.append(e)
    return out[0], out[1]


def compare_flows(good: Episode, bad: Episode, good_id: str, bad_id: str) -> ComparisonResult:
    a = good.call_site_sequence()
    b = bad.call_site_sequence()
    steps: list[StepDiff] = []
    break_index: Optional[int] = None

    matcher = difflib.SequenceMatcher(a=a, b=b, autojunk=False)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            for off in range(i2 - i1):
                gr, br = good.records[i1 + off], bad.records[j1 + off]
                fields = _diff_fields(gr, br)
                steps.append(StepDiff("SAME", a[i1 + off], gr, br, fields))
                if fields and break_index is None:
                    break_index = len(steps) - 1     # same path, wrong payload
        else:
            if break_index is None:
                break_index = len(steps)
            for i in range(i1, i2):
                steps.append(StepDiff("ONLY_IN_GOOD", a[i], good.records[i], None))
            for j in range(j1, j2):
                steps.append(StepDiff("ONLY_IN_BAD", b[j], None, bad.records[j]))

    good_sites = set(a)
    errors_only_in_bad = [r for r in bad.records
                          if (r.level or "").upper() == "ERROR" or r.has_stack_trace()]
    errors_only_in_bad = [r for r in errors_only_in_bad if r.call_site() not in good_sites
                          or not any((g.level or "").upper() == "ERROR" for g in good.records)]

    return ComparisonResult(good_id, bad_id, good, bad, steps, break_index,
                            errors_only_in_bad, _duration(good), _duration(bad))


def _diff_fields(good_rec: LogRecord, bad_rec: LogRecord) -> list[FieldDiff]:
    g = significant_payload(good_rec.message)
    b = significant_payload(bad_rec.message)
    diffs: list[FieldDiff] = []
    for key in sorted(set(g) | set(b)):
        gv, bv = g.get(key), b.get(key)
        if gv != bv:
            diffs.append(FieldDiff(key, gv, bv))
    return diffs


# --------------------------------------------------------------------- report

def _envelope(r: LogRecord) -> str:
    return f"{r.timestamp} | {r.level} | {r.thread_id} | {r.call_site()} | {r.message}"


def render_comparison(c: ComparisonResult, show_all: bool = False) -> str:
    L: list[str] = []
    bar = "=" * 78
    L.append(bar)
    L.append("TFA FLOW COMPARISON  (reference GOOD vs reference BAD)")
    L.append(bar)
    def _summary(e, ms):
        flag = "  (contains ERROR)" if e.has_error_record() or e.has_stack_trace() else ""
        return f"         {e.size()} records, {ms:,} ms{flag}"
    L.append(f"  GOOD : {c.good_id}")
    L.append(_summary(c.good, c.good_duration_ms))
    L.append(f"  BAD  : {c.bad_id}")
    L.append(_summary(c.bad, c.bad_duration_ms))
    L.append("")

    if c.good.size() == 0 or c.bad.size() == 0:
        missing = [n for n, e in (("GOOD", c.good), ("BAD", c.bad)) if e.size() == 0]
        L.append(f"  ERROR: no log lines found for the {' and '.join(missing)} reference id.")
        L.append("         Check the id is exact (it is matched as a whole token) and that the")
        L.append("         log folder contains the files for that flow.")
        L.append(bar)
        return "\n".join(L) + "\n"

    # --- the break -----------------------------------------------------------
    L.append("-" * 78)
    if c.break_index is None:
        L.append("NO BREAK FOUND - both flows took the same path with the same payload values.")
    else:
        step = c.break_step
        L.append(f"THE BREAK  (step {c.break_index + 1} of {len(c.steps)})")
        L.append("")
        if step.kind == "SAME" and step.fields:
            L.append(f"  Same step, different data: {step.call_site}")
            for f in step.fields:
                L.append(f"    {f.key}: good={f.good!r}  bad={f.bad!r}   [{f.kind}]")
            L.append("")
            L.append(f"    good: {_envelope(step.good)}")
            L.append(f"    bad : {_envelope(step.bad)}")
        elif step.kind == "ONLY_IN_GOOD":
            L.append(f"  The good flow did this step; the bad flow never did:")
            L.append(f"    {step.call_site}")
            L.append(f"    good: {_envelope(step.good)}")
        else:
            L.append(f"  The bad flow did a step the good flow never did:")
            L.append(f"    {step.call_site}")
            L.append(f"    bad : {_envelope(step.bad)}")
            for cont in step.bad.continuation_lines:
                L.append(f"          {cont}")
    L.append("")

    # --- payload differences -------------------------------------------------
    issues = c.payload_issues()
    if issues:
        L.append("-" * 78)
        L.append(f"PAYLOAD / PARAMETER DIFFERENCES  ({len(issues)} step(s) on the shared path)")
        for s in issues:
            L.append(f"  {s.call_site}")
            for f in s.fields:
                if f.kind == "MISSING_IN_BAD":
                    L.append(f"    - {f.key}: present in good ({f.good!r}), MISSING in bad")
                elif f.kind == "EXTRA_IN_BAD":
                    L.append(f"    + {f.key}: absent in good, present in bad ({f.bad!r})")
                else:
                    L.append(f"    ~ {f.key}: good={f.good!r}  bad={f.bad!r}")
        L.append("")

    # --- exceptions ----------------------------------------------------------
    if c.errors_only_in_bad:
        L.append("-" * 78)
        L.append(f"ERRORS / EXCEPTIONS IN THE BAD FLOW  ({len(c.errors_only_in_bad)})")
        for r in c.errors_only_in_bad:
            L.append(f"  {_envelope(r)}")
            for cont in r.continuation_lines:
                L.append(f"        {cont}")
        L.append("")

    # --- aligned trace -------------------------------------------------------
    L.append("-" * 78)
    L.append("ALIGNED FLOW   ( = same | - only in GOOD | + only in BAD | ~ payload differs )")
    for i, s in enumerate(c.steps):
        mark = {"SAME": "=", "ONLY_IN_GOOD": "-", "ONLY_IN_BAD": "+"}[s.kind]
        if s.kind == "SAME" and s.fields:
            mark = "~"
        if not show_all and mark == "=" and c.break_index is not None and abs(i - c.break_index) > 5:
            continue
        here = "  <== BREAK" if i == c.break_index else ""
        L.append(f"  {mark} {i + 1:>3}. {s.call_site}{here}")
    if not show_all:
        L.append("  (identical steps far from the break are hidden; pass --all to see everything)")
    L.append(bar)
    return "\n".join(L) + "\n"
