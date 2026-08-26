"""Pairwise reference comparison: one known-GOOD flow vs one known-BAD flow.

Complement to the population baseline. Where `analyze` asks "what did the other
N runs do?", `compare` asks "how does this run differ from that run?" - so it
works with exactly two reference ids and no population at all.

**The log format does not matter.** This module never uses a format profile, a
match-rate check, or a call-site alphabet. It reads raw lines from every file,
keeps the ones carrying a reference id, and derives what it needs best-effort:

  * timestamp  - recognised anywhere in the line, several common layouts; if a
                 line has none, file order is preserved.
  * step key   - `Class:line` when the line happens to carry one, otherwise a
                 normalised message template (values masked), so any format
                 still yields a stable "what kind of line is this" identity.
  * payload    - key=value pairs, including nested {a=1, b=2} blocks.

It surfaces the four ways a flow breaks:

  1. business logic   - the bad flow took a different branch (step diff)
  2. exception        - an error/stack trace present in one flow and not the other
  3. missing param    - a payload field present in good, absent in bad
  4. wrong payload    - a payload field whose value differs between the flows
"""
from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------- extraction

# key=value and "key": value / key: value (JSON, logfmt, plain), tolerating
# quoted strings and {...} / [...] blocks. Timestamps are stripped before this
# runs, so "10:00:00" can never be read as a key/value pair.
_KV = re.compile(r'"?([A-Za-z_][A-Za-z0-9_.]*)"?\s*[=:]\s*("[^"]*"|\{[^}]*\}|\[[^\]]*\]|[^\s,;}\])]+)')
# fields that legitimately differ between any two runs and are not defects
_NOISE_KEYS = {"trace_id", "traceid", "traceId".lower(), "span_id", "spanid", "correlationid",
               "correlation_id", "requestid", "request_id", "orderid", "order_id",
               "paymentid", "payment_id", "id", "timestamp", "ts", "time", "date"}

# Class:line anywhere in the line (e.g. OrderController:28)
_CALL_SITE = re.compile(r'\b([A-Za-z_][A-Za-z0-9_.$]*):(\d{1,6})\b')

_LEVEL = re.compile(r'\b(TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL|SEVERE)\b')

# common timestamp layouts, tried in order; group 0 is the whole stamp
_TS_RES = [
    (re.compile(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[.,]\d{1,9}'), None),
    (re.compile(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}'), None),
    (re.compile(r'\d{2}/\d{2}/\d{4}[T ]\d{2}:\d{2}:\d{2}'), "%d/%m/%Y %H:%M:%S"),
    (re.compile(r'\d{2}:\d{2}:\d{2}[.,]\d{1,3}'), None),
]

_STACK = re.compile(r'^\s*(at\s+\S+\(|Caused by:|\.\.\.\s*\d+\s+more|[\w.$]+(Exception|Error)\b)')
_ERROR_WORD = re.compile(r'\b(ERROR|FATAL|SEVERE|Exception|failed|failure)\b', re.IGNORECASE)


def strip_timestamps(text: str) -> str:
    for rx, _ in _TS_RES:
        text = rx.sub(" ", text)
    return text


def extract_payload(text: str) -> dict[str, str]:
    """key/value pairs from a line (key=value or "key": value), flattening
    nested {a=1, b=2} blocks. Timestamps are removed first so clock digits are
    never mistaken for a field."""
    out: dict[str, str] = {}
    if not text:
        return out
    text = strip_timestamps(text)
    for key, value in _KV.findall(text):
        value = value.strip()
        if value.startswith("{") and value.endswith("}"):
            for k2, v2 in _KV.findall(value[1:-1]):
                out[k2] = v2.strip().strip('"')
            continue
        out[key] = value.strip('"')
    return out


def significant_payload(text: str) -> dict[str, str]:
    return {k: v for k, v in extract_payload(text).items() if k.lower() not in _NOISE_KEYS}


def parse_any_timestamp(line: str) -> Optional[datetime]:
    """Best-effort timestamp from anywhere in the line. None if unrecognised."""
    for rx, explicit in _TS_RES:
        m = rx.search(line)
        if not m:
            continue
        text = m.group(0).replace(",", ".")
        if explicit:
            try:
                return datetime.strptime(text, explicit)
            except ValueError:
                continue
        for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S.%f",
                    "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%H:%M:%S.%f"):
            try:
                return datetime.strptime(text, fmt)
            except ValueError:
                continue
    return None


def normalise_template(line: str, refs: tuple[str, ...] = ()) -> str:
    """A format-agnostic identity for a line: mask the parts that vary per run.

    Used as the step key when the line carries no Class:line. Two lines produced
    by the same log statement collapse to the same template.
    """
    t = line
    for rx, _ in _TS_RES:
        t = rx.sub(" ", t)
    for ref in refs:
        if ref:
            t = t.replace(ref, " ")
    t = _LEVEL.sub(" ", t)
    # mask the VALUE of each pair but keep the key, so two different log
    # statements never collapse onto the same template
    t = re.sub(r'("[A-Za-z_][A-Za-z0-9_.]*"\s*:\s*)'
               r'("[^"]*"|\{[^}]*\}|\[[^\]]*\]|[^\s,;}\])]+)', r'\1?', t)
    t = re.sub(r'(\b[A-Za-z_][A-Za-z0-9_.]*\s*=\s*)'
               r'("[^"]*"|\{[^}]*\}|\[[^\]]*\]|[^\s,;}\])]+)', r'\1?', t)
    t = re.sub(r'\b[0-9a-fA-F]{8,}\b', "?", t) # ids / hashes
    t = re.sub(r'\b\d+\b', "?", t)             # bare numbers
    t = re.sub(r'\s+', " ", t).strip(" |\t-")
    return t


# -------------------------------------------------------------------- model

@dataclass
class FlowStep:
    raw: str
    source_file: str
    line_no: int
    timestamp: Optional[datetime]
    call_site: Optional[str]
    key: str
    payload: dict[str, str]
    continuations: list[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        return self.call_site or self.key

    def is_error(self) -> bool:
        if _ERROR_WORD.search(self.raw):
            return True
        return any(_STACK.match(c) for c in self.continuations)


@dataclass
class ReferenceFlow:
    ref_id: str
    steps: list[FlowStep]

    def size(self) -> int:
        return len(self.steps)

    def duration_ms(self) -> int:
        stamps = [s.timestamp for s in self.steps if s.timestamp is not None]
        if len(stamps) < 2:
            return 0
        return int((max(stamps) - min(stamps)).total_seconds() * 1000)

    def has_error(self) -> bool:
        return any(s.is_error() for s in self.steps)


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
    label: str
    good: Optional[FlowStep] = None
    bad: Optional[FlowStep] = None
    fields: list[FieldDiff] = field(default_factory=list)

    def has_payload_issue(self) -> bool:
        return bool(self.fields)


@dataclass
class ComparisonResult:
    good: ReferenceFlow
    bad: ReferenceFlow
    steps: list[StepDiff]
    break_index: Optional[int]
    errors_only_in_bad: list[FlowStep]

    @property
    def good_id(self) -> str:
        return self.good.ref_id

    @property
    def bad_id(self) -> str:
        return self.bad.ref_id

    @property
    def break_step(self) -> Optional[StepDiff]:
        return self.steps[self.break_index] if self.break_index is not None else None

    def payload_issues(self) -> list[StepDiff]:
        return [s for s in self.steps if s.has_payload_issue()]


# -------------------------------------------------------------------- input

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


def _make_step(line: str, src: str, line_no: int, refs: tuple[str, str]) -> FlowStep:
    m = _CALL_SITE.search(line)
    call_site = f"{m.group(1)}:{m.group(2)}" if m else None
    key = call_site or normalise_template(line, refs)
    return FlowStep(line.rstrip("\n"), src, line_no, parse_any_timestamp(line),
                    call_site, key, significant_payload(line))


def read_reference_flows(log_dir, good_id: str, bad_id: str) -> tuple[ReferenceFlow, ReferenceFlow]:
    """Read raw lines from every file, keeping those carrying each reference id.

    No format profile, no match-rate check - any text log works. A following line
    that carries no reference id but looks like a stack frame is attached to the
    step above it.
    """
    good_id = validate_reference_id(good_id)
    bad_id = validate_reference_id(bad_id)
    if good_id == bad_id:
        raise ValueError("the two reference ids are identical - nothing to compare")

    refs = (good_id, bad_id)
    patterns = {good_id: _exact_token(good_id), bad_id: _exact_token(bad_id)}
    buckets: dict[str, list[FlowStep]] = {good_id: [], bad_id: []}

    root = Path(log_dir)
    files = [root] if root.is_file() else sorted(p for p in root.rglob("*") if p.is_file())
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        last_ref: Optional[str] = None
        for line_no, line in enumerate(text.splitlines(), 1):
            matched = next((ref for ref, pat in patterns.items() if pat.search(line)), None)
            if matched is not None:
                buckets[matched].append(_make_step(line, str(path), line_no, refs))
                last_ref = matched
            elif last_ref is not None and (_STACK.match(line) or line.startswith((" ", "\t"))):
                if buckets[last_ref]:
                    buckets[last_ref][-1].continuations.append(line.rstrip("\n"))
            elif line.strip():
                last_ref = None      # an unrelated line ends the continuation block

    out = []
    for ref in (good_id, bad_id):
        steps = buckets[ref]
        # stable sort by timestamp where present; file order is the tie-break
        steps.sort(key=lambda s: (s.timestamp is None, s.timestamp or datetime.min))
        out.append(ReferenceFlow(ref, steps))
    return out[0], out[1]


# ---------------------------------------------------------------- comparison

def compare_flows(good: ReferenceFlow, bad: ReferenceFlow) -> ComparisonResult:
    a = [s.key for s in good.steps]
    b = [s.key for s in bad.steps]
    steps: list[StepDiff] = []
    break_index: Optional[int] = None

    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(a=a, b=b, autojunk=False).get_opcodes():
        if tag == "equal":
            for off in range(i2 - i1):
                gs, bs = good.steps[i1 + off], bad.steps[j1 + off]
                fields = _diff_fields(gs, bs, good.ref_id, bad.ref_id)
                steps.append(StepDiff("SAME", gs.label, gs, bs, fields))
                if fields and break_index is None:
                    break_index = len(steps) - 1     # same path, wrong payload
        else:
            if break_index is None:
                break_index = len(steps)
            for i in range(i1, i2):
                steps.append(StepDiff("ONLY_IN_GOOD", good.steps[i].label, good.steps[i], None))
            for j in range(j1, j2):
                steps.append(StepDiff("ONLY_IN_BAD", bad.steps[j].label, None, bad.steps[j]))

    errors_only_in_bad = [s for s in bad.steps if s.is_error()] if not good.has_error() \
        else [s for s in bad.steps if s.is_error() and s.key not in set(a)]
    return ComparisonResult(good, bad, steps, break_index, errors_only_in_bad)


def _diff_fields(good_step: FlowStep, bad_step: FlowStep,
                 good_id: str = "", bad_id: str = "") -> list[FieldDiff]:
    g, b = good_step.payload, bad_step.payload
    out: list[FieldDiff] = []
    for k in sorted(set(g) | set(b)):
        gv, bv = g.get(k), b.get(k)
        if gv == bv:
            continue
        # the field carrying the reference id itself is meant to differ
        if gv == good_id and bv == bad_id:
            continue
        out.append(FieldDiff(k, gv, bv))
    return out


# --------------------------------------------------------------------- report

def render_comparison(c: ComparisonResult, show_all: bool = False) -> str:
    L: list[str] = []
    bar = "=" * 78
    L.append(bar)
    L.append("TFA FLOW COMPARISON  (reference GOOD vs reference BAD)")
    L.append(bar)
    for name, flow in (("GOOD", c.good), ("BAD ", c.bad)):
        flag = "  (contains an error)" if flow.has_error() else ""
        L.append(f"  {name} : {flow.ref_id}")
        L.append(f"         {flow.size()} lines, {flow.duration_ms():,} ms{flag}")
    L.append("")

    if c.good.size() == 0 or c.bad.size() == 0:
        missing = [n for n, f in (("GOOD", c.good), ("BAD", c.bad)) if f.size() == 0]
        L.append(f"  ERROR: no log lines found for the {' and '.join(missing)} reference id.")
        L.append("         The id is matched as a whole token - check it is exact and that the")
        L.append("         folder contains the log files for that flow.")
        L.append(bar)
        return "\n".join(L) + "\n"

    L.append("-" * 78)
    if c.break_index is None:
        L.append("NO BREAK FOUND - both flows took the same path with the same payload values.")
    else:
        s = c.break_step
        L.append(f"THE BREAK  (step {c.break_index + 1} of {len(c.steps)})")
        L.append("")
        if s.kind == "SAME" and s.fields:
            L.append(f"  Same step, different data: {s.label}")
            for f in s.fields:
                L.append(f"    {f.key}: good={f.good!r}  bad={f.bad!r}   [{f.kind}]")
            L.append("")
            L.append(f"    good: {s.good.raw}")
            L.append(f"    bad : {s.bad.raw}")
        elif s.kind == "ONLY_IN_GOOD":
            L.append("  The good flow did this step; the bad flow never did:")
            L.append(f"    {s.label}")
            L.append(f"    good: {s.good.raw}")
        else:
            L.append("  The bad flow did a step the good flow never did:")
            L.append(f"    {s.label}")
            L.append(f"    bad : {s.bad.raw}")
            for cont in s.bad.continuations:
                L.append(f"          {cont}")
    L.append("")

    issues = c.payload_issues()
    if issues:
        L.append("-" * 78)
        L.append(f"PAYLOAD / PARAMETER DIFFERENCES  ({len(issues)} step(s) on the shared path)")
        for s in issues:
            L.append(f"  {s.label}")
            for f in s.fields:
                if f.kind == "MISSING_IN_BAD":
                    L.append(f"    - {f.key}: present in good ({f.good!r}), MISSING in bad")
                elif f.kind == "EXTRA_IN_BAD":
                    L.append(f"    + {f.key}: absent in good, present in bad ({f.bad!r})")
                else:
                    L.append(f"    ~ {f.key}: good={f.good!r}  bad={f.bad!r}")
        L.append("")

    if c.errors_only_in_bad:
        L.append("-" * 78)
        L.append(f"ERRORS / EXCEPTIONS IN THE BAD FLOW  ({len(c.errors_only_in_bad)})")
        for s in c.errors_only_in_bad:
            L.append(f"  {s.raw}")
            for cont in s.continuations:
                L.append(f"        {cont}")
        L.append("")

    L.append("-" * 78)
    L.append("ALIGNED FLOW   ( = same | - only in GOOD | + only in BAD | ~ payload differs )")
    hidden = 0
    for i, s in enumerate(c.steps):
        mark = {"SAME": "=", "ONLY_IN_GOOD": "-", "ONLY_IN_BAD": "+"}[s.kind]
        if s.kind == "SAME" and s.fields:
            mark = "~"
        if not show_all and mark == "=" and c.break_index is not None and abs(i - c.break_index) > 5:
            hidden += 1
            continue
        here = "  <== BREAK" if i == c.break_index else ""
        L.append(f"  {mark} {i + 1:>3}. {s.label[:110]}{here}")
    if hidden:
        L.append(f"  ({hidden} identical steps far from the break hidden; pass --all to see everything)")
    L.append(bar)
    return "\n".join(L) + "\n"
