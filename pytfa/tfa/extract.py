"""Format-agnostic extraction primitives.

The analyzer has no format profile and no parser configuration. Every log line,
whatever its layout, is read best-effort: a timestamp if one is recognisable, a
level if one is named, a thread if one is identifiable, a `Class:line` call site
if the line carries one, and otherwise a normalised message template that gives
the line a stable identity anyway.

Shared by ingestion (whole-corpus analysis) and compare (pairwise reference
comparison) so both see exactly the same view of a line.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Optional

# --------------------------------------------------------------- timestamps

_TS_RES = [
    (re.compile(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[.,]\d{1,9}'), None),
    (re.compile(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}'), None),
    (re.compile(r'\d{2}/\d{2}/\d{4}[T ]\d{2}:\d{2}:\d{2}'), "%d/%m/%Y %H:%M:%S"),
    (re.compile(r'\d{2}:\d{2}:\d{2}[.,]\d{1,3}'), None),
]

_TS_FORMATS = ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S.%f",
               "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%H:%M:%S.%f")


def parse_any_timestamp(line: str) -> Optional[datetime]:
    """Best-effort timestamp from anywhere in the line; None if unrecognised."""
    for rx, explicit in _TS_RES:
        m = rx.search(line)
        if not m:
            continue
        text = m.group(0).replace(",", ".")
        if explicit:
            try:
                return datetime.strptime(text, explicit).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        for fmt in _TS_FORMATS:
            try:
                return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
    return None


def strip_timestamps(text: str) -> str:
    for rx, _ in _TS_RES:
        text = rx.sub(" ", text)
    return text


def epoch_millis(dt: datetime) -> int:
    return int(dt.timestamp() * 1000)


# ------------------------------------------------------------------ fields

# Class:line anywhere in the line (e.g. OrderController:28)
_CALL_SITE = re.compile(r'\b([A-Za-z_][A-Za-z0-9_.$]*):(\d{1,6})\b')
_LEVEL = re.compile(r'\b(TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL|SEVERE)\b')
# thread names: [worker-1], thread=x, or pool/exec/nio style tokens
_THREAD_BRACKET = re.compile(r'\[([A-Za-z][\w.\-]{1,60})\]')
_THREAD_KV = re.compile(r'\bthread(?:[Nn]ame)?\s*[=:]\s*"?([\w.\-]+)"?')
_THREAD_STYLE = re.compile(r'\b((?:http-[\w.\-]*exec-\d+|pool-\d+-thread-\d+|'
                           r'[\w.\-]*exec(?:utor)?-\d+|Thread-\d+|main))\b')

_STACK = re.compile(r'^\s*(at\s+\S+\(|Caused by:|\.\.\.\s*\d+\s+more|'
                    r'[\w.$]+(Exception|Error)\b)')
_ERROR_WORD = re.compile(r'\b(ERROR|FATAL|SEVERE|Exception|failed|failure)\b', re.IGNORECASE)

# key=value and "key": value / key: value, tolerating quoted strings and blocks
_KV = re.compile(r'"?([A-Za-z_][A-Za-z0-9_.]*)"?\s*[=:]\s*'
                 r'("[^"]*"|\{[^}]*\}|\[[^\]]*\]|[^\s,;}\])]+)')

# fields that legitimately differ between any two runs and are not defects
_NOISE_KEYS = {"trace_id", "traceid", "span_id", "spanid", "correlationid",
               "correlation_id", "requestid", "request_id", "reqid",
               "orderid", "order_id", "paymentid", "payment_id", "id",
               "timestamp", "ts", "time", "date"}


def call_site_of(line: str) -> Optional[str]:
    m = _CALL_SITE.search(line)
    return f"{m.group(1)}:{m.group(2)}" if m else None


def level_of(line: str) -> Optional[str]:
    m = _LEVEL.search(line)
    if not m:
        return None
    level = m.group(1).upper()
    return "WARN" if level == "WARNING" else level


def thread_of(line: str) -> Optional[str]:
    for rx in (_THREAD_KV, _THREAD_STYLE):
        m = rx.search(line)
        if m:
            return m.group(1)
    for m in _THREAD_BRACKET.finditer(line):
        token = m.group(1)
        if not _LEVEL.fullmatch(token):
            return token
    return None


def is_stack_frame(line: str) -> bool:
    return bool(_STACK.match(line))


def looks_like_error(text: str) -> bool:
    return bool(_ERROR_WORD.search(text))


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


def normalise_template(line: str, refs: tuple[str, ...] = ()) -> str:
    """A format-agnostic identity for a line: mask the parts that vary per run.

    Used as the step/call-site key when the line carries no Class:line. Two lines
    produced by the same log statement collapse to the same template.
    """
    t = strip_timestamps(line)
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
    t = re.sub(r'\b[0-9a-fA-F]{8,}\b', "?", t)   # ids / hashes
    t = re.sub(r'\b\d+\b', "?", t)               # bare numbers
    t = re.sub(r'\s+', " ", t).strip(" |\t-")
    return t
