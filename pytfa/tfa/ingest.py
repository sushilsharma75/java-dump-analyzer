"""Ingestion: format profiles, record parsing, streaming file-set reading, and
format auto-detection. Port of the Java `tfa.ingest` package."""
from __future__ import annotations

import gzip
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Iterator, Optional
from zoneinfo import ZoneInfo

from .model import LogRecord


class Capability(Enum):
    CALL_SITE = "CALL_SITE"
    LEVEL = "LEVEL"
    THREAD = "THREAD"
    TIMESTAMP = "TIMESTAMP"
    MESSAGE = "MESSAGE"


# ------------------------------------------------------------------ timestamps

_TOKENS = [
    ("yyyy", "%Y"), ("MMM", "%b"), ("MM", "%m"), ("dd", "%d"),
    ("HH", "%H"), ("mm", "%M"), ("ss", "%S"), ("SSS", "%f"),
    ("XXX", "%z"), ("Z", "%z"),
]


def java_pattern_to_strptime(pattern: str) -> str:
    """Translate the common subset of Java DateTimeFormatter patterns to strptime."""
    out = []
    i = 0
    while i < len(pattern):
        if pattern[i] == "'":  # quoted literal, e.g. 'T'
            j = pattern.index("'", i + 1)
            out.append(pattern[i + 1:j])
            i = j + 1
            continue
        for jt, pt in _TOKENS:
            if pattern.startswith(jt, i):
                out.append(pt)
                i += len(jt)
                break
        else:
            out.append(pattern[i])
            i += 1
    return "".join(out)


def epoch_millis(dt: datetime) -> int:
    return int(dt.timestamp() * 1000)


# -------------------------------------------------------------------- profiles

_CANONICAL_GROUPS = ("ts", "level", "thread", "class", "line", "msg")

DEFAULT_ENVELOPE = (
    r"^(?P<ts>\S+ \S+)\s*\|\s*"
    r"(?P<level>\w+)\s*\|\s*"
    r"(?P<thread>[^|]+?)\s*\|\s*"
    r"(?P<class>[^:|]+):(?P<line>\d+)\s*\|\s*"
    r"(?P<msg>.*)$"
)


class FormatProfile:
    """A named, reusable log-format definition (see charter section 3.4)."""

    def __init__(self, name: str, envelope_regex: str, timestamp_pattern: Optional[str],
                 zone: str, capabilities: set[Capability]):
        self.name = name
        self.envelope = re.compile(envelope_regex)
        self.timestamp_pattern = timestamp_pattern
        self.zone = ZoneInfo(zone) if zone else timezone.utc
        self.capabilities = set(capabilities)
        self._groups = set(re.findall(r"\(\?P<([a-zA-Z][a-zA-Z0-9]*)>", envelope_regex))
        self._strptime = java_pattern_to_strptime(timestamp_pattern) if timestamp_pattern else None

    @staticmethod
    def default() -> "FormatProfile":
        return FormatProfile(
            "default", DEFAULT_ENVELOPE, "yyyy-MM-dd HH:mm:ss.SSS", "UTC",
            {Capability.CALL_SITE, Capability.LEVEL, Capability.THREAD,
             Capability.TIMESTAMP, Capability.MESSAGE})

    def has(self, cap: Capability) -> bool:
        return cap in self.capabilities

    def has_group(self, group: str) -> bool:
        return group in self._groups

    def parse_timestamp(self, text: Optional[str]) -> Optional[datetime]:
        if text is None or self._strptime is None:
            return None
        try:
            dt = datetime.strptime(text, self._strptime)
        except (ValueError, OverflowError):
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=self.zone)
        return dt.astimezone(timezone.utc)


# ----------------------------------------------------------------------- stats

class LineBucket(Enum):
    MATCHED = "MATCHED"
    CONTINUATION = "CONTINUATION"
    MALFORMED = "MALFORMED"


@dataclass
class ParseStats:
    sample_limit: int = 20
    matched: int = 0
    continuation: int = 0
    malformed: int = 0
    total_lines: int = 0
    timestamp_parse_failures: int = 0
    malformed_sample: list[tuple[str, int, str]] = field(default_factory=list)

    def count(self, bucket: LineBucket, source_file: str, line_no: int, text: str) -> None:
        self.total_lines += 1
        if bucket is LineBucket.MATCHED:
            self.matched += 1
        elif bucket is LineBucket.CONTINUATION:
            self.continuation += 1
        else:
            self.malformed += 1
            if len(self.malformed_sample) < self.sample_limit and text.strip():
                self.malformed_sample.append((source_file, line_no, text))

    def records(self) -> int:
        return self.matched


# ---------------------------------------------------------------------- parser

@dataclass(frozen=True)
class Envelope:
    ts: Optional[str]
    level: Optional[str]
    thread: Optional[str]
    cls: Optional[str]
    line: Optional[str]
    msg: Optional[str]


class RecordParser:
    def __init__(self, profile: FormatProfile):
        self.profile = profile

    def try_match(self, line: str) -> Optional[Envelope]:
        m = self.profile.envelope.match(line)  # pattern is ^...$, so this is a full match
        if not m:
            return None
        def g(name):
            if not self.profile.has_group(name):
                return None
            v = m.group(name)
            return v.strip() if v is not None else None
        return Envelope(g("ts"), g("level"), g("thread"), g("class"), g("line"), g("msg"))

    def build(self, env: Envelope, continuations: list[str], source_file: str,
              line_no: int, stats: Optional[ParseStats]) -> LogRecord:
        ts = None
        if env.ts is not None and self.profile._strptime is not None:
            ts = self.profile.parse_timestamp(env.ts)
            if ts is None and stats is not None:
                stats.timestamp_parse_failures += 1
        line_number = -1
        if env.line is not None:
            try:
                line_number = int(env.line)
            except ValueError:
                line_number = -1
        return LogRecord(ts, env.level, env.thread, env.cls, line_number,
                         env.msg or "", tuple(continuations), source_file, line_no)


# ------------------------------------------------------------- match-rate check

@dataclass(frozen=True)
class MatchRateReport:
    sampled_lines: int
    matched: int
    continuation: int
    malformed: int
    rate: float
    failures: list[tuple[str, int, str]]

    def meets(self, threshold: float) -> bool:
        return self.rate >= threshold


class MatchRateError(Exception):
    def __init__(self, report: MatchRateReport, threshold: float):
        super().__init__(
            f"match rate {report.rate * 100:.2f}% is below threshold {threshold * 100:.2f}% "
            f"(matched={report.matched}, malformed={report.malformed} of {report.sampled_lines} sampled lines)")
        self.report = report
        self.threshold = threshold


# ------------------------------------------------------------- file-set reader

def _open_text(path: Path):
    if path.name.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


class FileSetReader:
    """Presents a directory of log files as one continuous, lazily-evaluated
    stream of LogRecord. Files are ordered by first parseable timestamp."""

    FIRST_TS_SCAN_LIMIT = 5000

    def __init__(self, root: Path, parser: RecordParser, stats: Optional[ParseStats] = None):
        self.parser = parser
        self.stats = stats if stats is not None else ParseStats()
        self._files = self._order_by_timestamp(self._collect(root))

    @property
    def ordered_files(self) -> list[Path]:
        return list(self._files)

    @staticmethod
    def _collect(root: Path) -> list[Path]:
        if root.is_file():
            return [root]
        return sorted(p for p in root.rglob("*") if p.is_file())

    def _order_by_timestamp(self, files: list[Path]) -> list[Path]:
        keyed = [(self._first_timestamp(p), str(p), p) for p in files]
        # None sorts last
        keyed.sort(key=lambda k: (k[0] is None, k[0] or datetime.min.replace(tzinfo=timezone.utc), k[1]))
        return [p for _, _, p in keyed]

    def _first_timestamp(self, path: Path) -> Optional[datetime]:
        try:
            with _open_text(path) as fh:
                for i, line in enumerate(fh):
                    if i >= self.FIRST_TS_SCAN_LIMIT:
                        break
                    env = self.parser.try_match(line.rstrip("\n"))
                    if env and env.ts:
                        ts = self.profile_parse(env.ts)
                        if ts:
                            return ts
        except OSError:
            return None
        return None

    def profile_parse(self, text):
        return self.parser.profile.parse_timestamp(text)

    # -- match-rate sampling --

    def check_match_rate(self, sample_lines: int) -> MatchRateReport:
        matched = continuation = malformed = seen = 0
        record_open = False
        failures: list[tuple[str, int, str]] = []
        done = False
        for p in self._files:
            if done:
                break
            line_no = 0
            with _open_text(p) as fh:
                for raw in fh:
                    line_no += 1
                    if seen >= sample_lines:
                        done = True
                        break
                    seen += 1
                    line = raw.rstrip("\n")
                    if self.parser.try_match(line) is not None:
                        matched += 1
                        record_open = True
                    elif record_open:
                        continuation += 1
                    else:
                        malformed += 1
                        if len(failures) < 20 and line.strip():
                            failures.append((str(p), line_no, line))
        denom = matched + malformed
        rate = (matched / denom) if denom else 0.0
        return MatchRateReport(seen, matched, continuation, malformed, rate, failures)

    def require_match_rate(self, sample_lines: int, threshold: float) -> MatchRateReport:
        rep = self.check_match_rate(sample_lines)
        if not rep.meets(threshold):
            raise MatchRateError(rep, threshold)
        return rep

    # -- the record stream --

    def records(self) -> Iterator[LogRecord]:
        pending_env: Optional[Envelope] = None
        pending_cont: list[str] = []
        pending_file = ""
        pending_line = 0
        for path in self._files:
            line_no = 0
            with _open_text(path) as fh:
                for raw in fh:
                    line_no += 1
                    line = raw.rstrip("\n")
                    env = self.parser.try_match(line)
                    if env is not None:
                        self.stats.count(LineBucket.MATCHED, str(path), line_no, line)
                        if pending_env is not None:
                            yield self.parser.build(pending_env, pending_cont, pending_file,
                                                    pending_line, self.stats)
                        pending_env, pending_cont = env, []
                        pending_file, pending_line = str(path), line_no
                    elif pending_env is not None:
                        self.stats.count(LineBucket.CONTINUATION, str(path), line_no, line)
                        pending_cont.append(line)
                    else:
                        self.stats.count(LineBucket.MALFORMED, str(path), line_no, line)
        if pending_env is not None:
            yield self.parser.build(pending_env, pending_cont, pending_file, pending_line, self.stats)


# ------------------------------------------------------------- format detector

_TS_CANDIDATES = [
    "yyyy-MM-dd HH:mm:ss.SSS",
    "yyyy-MM-dd HH:mm:ss,SSS",
    "yyyy-MM-dd'T'HH:mm:ss.SSSXXX",
    "yyyy-MM-dd'T'HH:mm:ss.SSS",
    "yyyy-MM-dd HH:mm:ss",
    "yyyy-MM-dd'T'HH:mm:ss",
]


@dataclass(frozen=True)
class Detected:
    profile: FormatProfile
    match_rate: float
    sampled: int
    note: str


def detect_format(path: Path, sample_lines: int = 500) -> Detected:
    sample = []
    with _open_text(path) as fh:
        for raw in fh:
            if len(sample) >= sample_lines:
                break
            line = raw.rstrip("\n")
            if line.strip():
                sample.append(line)
    if not sample:
        raise ValueError(f"no readable lines in {path}")

    piped = sum(1 for l in sample if "|" in l)
    if piped < len(sample) * 0.5:
        prof = FormatProfile.default()
        return Detected(prof, _rate_of(prof, sample), len(sample),
                        "sample does not look pipe-delimited; author a profile by hand")

    fields = min(max((len(l.split("|")) for l in sample if "|" in l), default=0), 5)
    has_call_site = any(len(parts := l.split("|")) >= 4 and re.fullmatch(r"[\w.$]+:\d+", parts[3].strip())
                        for l in sample)
    ts_pattern = _detect_ts(sample)
    envelope = _build_envelope(fields, has_call_site)

    caps = {Capability.MESSAGE}
    if ts_pattern:
        caps.add(Capability.TIMESTAMP)
    if fields >= 2:
        caps.add(Capability.LEVEL)
    if fields >= 3:
        caps.add(Capability.THREAD)
    if has_call_site:
        caps.add(Capability.CALL_SITE)

    prof = FormatProfile(f"detected-{path.name}", envelope, ts_pattern, "UTC", caps)
    note = ("call site present -> primary sequence key available" if has_call_site
            else "no Class:line field detected -> CALL_SITE unavailable, message-template fallback needed")
    if not ts_pattern:
        note += "; timestamp pattern not recognised - set it by hand"
    return Detected(prof, _rate_of(prof, sample), len(sample), note)


def _detect_ts(sample: list[str]) -> Optional[str]:
    for cand in _TS_CANDIDATES:
        fmt = java_pattern_to_strptime(cand)
        ok = tried = 0
        for l in sample:
            first = l.split("|", 1)[0].strip()
            if not first:
                continue
            tried += 1
            try:
                datetime.strptime(first, fmt)
                ok += 1
            except (ValueError, OverflowError):
                pass
            if tried >= 50:
                break
        if tried and ok >= tried * 0.9:
            return cand
    return None


def _build_envelope(fields: int, has_call_site: bool) -> str:
    sb = [r"^(?P<ts>[^|]+?)\s*\|\s*"]
    if fields >= 2:
        sb.append(r"(?P<level>\w+)\s*\|\s*")
    if fields >= 3:
        sb.append(r"(?P<thread>[^|]+?)\s*\|\s*")
    if fields >= 4:
        sb.append(r"(?P<class>[^:|]+):(?P<line>\d+)\s*\|\s*" if has_call_site
                  else r"(?P<src>[^|]+?)\s*\|\s*")
    sb.append(r"(?P<msg>.*)$")
    return "".join(sb)


def _rate_of(profile: FormatProfile, sample: list[str]) -> float:
    parser = RecordParser(profile)
    matched = malformed = 0
    record_open = False
    for l in sample:
        if parser.try_match(l) is not None:
            matched += 1
            record_open = True
        elif not record_open:
            malformed += 1
    denom = matched + malformed
    return matched / denom if denom else 0.0


def profile_to_yaml(p: FormatProfile) -> str:
    caps = ", ".join(c.value for c in sorted(p.capabilities, key=lambda c: c.value))
    lines = ["profiles:", f"  {p.name}:",
             f"    envelope: '{p.envelope.pattern}'"]
    if p.timestamp_pattern:
        lines.append(f'    timestampPattern: "{p.timestamp_pattern}"')
    zone = getattr(p.zone, "key", "UTC")
    lines.append(f'    zone: "{zone}"')
    lines.append(f"    capabilities: [{caps}]")
    return "\n".join(lines) + "\n"
