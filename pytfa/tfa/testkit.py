"""Synthetic log generation for tests. Port of `tfa.testkit` (SyntheticLogGenerator,
Scenario, Defects)."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .model import Episode, LogRecord, TerminalStatus

_FMT = "%Y-%m-%d %H:%M:%S.%f"


def _fmt(dt: datetime) -> str:
    # millisecond precision, matching the default profile
    return dt.astimezone(timezone.utc).strftime(_FMT)[:-3]


# ------------------------------------------------------------ line generator

@dataclass
class Event:
    ts: datetime
    level: str
    thread: str
    call_site: str
    message: str
    continuations: tuple[str, ...] = ()


def format_line(e: Event) -> str:
    return f"{_fmt(e.ts)} | {e.level} | {e.thread} | {e.call_site} | {e.message}"


def write_file(path: Path, events: list[Event]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as w:
        for e in events:
            w.write(format_line(e) + "\n")
            for c in e.continuations:
                w.write(c + "\n")


# ------------------------------------------------------------------- scenario

@dataclass
class FlowDef:
    name: str
    call_sites: list[str]

    def entry(self) -> str:
        return self.call_sites[0]

    def terminal(self) -> str:
        return self.call_sites[-1]


@dataclass
class Truth:
    thread_id: str
    episode_sequences: list[list[str]]


@dataclass
class ScenarioResult:
    files: list[Path]
    truths: list[Truth]
    entry_call_sites: set[str]
    terminal_call_sites: set[str]


class Scenario:
    def __init__(self, flows: list[FlowDef]):
        self.flows = list(flows)
        self.thread_count = 4
        self.episodes_per_thread = 5
        self.within_gap_millis = 50
        self.idle_gap_millis = 10_000
        self.file_count = 3
        self.start = datetime(2026, 8, 20, 10, 0, 0, tzinfo=timezone.utc)

    def threads(self, n): self.thread_count = n; return self
    def episodes(self, n): self.episodes_per_thread = n; return self
    def within(self, m): self.within_gap_millis = m; return self
    def idle(self, m): self.idle_gap_millis = m; return self
    def files(self, n): self.file_count = n; return self

    def generate(self, directory: Path) -> ScenarioResult:
        from datetime import timedelta
        timed: list[tuple[datetime, Event]] = []
        truths: list[Truth] = []
        entries = {f.entry() for f in self.flows}
        terminals = {f.terminal() for f in self.flows}

        for t in range(self.thread_count):
            thread_id = f"exec-{t}"
            clock = self.start + timedelta(milliseconds=t * (self.within_gap_millis // 2 + 1))
            seqs: list[list[str]] = []
            for ep in range(self.episodes_per_thread):
                flow = self.flows[(t + ep) % len(self.flows)]
                seq = []
                for cs in flow.call_sites:
                    timed.append((clock, Event(clock, "INFO", thread_id, cs, f"{flow.name} ep{ep}")))
                    seq.append(cs)
                    clock += timedelta(milliseconds=self.within_gap_millis)
                seqs.append(seq)
                clock += timedelta(milliseconds=self.idle_gap_millis)
            truths.append(Truth(thread_id, seqs))

        timed.sort(key=lambda te: te[0])
        written: list[Path] = []
        n = len(timed)
        per_file = max(1, -(-n // self.file_count))
        idx = 0
        for i in range(0, n, per_file):
            chunk = [e for _, e in timed[i:i + per_file]]
            f = directory / f"app-{idx:02d}.log"
            write_file(f, chunk)
            written.append(f)
            idx += 1
        return ScenarioResult(written, truths, entries, terminals)


# -------------------------------------------------------------------- defects

ENTRY = "com.acme.Entry:1"
TERMINAL = "com.acme.Entry:99"
MODAL = ["com.acme.Entry:1", "com.acme.Svc:2", "com.acme.Proc:3", "com.acme.Repo:4", "com.acme.Entry:99"]
STEP_MS = 100


def _record(ts, level, thread_id, call_site):
    cls, _, ln = call_site.rpartition(":")
    return LogRecord(ts, level, thread_id, cls, int(ln), "m", (), "f", 1)


def _build(thread_id, start, status, level, call_sites) -> Episode:
    from datetime import timedelta
    e = Episode(thread_id)
    t = start
    for cs in call_sites:
        e.add(_record(t, level, thread_id, cs))
        t += timedelta(milliseconds=STEP_MS)
    e.set_status(status)
    return e


def clean(thread_id, start) -> Episode:
    return _build(thread_id, start, TerminalStatus.COMPLETED, "INFO", MODAL)


def truncated(thread_id, start) -> Episode:
    return _build(thread_id, start, TerminalStatus.TRUNCATED, "INFO",
                  ["com.acme.Entry:1", "com.acme.Svc:2", "com.acme.Proc:3"])


def wrong_branch(thread_id, start) -> Episode:
    return _build(thread_id, start, TerminalStatus.COMPLETED, "INFO",
                  ["com.acme.Entry:1", "com.acme.Svc:2", "com.acme.Proc:3",
                   "com.acme.Wrong:8", "com.acme.Entry:99"])


def slow_transition(thread_id, start) -> Episode:
    from datetime import timedelta
    e = Episode(thread_id)
    t = start
    for cs in ["com.acme.Entry:1", "com.acme.Svc:2", "com.acme.Proc:3"]:
        e.add(_record(t, "INFO", thread_id, cs))
        t += timedelta(milliseconds=STEP_MS)
    t += timedelta(milliseconds=STEP_MS * 100)  # the slow step
    e.add(_record(t, "INFO", thread_id, "com.acme.Repo:4"))
    t += timedelta(milliseconds=STEP_MS)
    e.add(_record(t, "INFO", thread_id, "com.acme.Entry:99"))
    e.set_status(TerminalStatus.COMPLETED)
    return e


def retry_storm(thread_id, start) -> Episode:
    return _build(thread_id, start, TerminalStatus.COMPLETED, "INFO",
                  ["com.acme.Entry:1", "com.acme.Svc:2", "com.acme.Proc:3",
                   "com.acme.Repo:4", "com.acme.Repo:4", "com.acme.Repo:4", "com.acme.Entry:99"])
