"""Domain model for the Thread Flow Analyzer.

A faithful Python port of the Java `tfa.model` package. Uses dataclasses; the
mutable objects (Episode, FlowCluster) grow during construction then are read
like value objects.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class TerminalStatus(Enum):
    """How an episode ended (ERRORED takes precedence when an ERROR was logged)."""
    COMPLETED = "COMPLETED"
    TRUNCATED = "TRUNCATED"
    ERRORED = "ERRORED"


class FindingType(Enum):
    TRUNCATION = "TRUNCATION"
    DIVERGENCE = "DIVERGENCE"
    TIMING = "TIMING"


@dataclass(frozen=True)
class LogRecord:
    """One envelope-matched line plus its attached continuation lines.

    ``timestamp`` may be None if the envelope matched but the timestamp text
    failed to parse. Continuation lines (stack frames, multi-line payloads) are
    never dropped.
    """
    timestamp: Optional[datetime]
    level: Optional[str]
    thread_id: Optional[str]
    class_name: Optional[str]
    line_number: int
    message: str
    continuation_lines: tuple[str, ...] = ()
    source_file: str = ""
    line_number_in_file: int = 0

    def call_site(self) -> Optional[str]:
        """Primary sequence key ``Class:line``; just the class if no line."""
        if self.class_name is None:
            return None
        return self.class_name if self.line_number < 0 else f"{self.class_name}:{self.line_number}"

    def has_stack_trace(self) -> bool:
        for c in self.continuation_lines:
            t = c.strip()
            if t.startswith("at ") or t.startswith("Caused by:") or t.startswith("... ") \
                    or "Exception" in t or "Error:" in t:
                return True
        return False


@dataclass
class Run:
    """A collapsed run: consecutive records at the same call site."""
    call_site: str
    count: int
    first_timestamp: Optional[datetime]
    last_timestamp: Optional[datetime]


class Episode:
    """One contiguous execution of one flow on one thread."""

    def __init__(self, thread_id: str):
        self.thread_id = thread_id
        self.records: list[LogRecord] = []
        self.status = TerminalStatus.TRUNCATED
        self._has_error = False
        self._call_sites: Optional[list[str]] = None
        self._runs: Optional[list[Run]] = None
        self._collapsed: Optional[list[str]] = None

    def add(self, record: LogRecord) -> None:
        self.records.append(record)
        self._call_sites = self._runs = self._collapsed = None
        if record.level is not None and record.level.upper() == "ERROR":
            self._has_error = True

    def set_status(self, status: TerminalStatus) -> None:
        self.status = status

    @property
    def start(self) -> Optional[datetime]:
        return self.records[0].timestamp if self.records else None

    @property
    def end(self) -> Optional[datetime]:
        return self.records[-1].timestamp if self.records else None

    def size(self) -> int:
        return len(self.records)

    def has_error_record(self) -> bool:
        return self._has_error

    def has_stack_trace(self) -> bool:
        return any(r.has_stack_trace() for r in self.records)

    def call_site_sequence(self) -> list[str]:
        if self._call_sites is None:
            self._call_sites = [cs for r in self.records if (cs := r.call_site()) is not None]
        return self._call_sites

    def collapsed_runs(self) -> list[Run]:
        if self._runs is None:
            runs: list[Run] = []
            cur = None
            for r in self.records:
                cs = r.call_site()
                if cs is None:
                    continue
                if cur is not None and cur.call_site == cs:
                    cur.count += 1
                    cur.last_timestamp = r.timestamp
                else:
                    cur = Run(cs, 1, r.timestamp, r.timestamp)
                    runs.append(cur)
            self._runs = runs
        return self._runs

    def collapsed_sequence(self) -> list[str]:
        if self._collapsed is None:
            self._collapsed = [run.call_site for run in self.collapsed_runs()]
        return self._collapsed

    def __repr__(self) -> str:
        return f"Episode[thread={self.thread_id}, status={self.status.value}, size={self.size()}, start={self.start}]"


class FlowCluster:
    """A set of episodes judged to be the same kind of flow (same signature)."""

    def __init__(self, signature: str):
        self.signature = signature
        self.episodes: list[Episode] = []
        self.under_sampled = False

    def add(self, episode: Episode) -> None:
        self.episodes.append(episode)

    def size(self) -> int:
        return len(self.episodes)

    def representative(self) -> Optional[Episode]:
        return self.episodes[0] if self.episodes else None

    def __repr__(self) -> str:
        us = ", UNDER_SAMPLED" if self.under_sampled else ""
        return f"FlowCluster[{self.signature}, size={self.size()}{us}]"


@dataclass(frozen=True)
class SequenceShare:
    sequence: tuple[str, ...]
    count: int
    share: float


@dataclass(frozen=True)
class PositionOption:
    call_site: str
    count: int
    share: float


@dataclass(frozen=True)
class TransitionTiming:
    frm: str
    to: str
    count: int
    median_millis: float
    p95_millis: float


@dataclass
class Baseline:
    """The consensus for one cluster, over collapsed call-site sequences."""
    cluster_signature: str
    episodes_used: int
    modal_sequence: list[str]
    modal_share: float
    modal_count: int
    alternatives: list[SequenceShare]
    positional: list[list[PositionOption]]        # aligned to modal_sequence
    transition_counts: dict[str, dict[str, int]]
    transition_timings: list[TransitionTiming]

    def modal_terminal(self) -> Optional[str]:
        return self.modal_sequence[-1] if self.modal_sequence else None

    def position_options(self, i: int) -> list[PositionOption]:
        return self.positional[i] if 0 <= i < len(self.positional) else []

    def expected_at(self, i: int) -> Optional[PositionOption]:
        opts = self.position_options(i)
        return opts[0] if opts else None

    def transition_probability(self, frm: str, to: str) -> float:
        outgoing = self.transition_counts.get(frm)
        if not outgoing:
            return 0.0
        total = sum(outgoing.values())
        return outgoing.get(to, 0) / total if total else 0.0

    def timing_for(self, frm: str, to: str) -> Optional[TransitionTiming]:
        for t in self.transition_timings:
            if t.frm == frm and t.to == to:
                return t
        return None

    def slowest_by_p95(self, n: int) -> list[TransitionTiming]:
        return sorted(self.transition_timings, key=lambda t: t.p95_millis, reverse=True)[:n]


@dataclass(frozen=True)
class Finding:
    """A ranked, explained deviation of one episode from its cluster baseline."""
    episode: Episode
    type: FindingType
    divergence_call_site: Optional[str]
    divergence_index: int
    expected_call_site: Optional[str]
    expected_share: float
    observed: str
    raw_score: float

    def dedupe_key(self, cluster_signature: str) -> str:
        return "\x01".join([
            cluster_signature, self.type.value, str(self.divergence_index),
            str(self.divergence_call_site), str(self.expected_call_site),
        ])
