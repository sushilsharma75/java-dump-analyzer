"""Episode segmentation — the pluggable flow-key strategies and the streaming
driver. Port of the Java `tfa.segment` package."""
from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import Callable, Iterable, Iterator, Optional

from .ingest import epoch_millis
from .model import Episode, LogRecord, TerminalStatus


class ThreadSegmenter(ABC):
    """Incremental, single-thread segmenter: fed records in time order, emits an
    episode the moment a boundary is crossed."""

    @abstractmethod
    def accept(self, record: LogRecord) -> list[Episode]:
        ...

    @abstractmethod
    def finish(self) -> Optional[Episode]:
        ...


class FlowKeyStrategy(ABC):
    """Segments one thread's ordered records into episodes. Nothing downstream
    may depend on which implementation ran."""

    @property
    @abstractmethod
    def name(self) -> str:
        ...

    @abstractmethod
    def new_thread_segmenter(self, thread_id: str) -> ThreadSegmenter:
        ...

    def grouping_key(self, record: LogRecord) -> Optional[str]:
        """Which key this record belongs to. Thread id by default; a correlation
        strategy overrides this so one flow can span threads and services.
        Returning None drops the record (it belongs to no flow)."""
        return record.thread_id

    def segment(self, thread_id: str, ordered_records: Iterable[LogRecord]) -> list[Episode]:
        seg = self.new_thread_segmenter(thread_id)
        out: list[Episode] = []
        for r in ordered_records:
            out.extend(seg.accept(r))
        last = seg.finish()
        if last is not None:
            out.append(last)
        return out


# ------------------------------------------------------------- EntryMarker (A)

class _EntrySegmenter(ThreadSegmenter):
    def __init__(self, thread_id, entries, terminals):
        self.thread_id = thread_id
        self.entries = entries
        self.terminals = terminals
        self.open: Optional[Episode] = None

    def _start(self, r):
        e = Episode(self.thread_id)
        e.add(r)
        return e

    def _close(self, e, base):
        e.set_status(TerminalStatus.ERRORED if e.has_error_record() else base)
        return e

    def accept(self, r):
        cs = r.call_site()
        out: list[Episode] = []
        is_entry = cs is not None and cs in self.entries
        is_terminal = cs is not None and cs in self.terminals
        if self.open is not None and is_entry:
            out.append(self._close(self.open, TerminalStatus.TRUNCATED))
            self.open = self._start(r)
            if is_terminal:
                out.append(self._close(self.open, TerminalStatus.COMPLETED))
                self.open = None
            return out
        if self.open is not None:
            self.open.add(r)
            if is_terminal:
                out.append(self._close(self.open, TerminalStatus.COMPLETED))
                self.open = None
            return out
        if is_entry:
            self.open = self._start(r)
            if is_terminal:
                out.append(self._close(self.open, TerminalStatus.COMPLETED))
                self.open = None
        return out

    def finish(self):
        if self.open is not None:
            e = self._close(self.open, TerminalStatus.TRUNCATED)
            self.open = None
            return e
        return None


class EntryMarkerStrategy(FlowKeyStrategy):
    def __init__(self, entry_call_sites, terminal_call_sites):
        self.entries = frozenset(entry_call_sites)
        self.terminals = frozenset(terminal_call_sites)

    @property
    def name(self):
        return "ENTRY_MARKER"

    def new_thread_segmenter(self, thread_id):
        return _EntrySegmenter(thread_id, self.entries, self.terminals)


# ---------------------------------------------------------------- IdleGap (B)

class _IdleSegmenter(ThreadSegmenter):
    def __init__(self, thread_id, gap_millis, terminals):
        self.thread_id = thread_id
        self.gap = gap_millis
        self.terminals = terminals
        self.open: Optional[Episode] = None
        self.last_ts = None
        self.terminal_reached = False

    def _start(self, r, ts):
        self.open = Episode(self.thread_id)
        self.open.add(r)
        self.terminal_reached = r.call_site() in self.terminals if r.call_site() else False
        self.last_ts = ts

    def _close(self, e):
        base = TerminalStatus.COMPLETED if self.terminal_reached else TerminalStatus.TRUNCATED
        e.set_status(TerminalStatus.ERRORED if e.has_error_record() else base)
        return e

    def accept(self, r):
        ts = r.timestamp
        if self.open is None:
            self._start(r, ts)
            return []
        gap = 0 if (self.last_ts is None or ts is None) else max(0, epoch_millis(ts) - epoch_millis(self.last_ts))
        if gap > self.gap:
            closed = self._close(self.open)
            self._start(r, ts)
            return [closed]
        self.open.add(r)
        if r.call_site() in self.terminals:
            self.terminal_reached = True
        if ts is not None:
            self.last_ts = ts
        return []

    def finish(self):
        if self.open is not None:
            e = self._close(self.open)
            self.open = None
            return e
        return None


class IdleGapStrategy(FlowKeyStrategy):
    def __init__(self, idle_gap_millis, terminal_call_sites):
        self.gap = idle_gap_millis
        self.terminals = frozenset(terminal_call_sites)

    @property
    def name(self):
        return "IDLE_GAP"

    def new_thread_segmenter(self, thread_id):
        return _IdleSegmenter(thread_id, self.gap, self.terminals)


# ----------------------------------------------------------- CorrelationId (C)

class _CorrelationSegmenter(ThreadSegmenter):
    """Accumulates every record carrying one correlation id, across threads and
    services, and emits a single time-ordered Episode at end of stream."""

    def __init__(self, correlation_id, terminals):
        self.correlation_id = correlation_id
        self.terminals = terminals
        self.records: list[LogRecord] = []

    def accept(self, record):
        self.records.append(record)
        return []          # a correlated flow has no mid-stream boundary

    def finish(self):
        if not self.records:
            return None
        # records arrive per-file, so sort the flow into true time order
        self.records.sort(key=lambda r: (r.timestamp is None, r.timestamp))
        e = Episode(self.correlation_id)
        for r in self.records:
            e.add(r)
        reached = any(r.call_site() in self.terminals for r in self.records)
        base = TerminalStatus.COMPLETED if reached else TerminalStatus.TRUNCATED
        e.set_status(TerminalStatus.ERRORED if e.has_error_record() else base)
        return e


class CorrelationIdStrategy(FlowKeyStrategy):
    """Segments by a correlation id carried in the log (Impl C).

    One flow = every record sharing a correlation id, regardless of which thread
    or which service emitted it. This is what makes a cross-service flow
    (order -> inventory -> payment) a single episode.

    ``pattern`` is a regex applied to each record's message with the id in group
    1, e.g. ``trace_id=([0-9a-f]+)``. Records with no match are dropped.

    Memory note: one open flow is held per in-flight correlation id until the
    stream ends, so this is bounded by concurrent flows rather than being fully
    streaming. Fine for batch analysis; revisit for very large corpora.
    """

    def __init__(self, pattern: str, terminal_call_sites=()):
        if not pattern:
            raise ValueError(
                "CORRELATION_ID strategy requires segmentation.correlationIdPattern, "
                "e.g. 'trace_id=([0-9a-f]+)'")
        self.pattern = re.compile(pattern)
        self.terminals = frozenset(terminal_call_sites)

    @property
    def name(self):
        return "CORRELATION_ID"

    def grouping_key(self, record: LogRecord) -> Optional[str]:
        m = self.pattern.search(record.message or "")
        if not m:
            return None
        return m.group(1) if m.groups() else m.group(0)

    def new_thread_segmenter(self, correlation_id: str) -> ThreadSegmenter:
        return _CorrelationSegmenter(correlation_id, self.terminals)


# ------------------------------------------------------------ streaming driver

class StreamingSegmenter:
    """Drives a strategy over the whole, globally time-ordered record stream,
    holding only one open segmenter per active thread."""

    def __init__(self, strategy: FlowKeyStrategy):
        self.strategy = strategy

    def segment(self, records: Iterator[LogRecord], sink: Callable[[Episode], None]) -> None:
        open_segs: dict[str, ThreadSegmenter] = {}
        for r in records:
            key = self.strategy.grouping_key(r)
            if key is None:
                continue           # record belongs to no flow (e.g. no correlation id)
            seg = open_segs.get(key)
            if seg is None:
                seg = self.strategy.new_thread_segmenter(key)
                open_segs[key] = seg
            for e in seg.accept(r):
                sink(e)
        for seg in open_segs.values():
            last = seg.finish()
            if last is not None:
                sink(last)

    def segment_to_list(self, records: Iterator[LogRecord]) -> list[Episode]:
        out: list[Episode] = []
        self.segment(records, out.append)
        return out
