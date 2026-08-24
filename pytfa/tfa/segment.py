"""Episode segmentation — the pluggable flow-key strategies and the streaming
driver. Port of the Java `tfa.segment` package."""
from __future__ import annotations

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

class CorrelationIdStrategy(FlowKeyStrategy):
    """V1 stub. Logs do not carry a correlation id yet. Exists to prove the
    interface accommodates a future cross-thread key without a redesign."""

    @property
    def name(self):
        return "CORRELATION_ID"

    def new_thread_segmenter(self, thread_id):
        raise NotImplementedError(
            "CorrelationIdStrategy is a V1 stub - logs do not carry a correlation id yet.")


# ------------------------------------------------------------ streaming driver

class StreamingSegmenter:
    """Drives a strategy over the whole, globally time-ordered record stream,
    holding only one open segmenter per active thread."""

    def __init__(self, strategy: FlowKeyStrategy):
        self.strategy = strategy

    def segment(self, records: Iterator[LogRecord], sink: Callable[[Episode], None]) -> None:
        open_segs: dict[str, ThreadSegmenter] = {}
        for r in records:
            seg = open_segs.get(r.thread_id)
            if seg is None:
                seg = self.strategy.new_thread_segmenter(r.thread_id)
                open_segs[r.thread_id] = seg
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
