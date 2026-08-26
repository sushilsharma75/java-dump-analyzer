"""Ingestion: turn a directory of log files into an ordered stream of LogRecord.

**There is no format profile and no parser configuration.** Any text log works.
Each line is read best-effort by `tfa.extract`: timestamp, level, thread and
`Class:line` where present, and a normalised message template as the call-site
identity where not. Nothing is ever rejected for "not matching a format", so a
run can never abort - or silently analyse a fraction of the corpus - because a
layout was unexpected.

Record contract: a line starts a new record unless it is an unindented,
non-stack-frame continuation of the line above it (stack frames and indented
payload lines attach to the record they belong to, and are never dropped).
"""
from __future__ import annotations

import gzip
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

from .extract import (call_site_of, epoch_millis, is_stack_frame, level_of,
                      normalise_template, parse_any_timestamp, thread_of)
from .model import LogRecord

__all__ = ["FileSetReader", "ParseStats", "LineExtractor", "epoch_millis"]


@dataclass
class ParseStats:
    """Line accounting. Every input line is either a record or a continuation -
    nothing is discarded, so there is no 'malformed' bucket to explain away."""
    total_lines: int = 0
    records: int = 0
    continuation: int = 0
    without_timestamp: int = 0
    without_call_site: int = 0


class LineExtractor:
    """Turns one raw line into a LogRecord, best-effort, for any format."""

    def build(self, line: str, source_file: str, line_no: int,
              stats: Optional[ParseStats] = None) -> LogRecord:
        ts = parse_any_timestamp(line)
        cs = call_site_of(line)
        if cs:
            cls, _, ln = cs.rpartition(":")
            class_name, line_number = cls, int(ln)
        else:
            # no Class:line in this format - fall back to a message template so
            # the line still has a stable identity downstream
            class_name, line_number = normalise_template(line), -1
        if stats is not None:
            if ts is None:
                stats.without_timestamp += 1
            if not cs:
                stats.without_call_site += 1
        return LogRecord(ts, level_of(line), thread_of(line), class_name, line_number,
                         line.strip(), (), source_file, line_no)


def _open_text(path: Path):
    if path.name.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


class FileSetReader:
    """Presents a directory of log files as one lazily-evaluated stream of
    LogRecord. Files are ordered by the first timestamp found inside them, never
    by filename; files with no recognisable timestamp sort last."""

    FIRST_TS_SCAN_LIMIT = 5000

    def __init__(self, root, stats: Optional[ParseStats] = None,
                 extractor: Optional[LineExtractor] = None):
        self.stats = stats if stats is not None else ParseStats()
        self.extractor = extractor or LineExtractor()
        self._files = self._order_by_timestamp(self._collect(Path(root)))

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
        keyed.sort(key=lambda k: (k[0] is None,
                                  k[0] or datetime.min.replace(tzinfo=timezone.utc), k[1]))
        return [p for _, _, p in keyed]

    def _first_timestamp(self, path: Path) -> Optional[datetime]:
        try:
            with _open_text(path) as fh:
                for i, line in enumerate(fh):
                    if i >= self.FIRST_TS_SCAN_LIMIT:
                        break
                    ts = parse_any_timestamp(line)
                    if ts:
                        return ts
        except OSError:
            return None
        return None

    def records(self) -> Iterator[LogRecord]:
        pending: Optional[LogRecord] = None
        conts: list[str] = []
        for path in self._files:
            with _open_text(path) as fh:
                for line_no, raw in enumerate(fh, 1):
                    line = raw.rstrip("\n")
                    self.stats.total_lines += 1
                    if pending is not None and self._is_continuation(line):
                        self.stats.continuation += 1
                        conts.append(line)
                        continue
                    if pending is not None:
                        yield _with_continuations(pending, conts)
                    conts = []
                    pending = self.extractor.build(line, str(path), line_no, self.stats)
                    self.stats.records += 1
        if pending is not None:
            yield _with_continuations(pending, conts)

    @staticmethod
    def _is_continuation(line: str) -> bool:
        """A stack frame or an indented line belongs to the record above it."""
        if not line.strip():
            return False
        if parse_any_timestamp(line) is not None:
            return False
        return is_stack_frame(line) or line[0] in " \t"


def _with_continuations(record: LogRecord, conts: list[str]) -> LogRecord:
    if not conts:
        return record
    return LogRecord(record.timestamp, record.level, record.thread_id, record.class_name,
                     record.line_number, record.message, tuple(conts),
                     record.source_file, record.line_number_in_file)
