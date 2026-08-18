"""
Wasteful-memory detector — finds reclaimable heap that isn't a "leak" but is pure
waste: the same array content stored over and over.

Duplicate strings/buffers are routinely 20-40% of a Java heap. Eclipse MAT can find
them ("Group by value"), and the SaaS tools charge for it — but the existing
histogram heuristics here could only *guess* from instance counts and tell the user
to go run MAT. This module does the real thing in-process: it streams the dump once,
hashes the contents of primitive arrays (`byte[]` and `char[]` — the backing stores
for `String` on JDK 9+ and ≤8 respectively), groups identical values, and reports the
actual reclaimable bytes with concrete example values.

It is memory-bounded by construction (a capped dict of content hashes, and it skips
oversized arrays), and — like the retention tracer — gated behind a file-size budget
so it never jeopardizes the primary histogram analysis on a huge dump.
"""
from __future__ import annotations
import hashlib
import os
from typing import BinaryIO, Dict, List, Optional, Tuple

from ..schemas import Finding, Severity
from .heap_dump import (
    _Reader, TYPE_SIZES,
    TAG_UTF8, TAG_LOAD_CLASS, TAG_HEAP_DUMP, TAG_HEAP_DUMP_SEGMENT,
    HEAP_CLASS_DUMP, HEAP_INSTANCE_DUMP, HEAP_OBJECT_ARRAY_DUMP, HEAP_PRIMITIVE_ARRAY_DUMP,
    HEAP_ROOT_UNKNOWN, HEAP_ROOT_JNI_GLOBAL, HEAP_ROOT_JNI_LOCAL, HEAP_ROOT_JAVA_FRAME,
    HEAP_ROOT_NATIVE_STACK, HEAP_ROOT_STICKY_CLASS, HEAP_ROOT_THREAD_BLOCK,
    HEAP_ROOT_MONITOR_USED, HEAP_ROOT_THREAD_OBJ,
)
from .heap_graph import _open
from .heap_sizing import SizeModel, size_model


def _file_size(fp: BinaryIO) -> int:
    try:
        cur = fp.tell()
        fp.seek(0, os.SEEK_END)
        size = fp.tell()
        fp.seek(cur, os.SEEK_SET)
        return size
    except (OSError, AttributeError):
        return 0


# Element type codes we hash (primitive arrays that back strings/buffers).
_BYTE, _CHAR = 8, 5
_ETYPE_NAME = {_BYTE: "byte[]", _CHAR: "char[]"}

# Tuning. Duplicate waste is dominated by *many small identical* values, so we
# skip very large arrays (rarely duplicated en masse, expensive to hash) and cap
# the number of distinct values tracked to bound memory.
_MAX_ARRAY_BYTES = 8 * 1024          # don't hash arrays larger than this
_MAX_DISTINCT = 400_000              # cap on tracked distinct content hashes
_SAMPLE_BYTES = 64                   # how much of a value we keep for display


def _decode_sample(etype: int, data: bytes) -> str:
    """A short, printable preview of an array value for the report."""
    try:
        if etype == _CHAR:
            text = data.decode("utf-16-be", errors="replace")
        else:
            text = data.decode("latin-1", errors="replace")
    except Exception:
        return repr(data[:24])
    text = "".join(ch if 32 <= ord(ch) < 127 else "·" for ch in text)
    return text


class _WasteScanner:
    def __init__(self, fp: BinaryIO, model: Optional[SizeModel] = None):
        self.fp = fp
        self.id_size = 8
        self.model = model or size_model(8, _file_size(fp))
        # content-hash -> [count, per_array_bytes, etype, sample]
        self.groups: Dict[bytes, List] = {}
        self.capped = False
        self.arrays_seen = 0
        self.bytes_in_arrays = 0

    def scan(self) -> None:
        reader, self.id_size = _open(self.fp)
        while True:
            tagb = reader.read(1)
            if not tagb:
                break
            tag = tagb[0]
            reader.u4()                  # timestamp delta
            length = reader.u4()
            if tag in (TAG_HEAP_DUMP, TAG_HEAP_DUMP_SEGMENT):
                self._scan_segment(reader, reader.pos + length)
            else:
                reader.skip(length)

    def _scan_segment(self, reader: _Reader, seg_end: int) -> None:
        id_size = self.id_size
        while reader.pos < seg_end:
            sub = reader.u1()
            if sub == HEAP_PRIMITIVE_ARRAY_DUMP:
                reader.id(id_size); reader.u4()            # oid, stack serial
                n = reader.u4(); etype = reader.u1()
                esize = TYPE_SIZES.get(etype, 0)
                nbytes = n * esize
                if etype in (_BYTE, _CHAR) and 0 < nbytes <= _MAX_ARRAY_BYTES:
                    self._record(etype, reader.read(nbytes), nbytes)
                else:
                    reader.skip(nbytes)
            elif sub == HEAP_INSTANCE_DUMP:
                reader.id(id_size); reader.u4(); reader.id(id_size)
                reader.skip(reader.u4())
            elif sub == HEAP_OBJECT_ARRAY_DUMP:
                reader.id(id_size); reader.u4()
                n = reader.u4(); reader.id(id_size)
                reader.skip(n * id_size)
            elif sub == HEAP_CLASS_DUMP:
                _skip_class_dump(reader, id_size)
            elif sub in (HEAP_ROOT_UNKNOWN, HEAP_ROOT_STICKY_CLASS, HEAP_ROOT_MONITOR_USED):
                reader.id(id_size)
            elif sub == HEAP_ROOT_JNI_GLOBAL:
                reader.id(id_size); reader.id(id_size)
            elif sub in (HEAP_ROOT_JNI_LOCAL, HEAP_ROOT_JAVA_FRAME, HEAP_ROOT_THREAD_OBJ):
                reader.id(id_size); reader.skip(8)
            elif sub in (HEAP_ROOT_NATIVE_STACK, HEAP_ROOT_THREAD_BLOCK):
                reader.id(id_size); reader.skip(4)
            else:
                reader.skip(max(0, seg_end - reader.pos))
                return

    def _record(self, etype: int, data: bytes, nbytes: int) -> None:
        # Size the array the way the histogram does, so "reclaimable bytes" is
        # directly comparable with the shallow sizes shown next to it.
        allocated = self.model.prim_array_size(nbytes, 1)
        self.arrays_seen += 1
        self.bytes_in_arrays += allocated
        h = hashlib.blake2b(data, digest_size=16).digest()
        g = self.groups.get(h)
        if g is not None:
            g[0] += 1
            return
        if len(self.groups) >= _MAX_DISTINCT:
            self.capped = True
            return
        self.groups[h] = [1, allocated, etype, data[:_SAMPLE_BYTES]]


def _skip_class_dump(reader: _Reader, id_size: int) -> None:
    reader.id(id_size); reader.u4(); reader.id(id_size)
    for _ in range(5):
        reader.id(id_size)
    reader.u4()                              # instance size
    cp = reader.u2()
    for _ in range(cp):
        reader.u2(); t = reader.u1()
        reader.skip(id_size if t == 2 else TYPE_SIZES.get(t, 0))
    n_static = reader.u2()
    for _ in range(n_static):
        reader.id(id_size); t = reader.u1()
        reader.skip(id_size if t == 2 else TYPE_SIZES.get(t, 0))
    n_fields = reader.u2()
    for _ in range(n_fields):
        reader.id(id_size); reader.u1()


def _fmt_bytes(n: float) -> str:
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:.1f} PB"


def find_wasted_memory(
    fp: BinaryIO, total_heap_bytes: int = 0
) -> Tuple[List[Finding], int]:
    """Scan for duplicated primitive-array content. Returns (findings, wasted_bytes).

    Best-effort and bounded — see the module docstring. `total_heap_bytes` (the
    shallow size from the histogram) is used only to express waste as a percentage.
    """
    scanner = _WasteScanner(fp)
    scanner.scan()

    dups = [(h, g) for h, g in scanner.groups.items() if g[0] >= 2]
    if not dups:
        return [], 0

    # wasted = the redundant copies: (count - 1) * per-array-bytes.
    ranked = sorted(
        dups, key=lambda kg: (kg[1][0] - 1) * kg[1][1], reverse=True
    )
    wasted_total = sum((g[0] - 1) * g[1] for _, g in ranked)
    dup_value_count = len(ranked)
    redundant_copies = sum(g[0] - 1 for _, g in ranked)

    pct = (wasted_total / total_heap_bytes * 100) if total_heap_bytes else 0.0
    if wasted_total < 1024 * 1024 and pct < 3:
        # Not worth a finding — every heap has a little duplication.
        return [], wasted_total

    severity = Severity.WARNING
    if pct >= 15 or wasted_total >= 256 * 1024 * 1024:
        severity = Severity.CRITICAL

    examples = []
    for _, g in ranked[:6]:
        count, per, etype, sample = g
        preview = _decode_sample(etype, sample)
        if len(preview) > 48:
            preview = preview[:48] + "…"
        examples.append(
            f"{count:,}× {_ETYPE_NAME[etype]} \"{preview}\" "
            f"→ wastes {_fmt_bytes((count - 1) * per)}"
        )

    pct_txt = f" (~{pct:.0f}% of measured heap)" if total_heap_bytes else ""
    capped_note = (
        " Note: distinct-value tracking hit its cap, so the true waste is at least this much."
        if scanner.capped else ""
    )

    finding = Finding(
        severity=severity,
        title=f"Duplicate data wastes ~{_fmt_bytes(wasted_total)}{pct_txt} of heap",
        description=(
            f"{redundant_copies:,} redundant copies of {dup_value_count:,} distinct "
            f"array values (the backing stores of Strings and buffers) are sitting in the "
            f"heap. This isn't a leak — it's the same content stored many times over, and "
            f"it's directly reclaimable by de-duplicating." + capped_note
        ),
        impact=(
            "Pure waste: memory that could be freed with no behavior change. It inflates the "
            "live set, leaving less headroom before GC pressure and OutOfMemoryError."
        ),
        likely_cause=(
            "Strings or byte buffers built fresh each time instead of being interned/shared — "
            "parsing the same tokens repeatedly, per-row labels, repeated config/JSON keys, or "
            "defensive copies of constant data."
        ),
        evidence=examples + [
            f"{redundant_copies:,} redundant array copies across {dup_value_count:,} distinct values",
            f"scanned {scanner.arrays_seen:,} byte[]/char[] arrays",
        ],
        remediation=(
            "Enable G1 string de-duplication (`-XX:+UseStringDeduplication`) for a zero-code "
            "win, and/or intern or cache the canonical instances of the hot values shown above "
            "(a shared constant, an enum, or a small `Map<String,String>` interner on the hot "
            "path). Avoid defensive-copying immutable byte[] payloads."
        ),
        category="memory",
    )
    return [finding], wasted_total
