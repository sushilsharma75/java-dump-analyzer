"""
Streaming parser for HotSpot JVM heap dump files (.hprof binary format).

The hprof format is a sequence of records: u1 tag + u4 timestamp delta + u4 length + body.
We walk the file once, building:
  - String table (UTF-8 records keyed by id)
  - Class table (class id -> class name id)
  - Per-class instance count and total shallow size (from HEAP_DUMP_SEGMENT sub-records)

This pass alone produces the histogram-style metrics that catch the majority of
"what's eating my heap" investigations; exact retained sizes, dominator trees and
GC-root paths are layered on by heap_dominators / heap_graph when the dump is
small enough for them (see `skipped_analyses` on the result — the analysis always
says which of its stages actually ran).

Shallow sizes come from heap_sizing, which reconstructs the real JVM object layout
(header + alignment, references at their live width) rather than reporting the raw
hprof payload length.

Spec reference: openjdk hprof.h (HotSpot Serviceability).
"""
from __future__ import annotations
import struct
import os
from collections import defaultdict, Counter
from typing import BinaryIO, Dict, Optional, Tuple, List
from ..schemas import (
    HeapDumpAnalysis, ClassHistogramEntry, Finding, Severity, ClassReference,
    SourceSnippet, SourceLocation, SkippedAnalysis,
)
from .source import is_user_code
from .heap_sizing import SizeModel, size_model


# Top-level record tags
TAG_UTF8 = 0x01
TAG_LOAD_CLASS = 0x02
TAG_UNLOAD_CLASS = 0x03
TAG_FRAME = 0x04
TAG_TRACE = 0x05
TAG_ALLOC_SITES = 0x06
TAG_HEAP_SUMMARY = 0x07
TAG_START_THREAD = 0x0A
TAG_END_THREAD = 0x0B
TAG_HEAP_DUMP = 0x0C
TAG_HEAP_DUMP_SEGMENT = 0x1C
TAG_HEAP_DUMP_END = 0x2C
TAG_CPU_SAMPLES = 0x0D
TAG_CONTROL_SETTINGS = 0x0E

TAG_NAMES = {
    TAG_UTF8: "UTF8",
    TAG_LOAD_CLASS: "LOAD_CLASS",
    TAG_UNLOAD_CLASS: "UNLOAD_CLASS",
    TAG_FRAME: "FRAME",
    TAG_TRACE: "TRACE",
    TAG_ALLOC_SITES: "ALLOC_SITES",
    TAG_HEAP_SUMMARY: "HEAP_SUMMARY",
    TAG_START_THREAD: "START_THREAD",
    TAG_END_THREAD: "END_THREAD",
    TAG_HEAP_DUMP: "HEAP_DUMP",
    TAG_HEAP_DUMP_SEGMENT: "HEAP_DUMP_SEGMENT",
    TAG_HEAP_DUMP_END: "HEAP_DUMP_END",
    TAG_CPU_SAMPLES: "CPU_SAMPLES",
    TAG_CONTROL_SETTINGS: "CONTROL_SETTINGS",
}

# Heap sub-record tags (inside HEAP_DUMP / HEAP_DUMP_SEGMENT)
HEAP_ROOT_UNKNOWN = 0xFF
HEAP_ROOT_JNI_GLOBAL = 0x01
HEAP_ROOT_JNI_LOCAL = 0x02
HEAP_ROOT_JAVA_FRAME = 0x03
HEAP_ROOT_NATIVE_STACK = 0x04
HEAP_ROOT_STICKY_CLASS = 0x05
HEAP_ROOT_THREAD_BLOCK = 0x06
HEAP_ROOT_MONITOR_USED = 0x07
HEAP_ROOT_THREAD_OBJ = 0x08
HEAP_CLASS_DUMP = 0x20
HEAP_INSTANCE_DUMP = 0x21
HEAP_OBJECT_ARRAY_DUMP = 0x22
HEAP_PRIMITIVE_ARRAY_DUMP = 0x23

# Primitive type sizes (used inside CLASS_DUMP and array dumps)
TYPE_SIZES = {
    2: 0,   # object (depends on id_size; computed at parse time)
    4: 1,   # boolean
    5: 2,   # char
    6: 4,   # float
    7: 8,   # double
    8: 1,   # byte
    9: 2,   # short
    10: 4,  # int
    11: 8,  # long
}


class _Reader:
    """Buffered reader with positional tracking.

    The hprof parser does millions of small reads (1-8 bytes at a time). Without
    buffering, each one is a syscall and the parser is hopelessly slow on big
    dumps. The buffer is refilled in large chunks, giving ~50x speedup.
    """

    def __init__(self, fp: BinaryIO, buf_size: int = 4 * 1024 * 1024):
        self.fp = fp
        self._buf = b""
        self._buf_pos = 0
        self._buf_size = buf_size
        self.pos = 0  # absolute byte position in the underlying stream

    def _ensure(self, n: int) -> None:
        """Refill buffer if it doesn't have at least n bytes available."""
        avail = len(self._buf) - self._buf_pos
        if avail >= n:
            return
        # Compact remaining bytes to the front, then read more
        remaining = self._buf[self._buf_pos:] if avail > 0 else b""
        need = max(self._buf_size, n)
        chunk = self.fp.read(need)
        self._buf = remaining + chunk
        self._buf_pos = 0

    def read(self, n: int) -> bytes:
        self._ensure(n)
        avail = len(self._buf) - self._buf_pos
        if avail < n:
            # EOF within request — return whatever we have
            data = self._buf[self._buf_pos:]
            self._buf_pos = len(self._buf)
            self.pos += len(data)
            return data
        data = self._buf[self._buf_pos:self._buf_pos + n]
        self._buf_pos += n
        self.pos += n
        return data

    def skip(self, n: int) -> None:
        """Advance n bytes, using seek where possible for speed."""
        if n <= 0:
            return
        # First, consume any bytes already in the buffer
        avail = len(self._buf) - self._buf_pos
        if avail >= n:
            self._buf_pos += n
            self.pos += n
            return
        # Drop the buffer
        consumed = avail
        self._buf = b""
        self._buf_pos = 0
        self.pos += consumed
        remaining = n - consumed

        # Try to seek for the rest
        try:
            self.fp.seek(remaining, os.SEEK_CUR)
            self.pos += remaining
        except (OSError, AttributeError):
            # Non-seekable stream — read and discard
            while remaining > 0:
                chunk = self.fp.read(min(remaining, 65536))
                if not chunk:
                    break
                remaining -= len(chunk)
                self.pos += len(chunk)

    def u1(self) -> int:
        return self.read(1)[0]

    def u2(self) -> int:
        return struct.unpack(">H", self.read(2))[0]

    def u4(self) -> int:
        return struct.unpack(">I", self.read(4))[0]

    def u8(self) -> int:
        return struct.unpack(">Q", self.read(8))[0]

    def id(self, id_size: int) -> int:
        if id_size == 4:
            return self.u4()
        elif id_size == 8:
            return self.u8()
        raise ValueError(f"Unsupported identifier size: {id_size}")


def _normalize_class_name(name: str) -> str:
    """Convert JNI signature 'Ljava/lang/String;' or 'java/lang/String' to 'java.lang.String'."""
    if not name:
        return ""
    # Array notation: [Ljava/lang/String; -> java.lang.String[]
    arr_dims = 0
    while name.startswith("["):
        arr_dims += 1
        name = name[1:]
    if name.startswith("L") and name.endswith(";"):
        name = name[1:-1]
    # Primitive array element types (B, C, etc.) handled inline
    prim_map = {"B": "byte", "C": "char", "D": "double", "F": "float",
                "I": "int", "J": "long", "S": "short", "Z": "boolean"}
    if arr_dims > 0 and len(name) == 1 and name in prim_map:
        name = prim_map[name]
    name = name.replace("/", ".")
    return name + ("[]" * arr_dims)


def parse_heap_dump(
    fp: BinaryIO,
    max_bytes: Optional[int] = None,
    progress_callback: Optional[callable] = None,
    progress_interval_records: int = 5000,
    source=None,
    trace_graph: bool = True,
) -> HeapDumpAnalysis:
    """
    Stream-parse an .hprof file.

    Args:
        fp: binary stream to parse from
        max_bytes: if set, stop after reading this many bytes (quick mode)
        progress_callback: optional callable(bytes_processed, records_seen, instances_seen).
            Called periodically so a UI can show a progress bar.
        progress_interval_records: how often (in records) to fire the callback.
    """
    reader = _Reader(fp)
    file_size = _stream_size(fp)

    # --- Header ---
    # A valid hprof begins with an ASCII string like "JAVA PROFILE 1.0.2" terminated
    # by a NUL byte. We collect up to 64 bytes looking for that NUL; if we hit the
    # limit, the file is almost certainly not an hprof — most often a thread dump
    # uploaded to the wrong endpoint.
    header_bytes = bytearray()
    while True:
        b = reader.read(1)
        if not b:
            raise ValueError("Unexpected EOF reading header — file is empty or truncated")
        if b == b"\x00":
            break
        header_bytes.extend(b)
        if len(header_bytes) > 64:
            preview = bytes(header_bytes[:60]).decode("ascii", errors="replace")
            # If it looks like text (no control chars beyond newline/tab), it's
            # very likely a thread dump or some other text file.
            looks_textual = all(
                ch in (9, 10, 13) or 32 <= ch < 127 for ch in header_bytes
            )
            if looks_textual:
                hint = "Full thread dump" in preview or preview.lstrip().startswith(("20", "19"))
                if hint:
                    raise ValueError(
                        "This file looks like a thread dump (text), not a heap dump (.hprof binary). "
                        "Use the Thread Dump upload zone instead."
                    )
                raise ValueError(
                    "This file appears to be plain text, not a binary .hprof heap dump. "
                    "Heap dumps come from `jmap -dump:format=b,file=…` or `jcmd <pid> GC.heap_dump …`."
                )
            raise ValueError(
                f"Not a valid .hprof file — header doesn't start with 'JAVA PROFILE' "
                f"(got: {preview!r})"
            )

    header = header_bytes.decode("ascii", errors="replace")
    if not header.startswith("JAVA PROFILE"):
        raise ValueError(
            f"Not a valid .hprof file — expected header 'JAVA PROFILE …' but got {header!r}"
        )

    id_size = reader.u4()
    if id_size not in (4, 8):
        raise ValueError(f"Unsupported identifier size in header: {id_size}")

    ts_high = reader.u4()
    ts_low = reader.u4()
    timestamp_ms = (ts_high << 32) | ts_low

    # Object layout this dump was produced under — decides headers, alignment,
    # and reference width for every shallow size we report.
    model = size_model(id_size, file_size)

    # --- Tables ---
    strings: Dict[int, str] = {}
    # class_obj_id -> class_name_id
    class_obj_to_name_id: Dict[int, int] = {}
    # class_obj_id -> aggregate stats
    instance_count: Dict[int, int] = defaultdict(int)
    instance_size: Dict[int, int] = defaultdict(int)
    # for object arrays we also key by element class
    array_count: Dict[int, int] = defaultdict(int)
    array_size: Dict[int, int] = defaultdict(int)

    # Static object fields: (class_obj_id, field_name_id, value_obj_id) for every
    # static field holding a live (non-null) object reference. Static fields are
    # GC roots and the #1 source of "I left a cache/registry unbounded" leaks, so
    # this is what lets us point a leak at an exact line of the user's code.
    # Bounded by (#classes x #static object fields) — typically tens of thousands.
    static_object_fields: List[Tuple[int, int, int]] = []

    # Deployment/thread capture rides along on this pass: CLASS_DUMP carries the
    # classloader + protection domain of every class (which WAR it came from), and
    # ROOT_THREAD_OBJ carries the id of every live thread. Both are emitted before
    # the first instance record, so no forward reference is ever needed.
    from .heap_deployments import DeploymentScan
    scan = DeploymentScan(id_size, strings, class_obj_to_name_id)

    record_type_counts: Counter = Counter()
    # Set when quick mode's byte budget ran out inside a heap segment; carries the
    # offset we actually stopped reading at, which is not where the stream ends.
    stopped_early_at: Optional[int] = None
    total_records = 0
    total_instances_so_far = 0  # running counter for progress
    total_strings_recorded = 0

    while True:
        tag_byte = reader.read(1)
        if not tag_byte:
            break  # EOF
        tag = tag_byte[0]
        try:
            _ = reader.u4()  # timestamp delta (ignored)
            length = reader.u4()
        except struct.error:
            break

        total_records += 1
        record_type_counts[TAG_NAMES.get(tag, f"UNKNOWN_{tag:02x}")] += 1

        # Progress reporting (every N records, cheap)
        if progress_callback and total_records % progress_interval_records == 0:
            try:
                progress_callback(reader.pos, total_records, total_instances_so_far)
            except Exception:
                pass  # never let a callback failure break parsing

        if max_bytes and reader.pos > max_bytes:
            break

        if tag == TAG_UTF8:
            if length < id_size:
                reader.skip(length)
                continue
            sid = reader.id(id_size)
            data = reader.read(length - id_size)
            try:
                strings[sid] = data.decode("utf-8", errors="replace")
            except Exception:
                strings[sid] = ""
        elif tag == TAG_LOAD_CLASS:
            # u4 class serial num, id class obj id, u4 stack trace serial, id class name id
            _ = reader.u4()
            class_obj_id = reader.id(id_size)
            _ = reader.u4()
            class_name_id = reader.id(id_size)
            class_obj_to_name_id[class_obj_id] = class_name_id
        elif tag in (TAG_HEAP_DUMP, TAG_HEAP_DUMP_SEGMENT):
            stopped_at = _scan_heap_segment(
                reader, length, id_size,
                instance_count, instance_size,
                array_count, array_size,
                progress_callback, progress_interval_records, total_records,
                static_object_fields,
                scan,
                model,
                max_bytes,
            )
            total_instances_so_far = sum(instance_count.values())
            if stopped_at is not None:
                stopped_early_at = stopped_at
                break
        else:
            # Skip unknown / uninteresting records
            reader.skip(length)

    # Final progress tick
    if progress_callback:
        try:
            progress_callback(reader.pos, total_records, total_instances_so_far)
        except Exception:
            pass

    # --- Correct instance shallow sizes ---
    # Every CLASS_DUMP has been seen by now, so each class's reference-field count
    # (its own plus its superclasses') is finally resolvable. All instances of a
    # class share one field layout, so the per-instance payload is exact.
    instance_size = _shallow_by_class(instance_count, instance_size, scan, model, id_size)

    # --- Build histogram ---
    aggregate_count: Dict[str, int] = defaultdict(int)
    aggregate_size: Dict[str, int] = defaultdict(int)

    for class_obj_id, cnt in instance_count.items():
        name_id = class_obj_to_name_id.get(class_obj_id)
        cname = _normalize_class_name(strings.get(name_id, f"<class@{class_obj_id:x}>"))
        aggregate_count[cname] += cnt
        aggregate_size[cname] += instance_size.get(class_obj_id, 0)

    for class_obj_id, cnt in array_count.items():
        if class_obj_id < 0:
            # Primitive array: synthetic negative key encodes the element type
            cname = _PRIM_ARRAY_NAMES.get(-class_obj_id, f"<prim:{-class_obj_id}>[]")
        else:
            name_id = class_obj_to_name_id.get(class_obj_id)
            cname_raw = strings.get(name_id, f"<class@{class_obj_id:x}>") if name_id else f"<class@{class_obj_id:x}>"
            cname = _normalize_class_name(cname_raw)
            if not cname.endswith("[]"):
                cname = cname + "[]"
        aggregate_count[cname] += cnt
        aggregate_size[cname] += array_size.get(class_obj_id, 0)

    histogram = [
        ClassHistogramEntry(
            class_name=name,
            instance_count=aggregate_count[name],
            shallow_size_bytes=aggregate_size[name],
        )
        for name in aggregate_count
    ]
    histogram_by_count = sorted(histogram, key=lambda e: e.instance_count, reverse=True)
    histogram_by_size = sorted(histogram, key=lambda e: e.shallow_size_bytes, reverse=True)

    # Annotate top entries with % of measured bytes and a plain-English explanation
    total_shallow = sum(h.shallow_size_bytes for h in histogram) or 1
    for h in histogram_by_size[:30] + histogram_by_count[:30]:
        h.pct_of_total_size = round(h.shallow_size_bytes / total_shallow * 100, 1)
        h.explanation = _explain_class(h.class_name)

    # If a source repo is attached, find where the user's own code references the
    # biggest classes — answers "which of MY methods creates/holds this?".
    if source is not None:
        _attach_references(source, histogram_by_size[:8])
        _attach_references(source, histogram_by_count[:8])

    total_instances = sum(aggregate_count.values())
    string_entry = next((h for h in histogram if h.class_name == "java.lang.String"), None)
    total_strings_recorded = string_entry.instance_count if string_entry else 0

    # --- Findings ---
    analyzed_bytes = stopped_early_at if stopped_early_at is not None else reader.pos
    truncated = bool(max_bytes and file_size and analyzed_bytes < file_size)
    skipped: List[SkippedAnalysis] = []

    findings = _build_heap_findings(histogram_by_count, histogram_by_size, total_instances, file_size)

    # Static-field leak suspects: map GC-root static fields to the exact line in
    # the user's source where they're declared. This is the heap → code bridge.
    static_findings = _build_static_field_findings(
        static_object_fields, class_obj_to_name_id, strings, source,
        histogram_by_count, histogram_by_size,
    )
    if static_findings:
        # A concrete suspect supersedes the generic "nothing found" note.
        findings = [f for f in findings if f.title != "No obvious red flags"]
        findings = static_findings + findings

    # Retention tracing (Phase 2): walk the reference graph in reverse to find
    # what holds the top consumer alive. Multi-pass, so gated by file size; never
    # let it break the primary analysis.
    graph_gate = _gate_reason("retention tracing (what holds the top consumer)",
                              enabled=trace_graph, truncated=truncated,
                              file_size=file_size, limit=_graph_max_bytes(),
                              seekable=_seekable(fp),
                              env_hint="HEAP_GRAPH_MAX_BYTES")
    if graph_gate:
        skipped.append(graph_gate)
    else:
        leaf = _pick_trace_leaf(histogram_by_size, histogram_by_count)
        if leaf:
            try:
                from .heap_graph import trace_retention
                rf = trace_retention(fp, leaf, source=source)
                if rf:
                    findings = [f for f in findings if f.title != "No obvious red flags"]
                    findings.insert(0, rf)
            except Exception:
                pass  # best-effort; histogram + other findings still stand

    # Wasteful-memory detection (duplicate arrays). Bounded second pass, gated by
    # file size and toggleable via HEAP_WASTE_TRACE=0; never breaks the histogram.
    wasted_bytes = None
    waste_gate = _gate_reason("duplicate-string / duplicate-buffer scan",
                              enabled=os.environ.get("HEAP_WASTE_TRACE", "1") != "0",
                              truncated=truncated, file_size=file_size,
                              limit=_waste_max_bytes(), seekable=_seekable(fp),
                              env_hint="HEAP_WASTE_MAX_BYTES")
    if waste_gate:
        skipped.append(waste_gate)
    else:
        try:
            from .heap_waste import find_wasted_memory
            total_shallow = sum(h.shallow_size_bytes for h in histogram_by_size)
            waste_findings, wasted_bytes = find_wasted_memory(fp, total_shallow)
            if waste_findings:
                findings = [f for f in findings if f.title != "No obvious red flags"]
                findings.extend(waste_findings)
        except Exception:
            pass  # best-effort

    # Dominator tree → exact retained sizes (the Eclipse-MAT-core number), leak
    # suspects, and unreachable-object accounting. Memory scales with the object
    # count, so it's gated by file size; above the gate the heuristic retention
    # tracer above still stands.
    dominator_entries: List = []
    reachable_bytes = unreachable_instances = unreachable_bytes = None
    from .heap_dominators import dominator_max_bytes
    dom_gate = _gate_reason("dominator tree (exact retained sizes, leak suspects, "
                            "unreachable-object accounting)",
                            enabled=True, truncated=truncated, file_size=file_size,
                            limit=dominator_max_bytes(), seekable=_seekable(fp),
                            env_hint="HEAP_DOMINATOR_MAX_BYTES")
    if dom_gate:
        skipped.append(dom_gate)
    else:
        try:
            from .heap_dominators import compute_retained
            rr = compute_retained(fp, model=model)
            dominator_entries = rr.entries
            reachable_bytes = rr.reachable_bytes
            unreachable_instances = rr.unreachable_count
            unreachable_bytes = rr.unreachable_bytes
            if rr.findings:
                findings = [f for f in findings if f.title != "No obvious red flags"]
                findings = rr.findings + findings
        except Exception:
            if os.environ.get("HEAP_DEPLOY_STRICT"):
                raise
            skipped.append(SkippedAnalysis(
                stage="dominator tree (exact retained sizes)",
                reason="the graph pass failed on this dump; the histogram and "
                       "static-field findings below are unaffected",
            ))

    # Deployment (WAR/classloader) + thread attribution. The structural half came
    # free with the main pass; resolving the leaf strings (thread names, the
    # CodeSource .war path) needs the file again, so it's skipped for non-seekable
    # streams and quick mode — the deployments still resolve, just labelled by
    # loader class and package prefix rather than by file path.
    deployments, thread_ownership, duplicate_classes = [], None, []
    try:
        from .heap_deployments import analyze_deployments, find_duplicate_classes
        deployments, thread_ownership, dep_findings = analyze_deployments(
            scan, instance_count, instance_size,
            fp=fp if (_seekable(fp) and not max_bytes) else None,
        )
        duplicate_classes = find_duplicate_classes(scan, deployments)
        if dep_findings:
            findings = [f for f in findings if f.title != "No obvious red flags"]
            findings = dep_findings + findings
    except Exception:
        if os.environ.get("HEAP_DEPLOY_STRICT"):
            raise
        pass  # never let attribution break the histogram

    # Say plainly when the numbers describe only part of the dump, or when the
    # deep stages didn't run — otherwise a partial analysis reads like a complete
    # one, which is the most dangerous failure mode this tool can have.
    if truncated:
        findings.insert(0, _truncation_finding(analyzed_bytes, file_size))
    elif skipped:
        findings.append(_skipped_finding(skipped, file_size))

    summary = _build_heap_summary(histogram_by_size, total_instances, file_size,
                                  findings, truncated=truncated,
                                  analyzed_bytes=analyzed_bytes)

    return HeapDumpAnalysis(
        header=header,
        identifier_size=id_size,
        timestamp_ms=timestamp_ms,
        file_size_bytes=file_size,
        analyzed_bytes=analyzed_bytes,
        truncated=truncated,
        sizing_model=model.name,
        skipped_analyses=skipped,
        total_records=total_records,
        record_type_counts=dict(record_type_counts),
        total_classes_loaded=len(class_obj_to_name_id),
        total_strings=total_strings_recorded,
        total_utf8_records=len(strings),
        total_instances=total_instances,
        top_classes_by_count=histogram_by_count[:30],
        top_classes_by_size=histogram_by_size[:30],
        suspicious_classes=[h.class_name for h in histogram_by_size[:10]
                            if _is_suspicious(h.class_name, h.instance_count)],
        findings=findings,
        wasted_bytes_estimate=wasted_bytes,
        deployments=deployments,
        thread_ownership=thread_ownership,
        dominators=dominator_entries,
        reachable_bytes=reachable_bytes,
        unreachable_instances=unreachable_instances,
        unreachable_bytes=unreachable_bytes,
        duplicate_classes=duplicate_classes,
        summary=summary,
        verdict=(
            "critical" if any(f.severity == Severity.CRITICAL for f in findings)
            else "degraded" if any(f.severity == Severity.WARNING for f in findings)
            else "healthy"
        ),
    )


def _gate_reason(
    stage: str,
    *,
    enabled: bool,
    truncated: bool,
    file_size: int,
    limit: int,
    seekable: bool,
    env_hint: str,
) -> Optional["SkippedAnalysis"]:
    """None if the stage may run, otherwise why it can't."""
    if not enabled or limit <= 0:
        return SkippedAnalysis(
            stage=stage,
            reason="disabled by configuration on this server",
            enable_hint=f"unset the disabling env var (see {env_hint})",
        )
    if truncated:
        return SkippedAnalysis(
            stage=stage,
            reason="quick mode only reads a prefix of the dump, and this stage "
                   "needs the whole object graph to be correct",
            enable_hint="re-run without quick mode",
        )
    if not seekable:
        return SkippedAnalysis(
            stage=stage,
            reason="the dump was streamed rather than stored, and this stage needs "
                   "multiple passes over the file",
            enable_hint="upload the file or use the server-side path option",
        )
    if not file_size:
        return SkippedAnalysis(stage=stage, reason="the dump's size could not be determined")
    if file_size > limit:
        return SkippedAnalysis(
            stage=stage,
            reason=f"dump is {_fmt_bytes(file_size)}, above this stage's "
                   f"{_fmt_bytes(limit)} ceiling",
            enable_hint=f"raise {env_hint} to opt this dump in (costs time and RAM)",
        )
    return None


def _truncation_finding(analyzed_bytes: int, file_size: int) -> Finding:
    pct = (analyzed_bytes / file_size * 100) if file_size else 0
    return Finding(
        severity=Severity.WARNING,
        title=f"Partial analysis — only {_fmt_bytes(analyzed_bytes)} of "
              f"{_fmt_bytes(file_size)} ({pct:.0f}%) was read",
        description=(
            "Quick mode samples the start of the dump so a huge file returns "
            "something fast. Every instance count, size and percentage on this page "
            "describes that prefix only. Objects are not ordered by importance in an "
            "hprof file, so the sample is not a random sample — a class that appears "
            "small here can dominate the rest of the dump."
        ),
        impact="Treating these numbers as whole-heap totals will point the "
               "investigation at the wrong class.",
        evidence=[f"{_fmt_bytes(analyzed_bytes)} of {_fmt_bytes(file_size)} parsed",
                  "retained sizes, leak suspects and the duplicate scan are all skipped in quick mode"],
        remediation="Re-run without quick mode for the complete picture. For very "
                    "large dumps use the server-side path option so no upload is needed.",
        category="parse",
    )


def _skipped_finding(skipped: List["SkippedAnalysis"], file_size: int) -> Finding:
    return Finding(
        severity=Severity.INFO,
        title=f"{len(skipped)} deeper analysis stage(s) did not run on this dump",
        description=(
            "The histogram, static-field and deployment findings above are complete, "
            "but the stages listed below were gated out — so the absence of a leak "
            "suspect here is not evidence that there isn't one."
        ),
        evidence=[f"{s.stage}: {s.reason}" for s in skipped],
        remediation="; ".join(s.enable_hint for s in skipped if s.enable_hint) or None,
        category="parse",
    )


def _shallow_by_class(
    instance_count: Dict[int, int],
    payload_sum: Dict[int, int],
    scan,
    model: SizeModel,
    id_size: int,
) -> Dict[int, int]:
    """Turn accumulated hprof payload bytes into real JVM shallow sizes.

    `payload_sum[cid]` is the sum of INSTANCE_DUMP field-value lengths. Since every
    instance of a class has the identical layout, dividing by the instance count
    recovers the exact per-instance payload, which the size model then turns into
    an allocated size (header + alignment, references at their live width)."""
    ref_counts = _ref_field_counts(scan)
    out: Dict[int, int] = {}
    for cid, cnt in instance_count.items():
        if cnt <= 0:
            continue
        each = payload_sum.get(cid, 0) // cnt
        out[cid] = cnt * model.instance_size(each, ref_counts.get(cid, 0), id_size)
    return out


def _ref_field_counts(scan) -> Dict[int, int]:
    """Object-typed instance fields per class, including inherited ones — the
    number of slots hprof widened to id_size."""
    if scan is None:
        return {}
    meta = getattr(scan, "class_meta", None)
    fields = getattr(scan, "class_fields", None)
    if not meta or fields is None:
        return {}

    memo: Dict[int, int] = {}

    def count(cid: int) -> int:
        got = memo.get(cid)
        if got is not None:
            return got
        memo[cid] = 0          # guards cyclic/self-referential super chains
        own = sum(1 for _name_id, ftype in fields.get(cid, ()) if ftype == 2)
        sup = meta.get(cid, (0, 0, 0))[0]
        total = own + (count(sup) if sup and sup != cid else 0)
        memo[cid] = total
        return total

    for cid in list(meta):
        count(cid)
    return memo


def _graph_max_bytes() -> int:
    """File-size ceiling for retention tracing. Tracing is memory-bounded but makes
    several streaming passes in Python, so it's time-expensive on big dumps — by
    default it only auto-runs on dumps up to 2GB (the histogram + static-field
    findings still stand on larger ones). Raise HEAP_GRAPH_MAX_BYTES to opt a
    bigger dump in (accepting the extra minutes); set HEAP_GRAPH_TRACE=0 to disable."""
    if os.environ.get("HEAP_GRAPH_TRACE", "1") in ("0", "", "false", "False"):
        return 0
    try:
        return int(os.environ.get("HEAP_GRAPH_MAX_BYTES", str(2 * 1024 * 1024 * 1024)))
    except ValueError:
        return 2 * 1024 * 1024 * 1024


def _waste_max_bytes() -> int:
    """File-size ceiling for the duplicate-array waste scan — a single extra
    streaming pass, memory-bounded. Default 2GB; raise HEAP_WASTE_MAX_BYTES to opt
    a bigger dump in, or set HEAP_WASTE_TRACE=0 to disable entirely."""
    try:
        return int(os.environ.get("HEAP_WASTE_MAX_BYTES", str(2 * 1024 * 1024 * 1024)))
    except ValueError:
        return 2 * 1024 * 1024 * 1024


def _seekable(fp: BinaryIO) -> bool:
    try:
        return fp.seekable()
    except (AttributeError, OSError):
        return False


def _pick_trace_leaf(by_size, by_count) -> Optional[str]:
    """Choose the most actionable class to trace: prefer a user class by size,
    then a leaking collection internal, then the single biggest consumer."""
    for h in by_size[:10]:
        base = h.class_name[:-2] if h.class_name.endswith("[]") else h.class_name
        if is_user_code(base):
            return h.class_name
    for h in by_count[:10]:
        if h.class_name.endswith("$Node") or h.class_name.endswith("$Entry"):
            return h.class_name
    return by_size[0].class_name if by_size else None


def _stream_size(fp: BinaryIO) -> int:
    try:
        cur = fp.tell()
        fp.seek(0, os.SEEK_END)
        size = fp.tell()
        fp.seek(cur, os.SEEK_SET)
        return size
    except (OSError, AttributeError):
        return 0


_PRIM_ARRAY_NAMES = {4: "boolean[]", 5: "char[]", 6: "float[]", 7: "double[]",
                     8: "byte[]", 9: "short[]", 10: "int[]", 11: "long[]"}


def _scan_heap_segment(
    reader: _Reader,
    segment_length: int,
    id_size: int,
    instance_count: Dict[int, int],
    instance_size: Dict[int, int],
    array_count: Dict[int, int],
    array_size: Dict[int, int],
    progress_callback: Optional[callable] = None,
    progress_interval: int = 5000,
    top_level_records: int = 0,
    static_object_fields: Optional[List[Tuple[int, int, int]]] = None,
    scan=None,
    model: Optional[SizeModel] = None,
    max_bytes: Optional[int] = None,
) -> Optional[int]:
    """Walk the sub-records inside a HEAP_DUMP / HEAP_DUMP_SEGMENT body.

    This is THE hot path: a 25GB dump contains hundreds of millions of
    sub-records. We parse from a local buffer with manual offsets and
    precompiled structs instead of per-field reader calls — roughly 5x
    faster, which is the difference between ~4 and ~18 minutes on 25GB.

    Returns None on a complete segment, or the absolute file offset at which it
    stopped when `max_bytes` was reached mid-segment. HotSpot writes the heap as a
    handful of very large HEAP_DUMP_SEGMENT records, so a byte budget that is only
    honoured between top-level records is no budget at all — quick mode has to be
    able to stop inside one.
    """
    if model is None:
        model = size_model(id_size)
    # Hoisted into locals: this loop runs once per object in the dump.
    align = model.alignment
    arr_hdr = model.array_header
    oop = model.oop_size

    CHUNK = 8 * 1024 * 1024
    remaining = segment_length      # segment bytes not yet pulled from reader
    buf = b""
    pos = 0
    inst_total = sum(instance_count.values())
    subs = 0

    if id_size == 8:
        S_INST = struct.Struct(">QIQI"); INST_HEAD = 24
        S_OARR = struct.Struct(">QIIQ"); OARR_HEAD = 24
        S_PARR = struct.Struct(">QIIB"); PARR_HEAD = 17
        S_ID = struct.Struct(">Q")
        S_CLS = struct.Struct(">QIQQQQ")   # class, serial, super, loader, signers, prot-domain
    else:
        S_INST = struct.Struct(">IIII"); INST_HEAD = 16
        S_OARR = struct.Struct(">IIII"); OARR_HEAD = 16
        S_PARR = struct.Struct(">IIIB"); PARR_HEAD = 13
        S_ID = struct.Struct(">I")
        S_CLS = struct.Struct(">IIIIII")
    CLS_HEAD = 7 * id_size + 8

    # Deployment/thread capture (see heap_deployments). `retain_cids` is the set of
    # class ids whose instance bodies we keep — a few dozen classes. HotSpot emits
    # every CLASS_DUMP before the first instance, so the set is complete by the time
    # we need it; `cls_dirty` re-reads it if a dump ever violates that ordering.
    retain_cids: set = set()
    cls_dirty = True

    # Stop accumulating static fields past this many — protects against
    # pathological dumps without changing the diagnosis (we only rank the top few).
    collect_statics = static_object_fields is not None
    STATIC_CAP = 500_000

    def refill(min_need: int) -> None:
        nonlocal buf, pos, remaining
        if remaining <= 0:
            return
        take = CHUNK if CHUNK > min_need else min_need
        if take > remaining:
            take = remaining
        chunk = reader.read(take)
        remaining -= len(chunk)
        buf = buf[pos:] + chunk
        pos = 0

    def ensure(n: int) -> bool:
        if len(buf) - pos < n:
            refill(n - (len(buf) - pos))
        return len(buf) - pos >= n

    def skip_payload(n: int) -> None:
        nonlocal buf, pos, remaining
        avail = len(buf) - pos
        if n <= avail:
            pos += n
            return
        n -= avail
        buf = b""
        pos = 0
        take = n if n <= remaining else remaining
        if take > 0:
            reader.skip(take)
            remaining -= take

    while True:
        if len(buf) - pos < 1:
            if remaining <= 0:
                break
            refill(1)
            if len(buf) - pos < 1:
                break

        subs += 1
        if subs % progress_interval == 0:
            consumed = reader.pos - (len(buf) - pos)
            if progress_callback:
                try:
                    progress_callback(consumed, top_level_records, inst_total)
                except Exception:
                    pass
            if max_bytes and consumed > max_bytes:
                # Abandon the rest of this segment cleanly and tell the caller to
                # stop; the records read so far are complete and self-consistent.
                if remaining > 0:
                    reader.skip(remaining)
                    remaining = 0
                return consumed

        tag = buf[pos]
        pos += 1

        if tag == HEAP_INSTANCE_DUMP:
            if not ensure(INST_HEAD):
                break
            oid, _st, class_id, nbytes = S_INST.unpack_from(buf, pos)
            pos += INST_HEAD
            # Accumulate the raw hprof payload only. Header, alignment, and the
            # reference-width correction need the class's field layout, which
            # isn't resolvable until every CLASS_DUMP has been seen — so the real
            # shallow size is folded in after the pass (see _shallow_by_class).
            instance_count[class_id] += 1
            instance_size[class_id] += nbytes
            inst_total += 1
            if scan is not None:
                if cls_dirty:
                    retain_cids = scan.retain_cids
                    cls_dirty = False
                if class_id in retain_cids and ensure(nbytes):
                    scan.note_instance(oid, class_id, bytes(buf[pos:pos + nbytes]))
                    pos += nbytes
                    continue
            skip_payload(nbytes)

        elif tag == HEAP_PRIMITIVE_ARRAY_DUMP:
            if not ensure(PARR_HEAD):
                break
            _oid, _st, n_elems, etype = S_PARR.unpack_from(buf, pos)
            pos += PARR_HEAD
            tsz = TYPE_SIZES.get(etype, 0)
            key = -etype   # negative synthetic key; resolved to "byte[]" etc. in aggregation
            array_count[key] += 1
            array_size[key] += (arr_hdr + n_elems * tsz + align - 1) // align * align
            skip_payload(n_elems * tsz)

        elif tag == HEAP_OBJECT_ARRAY_DUMP:
            if not ensure(OARR_HEAD):
                break
            _oid, _st, n_elems, elem_class = S_OARR.unpack_from(buf, pos)
            pos += OARR_HEAD
            array_count[elem_class] += 1
            # Elements are `oop` wide in the live heap even though hprof writes
            # them at id_size — size the array as the JVM allocated it.
            array_size[elem_class] += (arr_hdr + n_elems * oop + align - 1) // align * align
            skip_payload(n_elems * id_size)

        elif tag in (HEAP_ROOT_UNKNOWN, HEAP_ROOT_STICKY_CLASS, HEAP_ROOT_MONITOR_USED):
            ensure(id_size); pos += id_size
        elif tag == HEAP_ROOT_JNI_GLOBAL:
            ensure(2 * id_size); pos += 2 * id_size
        elif tag == HEAP_ROOT_THREAD_OBJ:
            # The object id of a *live* thread — what separates a running thread
            # from a dead Thread object still sitting on the heap.
            if ensure(id_size + 8):
                if scan is not None:
                    scan.note_thread_root(S_ID.unpack_from(buf, pos)[0])
            pos += id_size + 8
        elif tag in (HEAP_ROOT_JNI_LOCAL, HEAP_ROOT_JAVA_FRAME):
            ensure(id_size + 8); pos += id_size + 8
        elif tag in (HEAP_ROOT_NATIVE_STACK, HEAP_ROOT_THREAD_BLOCK):
            ensure(id_size + 4); pos += id_size + 4

        elif tag == HEAP_CLASS_DUMP:
            # Rare (one per class); field-by-field is fine here.
            ensure(CLS_HEAD)
            # class_obj_id, stack serial, super, classloader, signers, protection domain.
            # The loader and protection domain are the deployment identity: which WAR
            # loaded this class, and the CodeSource URL it came from.
            class_obj_id_cd, _serial, super_id_cd, loader_id_cd, _signers, pd_id_cd = \
                S_CLS.unpack_from(buf, pos)
            pos += CLS_HEAD
            ensure(2)
            (cp_count,) = struct.unpack_from(">H", buf, pos); pos += 2
            for _ in range(cp_count):
                ensure(3)
                etype = buf[pos + 2]; pos += 3
                vsz = id_size if etype == 2 else TYPE_SIZES.get(etype, 0)
                ensure(vsz); pos += vsz
            ensure(2)
            (n_static,) = struct.unpack_from(">H", buf, pos); pos += 2
            for _ in range(n_static):
                ensure(id_size + 1)
                name_id = S_ID.unpack_from(buf, pos)[0]
                etype = buf[pos + id_size]; pos += id_size + 1
                vsz = id_size if etype == 2 else TYPE_SIZES.get(etype, 0)
                ensure(vsz)
                # type 2 == object reference. A non-null value means this static
                # field is holding a live object — a GC root worth flagging.
                if (etype == 2 and vsz and collect_statics
                        and len(static_object_fields) < STATIC_CAP):
                    val_id = S_ID.unpack_from(buf, pos)[0]
                    if val_id != 0:
                        static_object_fields.append((class_obj_id_cd, name_id, val_id))
                pos += vsz
            ensure(2)
            (n_fields,) = struct.unpack_from(">H", buf, pos); pos += 2
            need = n_fields * (id_size + 1)
            ensure(need)
            if scan is not None:
                fields = []
                fp_ = pos
                for _ in range(n_fields):
                    fields.append((S_ID.unpack_from(buf, fp_)[0], buf[fp_ + id_size]))
                    fp_ += id_size + 1
                scan.note_class(class_obj_id_cd, super_id_cd, loader_id_cd, pd_id_cd, fields)
                cls_dirty = True
            pos += need

        else:
            # Unknown sub-tag — abandon the rest of this segment safely
            pos = len(buf)
            if remaining > 0:
                reader.skip(remaining)
                remaining = 0
            break

    return None


def _skip_class_dump(reader: _Reader, id_size: int) -> None:
    """Skip over a CLASS_DUMP sub-record without parsing its fields."""
    # class_id; u4 stack serial; superclass id; classloader id; signers id;
    # protection domain id; reserved1; reserved2;
    # u4 instance size
    reader.id(id_size); reader.u4()
    for _ in range(6):
        reader.id(id_size)
    reader.u4()  # instance size

    # Constant pool size + entries (u2 idx, u1 type, value)
    cp_size = reader.u2()
    for _ in range(cp_size):
        reader.u2()
        t = reader.u1()
        reader.skip(_type_value_size(t, id_size))

    # Static fields: u2 num, then (name id, type, value) each
    num_static = reader.u2()
    for _ in range(num_static):
        reader.id(id_size)
        t = reader.u1()
        reader.skip(_type_value_size(t, id_size))

    # Instance fields: u2 num, then (name id, type) each
    num_instance = reader.u2()
    for _ in range(num_instance):
        reader.id(id_size)
        reader.u1()


def _type_value_size(t: int, id_size: int) -> int:
    if t == 2:  # object
        return id_size
    return TYPE_SIZES.get(t, 0)


# --- Diagnostic heuristics for heap ---

_LEAK_HINT_CLASSES = (
    "java.util.HashMap$Node",
    "java.util.HashMap$Entry",
    "java.util.LinkedHashMap$Entry",
    "java.util.concurrent.ConcurrentHashMap$Node",
    "java.util.WeakHashMap$Entry",
    "java.lang.ref.Finalizer",
    "java.lang.ref.WeakReference",
    "java.lang.ref.SoftReference",
    "java.lang.ThreadLocal$ThreadLocalMap$Entry",
)

_FRAMEWORK_HINTS = ("org.hibernate", "org.springframework", "io.netty", "org.apache.kafka")



# What common histogram-toppers usually mean. Shown next to entries in the UI
# so non-experts can interpret a histogram without memorizing JVM internals.
CLASS_EXPLANATIONS = {
    "char[]": "Backing storage for Strings (Java 8) and StringBuilders. Tracks String volume — high char[] means lots of text in memory.",
    "byte[]": "Raw buffers: String storage (Java 9+), I/O buffers, serialized blobs, cached file/network content. Often the single biggest class in any heap.",
    "java.lang.String": "Text objects. High counts are normal, but a heap dominated by Strings often hides duplicates or oversized caches of text.",
    "java.lang.Object[]": "Backing arrays of ArrayList/HashMap and friends. Tracks collection volume.",
    "int[]": "Primitive int arrays — common in image/data processing, hash tables, and indexes.",
    "long[]": "Primitive long arrays — IDs, timestamps, bitsets, statistics buffers.",
    "java.util.HashMap$Node": "One per HashMap entry. Millions of these = some map(s) holding millions of entries — find which map and whether it's bounded.",
    "java.util.concurrent.ConcurrentHashMap$Node": "One per ConcurrentHashMap entry. Often a cache — check it has eviction.",
    "java.util.HashMap": "The maps themselves. Many small maps is a different problem (per-request allocation) than one huge map (cache growth).",
    "java.util.ArrayList": "List headers. The data lives in Object[]; many ArrayLists usually mirrors many domain objects.",
    "java.util.LinkedList$Node": "One per LinkedList element — LinkedList carries heavy per-element overhead; consider ArrayList/ArrayDeque.",
    "java.lang.Integer": "Boxed ints. Counts in the millions suggest autoboxing waste in collections — consider primitive collections (fastutil, Eclipse Collections).",
    "java.lang.Long": "Boxed longs. Same boxing-waste story as Integer — often map keys that could be primitives.",
    "java.lang.ThreadLocal$ThreadLocalMap$Entry": "ThreadLocal storage. Accumulation with thread pools = ThreadLocals set but never removed.",
    "java.lang.ref.WeakReference": "Weak refs — common in caches/registries. Huge counts can mean reference-processing pressure.",
    "java.lang.ref.Finalizer": "Objects awaiting finalization. A backlog means the finalizer thread can't keep up — finalizers are slow and deprecated.",
    "java.lang.Class": "Loaded classes. Tens of thousands can indicate classloader leaks (common with hot-redeploy) or heavy proxy generation.",
}


def _explain_class(name: str):
    if name in CLASS_EXPLANATIONS:
        return CLASS_EXPLANATIONS[name]
    if name.endswith("[]") and not name.startswith("java."):
        return None
    return None


# Classes too generic to bother searching the user's source for (every file uses them)
_NO_REF_SEARCH = {
    "java.lang.String", "java.lang.Object", "java.lang.Integer", "java.lang.Long",
    "java.lang.Boolean", "java.lang.Character", "java.lang.Double", "java.lang.Float",
    "java.lang.Short", "java.lang.Byte", "char[]", "byte[]", "int[]", "long[]",
    "boolean[]", "short[]", "float[]", "double[]", "java.lang.Object[]",
    "java.util.HashMap", "java.util.HashMap$Node", "java.util.ArrayList",
    "java.util.LinkedList", "java.util.concurrent.ConcurrentHashMap",
    "java.util.concurrent.ConcurrentHashMap$Node",
}


def _attach_references(source, entries) -> None:
    """For each interesting class entry, find where application code names it."""
    for entry in entries:
        if entry.references:
            continue  # already done (same object can appear in both lists)
        cname = entry.class_name
        if cname in _NO_REF_SEARCH:
            continue
        # Strip array suffix for the search ("Foo[]" -> "Foo")
        search_name = cname[:-2] if cname.endswith("[]") else cname
        try:
            refs = source.find_references(search_name, max_results=8)
        except Exception:
            refs = []
        for r in refs:
            snip = r.get("snippet")
            entry.references.append(ClassReference(
                repo_path=r["repo_path"],
                line=r["line"],
                method=r.get("method"),
                kind=r.get("kind", "type-use"),
                snippet=SourceSnippet(**snip) if snip else None,
            ))


def _is_suspicious(class_name: str, count: int) -> bool:
    if class_name in _LEAK_HINT_CLASSES and count > 10_000:
        return True
    if class_name.endswith("$Entry") and count > 100_000:
        return True
    return False


def _build_heap_findings(
    by_count: List[ClassHistogramEntry],
    by_size: List[ClassHistogramEntry],
    total_instances: int,
    file_size: int,
) -> List[Finding]:
    findings: List[Finding] = []

    if not by_size:
        findings.append(Finding(
            severity=Severity.WARNING,
            title="No heap data found",
            description="The file parsed as a valid .hprof but contained no heap dump segments. This is unusual.",
            category="parse",
        ))
        return findings

    # Top consumer
    top = by_size[0]
    total_size = sum(h.shallow_size_bytes for h in by_size)
    if total_size > 0 and top.shallow_size_bytes / total_size > 0.30:
        findings.append(Finding(
            severity=Severity.WARNING,
            title=f"`{top.class_name}` dominates heap shallow-size ({top.shallow_size_bytes / max(total_size,1):.0%})",
            description=(
                f"{top.instance_count:,} instances totalling roughly {_fmt_bytes(top.shallow_size_bytes)}. "
                "When one class accounts for a large fraction of the heap, it's worth checking "
                "whether instance accumulation is bounded."
            ),
            impact=(
                "If this class keeps growing, the heap eventually fills, GC runs constantly, "
                "and the JVM dies with OutOfMemoryError."
            ),
            likely_cause=(
                "An unbounded cache or collection, a listener/registry that's added to but never removed from, "
                "or large payloads retained longer than needed." 
                + (f" Note: `{top.class_name}` — {_explain_class(top.class_name)}" if _explain_class(top.class_name) else "")
            ),
            evidence=[
                f"{top.instance_count:,} instances",
                f"~{_fmt_bytes(top.shallow_size_bytes)} shallow size ({top.shallow_size_bytes / max(total_size,1):.0%} of measured heap)",
            ],
            remediation=(
                f"Use Eclipse MAT's 'GC roots' query on a `{top.class_name}` instance to find "
                "what's holding it. Look for caches without eviction, growing collections, or "
                "long-lived references (static fields, ThreadLocals)."
            ),
            category="memory",
        ))

    # Excessive HashMap entries (classic leak symptom)
    for entry in by_count[:20]:
        if entry.class_name in _LEAK_HINT_CLASSES and entry.instance_count > 100_000:
            findings.append(Finding(
                severity=Severity.WARNING,
                title=f"{entry.instance_count:,} `{entry.class_name}` instances",
                description=(
                    "Large numbers of HashMap/WeakReference/Finalizer entries can indicate a "
                    "leaking cache, an unbounded map, or excessive finalization pressure."
                ),
                impact="Entry accumulation grows the heap linearly with whatever drives the map until memory runs out.",
                likely_cause="A map used as a cache without eviction, or keyed by something unbounded (session IDs, request IDs, timestamps).",
                evidence=[f"{entry.instance_count:,} × {entry.class_name}"],
                remediation=(
                    "Find the dominator: which map/collection contains all these entries? "
                    "Consider bounded caches (Caffeine), explicit eviction, or weaker references."
                ),
                category="memory",
            ))

    # ThreadLocal leak hint
    tl_entries = next((e for e in by_count
                       if e.class_name == "java.lang.ThreadLocal$ThreadLocalMap$Entry"), None)
    if tl_entries and tl_entries.instance_count > 10_000:
        findings.append(Finding(
            severity=Severity.WARNING,
            title=f"High ThreadLocal entry count ({tl_entries.instance_count:,})",
            description=(
                "ThreadLocalMap$Entry instances accumulate when ThreadLocals are set but "
                "never explicitly removed, especially with reused threads (thread pools, "
                "Tomcat workers)."
            ),
            remediation=(
                "Audit ThreadLocal usage. In long-lived thread pools, call ThreadLocal.remove() "
                "in a finally block after each task. Inspect frameworks (Hibernate, security "
                "contexts) for cleanup hooks."
            ),
            category="memory",
        ))

    # Excessive String count
    str_entry = next((e for e in by_count if e.class_name == "java.lang.String"), None)
    char_arr = next((e for e in by_count if e.class_name == "char[]"), None)
    byte_arr = next((e for e in by_count if e.class_name == "byte[]"), None)
    if str_entry and total_instances > 0 and str_entry.instance_count / total_instances > 0.30:
        findings.append(Finding(
            severity=Severity.INFO,
            title=f"Strings make up {str_entry.instance_count / total_instances:.0%} of all instances",
            description=(
                f"{str_entry.instance_count:,} String instances. High string counts often hide "
                "duplicate strings. If true, String.intern() or de-duplication can reclaim memory."
            ),
            remediation=(
                "Run Eclipse MAT's 'Group by value' on java.lang.String to find duplicates. "
                "JVM option -XX:+UseStringDeduplication (with G1) can also help."
            ),
            category="memory",
        ))

    # Autoboxing waste
    for boxed in ("java.lang.Integer", "java.lang.Long"):
        be = next((e for e in by_count if e.class_name == boxed), None)
        if be and be.instance_count > 1_000_000:
            findings.append(Finding(
                severity=Severity.INFO,
                title=f"{be.instance_count:,} boxed `{boxed}` instances",
                description=(
                    f"Each {boxed} wraps a primitive in a 16-byte object. At this volume, boxing alone "
                    f"costs roughly {_fmt_bytes(be.instance_count * 16)} plus GC pressure."
                ),
                impact="Wasted memory and extra GC work compared to primitive storage.",
                likely_cause="Collections of boxed numbers — Map<Long, X>, List<Integer> — usually via autoboxing in hot paths.",
                evidence=[f"{be.instance_count:,} instances ≈ {_fmt_bytes(be.shallow_size_bytes)}"],
                remediation="Where the volume lives in one place, switch to primitive collections (fastutil, Eclipse Collections, HPPC) or arrays.",
                category="memory",
            ))

    if not findings:
        findings.append(Finding(
            severity=Severity.INFO,
            title="No obvious red flags",
            description=(
                f"Heap dump of {_fmt_bytes(file_size)} parsed successfully. "
                f"{total_instances:,} object instances across {len(by_count)} classes. "
                "No classic leak signatures detected from shallow-size analysis."
            ),
            category="general",
        ))

    return findings


# Histogram-topping classes that signal the heap is full of growable containers
# (map/collection backbones). Their presence strengthens a static-field suspicion.
_CONTAINER_INDICATORS = {
    "java.util.HashMap$Node", "java.util.HashMap$Entry",
    "java.util.LinkedHashMap$Entry", "java.util.Hashtable$Entry",
    "java.util.concurrent.ConcurrentHashMap$Node", "java.lang.Object[]",
    "java.util.TreeMap$Entry",
}

# Static field names that are almost never the leak — loggers, synthetic fields.
_BORING_STATIC_FIELDS = {"LOG", "LOGGER", "log", "logger", "TAG", "$VALUES",
                         "$assertionsDisabled", "serialVersionUID"}


def _heap_looks_container_dominated(
    by_count: List[ClassHistogramEntry],
    by_size: List[ClassHistogramEntry],
) -> bool:
    """True when map/collection internals top the histogram — i.e. the heap is
    full of entries, which is exactly what an unbounded static collection produces."""
    for e in by_count[:8] + by_size[:8]:
        n = e.class_name
        if n in _CONTAINER_INDICATORS or n.endswith("$Node") or n.endswith("$Entry"):
            return True
    return False


def _build_static_field_findings(
    static_object_fields: List[Tuple[int, int, int]],
    class_obj_to_name_id: Dict[int, int],
    strings: Dict[int, str],
    source,
    by_count: List[ClassHistogramEntry],
    by_size: List[ClassHistogramEntry],
) -> List[Finding]:
    """Turn static GC-root object fields of user code into a source-pinpointed finding.

    Heap dumps have no stack traces, so we can't see *who* allocated an object.
    But static fields are GC roots that are never released — the classic
    "someone left a cache/registry unbounded" leak — and we *can* tie them to an
    exact line of the user's source. Strategy:

      * With source attached: resolve each static field's declared type. Only
        raise a real warning for collection/cache-typed fields (the true leak
        shape), so we don't flag every `static final Logger`.
      * Without source: stay quiet unless the histogram already looks
        container-dominated, then emit a gentle INFO nudge to attach source.
    """
    if not static_object_fields:
        return []

    # Resolve + dedupe to distinct user-code (class, field) pairs.
    seen = set()
    suspects: List[dict] = []
    for class_obj_id, name_id, _val_id in static_object_fields:
        cls_name_id = class_obj_to_name_id.get(class_obj_id)
        cname = _normalize_class_name(strings.get(cls_name_id, "")) if cls_name_id else ""
        fname = strings.get(name_id, "")
        if not cname or not fname or not is_user_code(cname):
            continue
        if fname.startswith("$") or fname in _BORING_STATIC_FIELDS:
            continue
        key = (cname, fname)
        if key in seen:
            continue
        seen.add(key)
        suspects.append({"class_name": cname, "field_name": fname})

    if not suspects:
        return []

    container_dominated = _heap_looks_container_dominated(by_count, by_size)

    # --- No source attached: at most a gentle nudge, only if the heap looks leaky.
    if source is None:
        if not container_dominated:
            return []
        shown = suspects[:8]
        return [Finding(
            severity=Severity.INFO,
            title=f"{len(suspects)} static field(s) in your code hold live objects",
            description=(
                "The heap is dominated by collection internals, and your application "
                "code has static fields holding live objects. Static fields are GC "
                "roots — they're never garbage-collected — so an unbounded static "
                "collection is the most common cause of this shape. Attach your source "
                "repo to resolve these to exact lines and see which are collections."
            ),
            impact="If one of these is a collection that only grows, the heap fills until the JVM dies with OutOfMemoryError.",
            likely_cause="A static Map/List/Set/cache used as a registry that's added to but never evicted from.",
            evidence=[f"static {s['class_name']}.{s['field_name']}" for s in shown],
            remediation="Re-run with a source repo attached (zip, server path, or git URL) to pinpoint the declarations and their declared types.",
            category="memory",
        )]

    # --- Source attached: resolve declared types; collection-typed are the leads.
    for s in suspects:
        s["info"] = source.find_static_field(s["class_name"], s["field_name"])
        s["is_collection"] = bool(s["info"] and s["info"].get("is_collection"))

    collection_suspects = [s for s in suspects if s["is_collection"]]
    if not collection_suspects:
        # No static collection smoking gun — leave it to histogram findings
        # (and, later, Phase-2 reference tracing). Avoid crying wolf.
        return []

    collection_suspects.sort(key=lambda s: s["info"] is None)
    shown = collection_suspects[:8]

    locations: List[SourceLocation] = []
    for s in shown:
        info = s["info"]
        loc = SourceLocation(
            class_name=s["class_name"],
            method=s["field_name"],   # `method` slot carries the field name for display
            is_user_code=True,
        )
        if info:
            loc.line = info["line"]
            loc.repo_path = info["repo_path"]
            loc.snippet = info["snippet"]
        locations.append(loc)

    lead = shown[0]
    sev = Severity.WARNING
    evidence = [f"static {s['class_name']}.{s['field_name']} — {s['info']['type_hint']}"
                for s in shown if s.get("info")]
    if container_dominated:
        top = (by_count[:1] or by_size[:1])
        if top:
            evidence.append(
                f"heap is dominated by container internals (e.g. {top[0].class_name}, "
                f"{top[0].instance_count:,} instances)"
            )

    title = (
        f"Static collection `{lead['class_name'].rsplit('.', 1)[-1]}.{lead['field_name']}` "
        "is a likely leak root"
        if len(shown) == 1 else
        f"{len(shown)} static collection fields are likely leak roots"
    )

    return [Finding(
        severity=sev,
        title=title,
        description=(
            f"Your code declares {len(shown)} `static` collection field"
            f"{'s' if len(shown) > 1 else ''} that currently hold live objects. "
            "Static fields are GC roots — the objects they reference are never "
            "collected for the life of the process. When such a collection is only "
            "ever added to, it grows without bound until the heap is exhausted. "
            + ("The histogram confirms the heap is full of collection entries, "
               "which is exactly this pattern. " if container_dominated else "")
            + "The source location(s) below point to the exact declaration to review."
        ),
        impact=(
            "An unbounded static collection grows forever: the heap fills, GC runs "
            "more and more often for less and less benefit, response times climb, and "
            "the JVM eventually dies with OutOfMemoryError."
        ),
        likely_cause=(
            f"`{lead['class_name']}.{lead['field_name']}` (and similar) used as an "
            "in-memory cache or registry that is added to but never evicted from — "
            "often keyed by something unbounded like session IDs, request IDs, or timestamps."
        ),
        evidence=evidence,
        remediation=(
            "Open each declaration below and check whether the collection is bounded. "
            "Fixes, in order of preference: (1) use a size- or time-bounded cache such "
            "as Caffeine or Guava `CacheBuilder` with `maximumSize`/`expireAfterWrite`; "
            "(2) evict entries explicitly when you're done with them; (3) if it's a "
            "true registry, make sure every add has a matching remove. Avoid plain "
            "`static HashMap`/`ArrayList` as a cache."
        ),
        category="memory",
        source_locations=locations,
    )]


def _build_heap_summary(
    by_size: List[ClassHistogramEntry],
    total_instances: int,
    file_size: int,
    findings: List[Finding],
    truncated: bool = False,
    analyzed_bytes: int = 0,
) -> str:
    if truncated:
        parts = [
            f"PARTIAL: {_fmt_bytes(analyzed_bytes)} of a {_fmt_bytes(file_size)} heap dump "
            f"was sampled (quick mode), containing {total_instances:,} object instances."
        ]
    else:
        parts = [
            f"Heap dump of {_fmt_bytes(file_size)} containing roughly {total_instances:,} object instances."
        ]
    if by_size:
        top = by_size[0]
        parts.append(
            f"Largest single class by shallow size is `{top.class_name}` "
            f"({top.instance_count:,} instances, ≈{_fmt_bytes(top.shallow_size_bytes)})."
        )
    crit = sum(1 for f in findings if f.severity == Severity.CRITICAL)
    warn = sum(1 for f in findings if f.severity == Severity.WARNING)
    if crit:
        parts.append(f"{crit} critical finding(s) flagged.")
    elif warn:
        parts.append(f"{warn} warning(s) worth investigating.")
    else:
        parts.append("No obvious leak signatures from the histogram.")
    return " ".join(parts)


def _fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:.1f} PB"
