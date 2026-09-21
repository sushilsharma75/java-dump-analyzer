"""
Cross-dump correlation: thread dump  ×  heap dump  ×  source.

Heap dumps tell you *what* is filling memory but carry no stack traces, so on
their own they can't say *where* in your code the problem lives. Thread dumps
are the opposite: they have line-precise stack traces but no view of the heap.

This module intersects the two. A user-code class that simultaneously
  (a) dominates the heap histogram (or is a Phase-1 static leak suspect), and
  (b) appears on a live thread's stack at the moment of capture
is a double-confirmed pinpoint: two independent signals agreeing on the same
class, and — because the thread frame has a line number — a real `file:line`
the user can open. When a source repo is attached we resolve that frame to an
actual code snippet.

Inputs are the already-serialized analysis dicts (the same JSON the UI holds),
so this stays stateless and reuses the existing analyzers' output.
"""
from __future__ import annotations
from typing import Dict, List, Optional, Any, Tuple

from ..schemas import Finding, Severity, SourceLocation
from .source import SourceIndex, is_user_code
from .evidence import compatibility, stamp


def _outer_class(name: str) -> str:
    """Normalize a class name to the outer type: strip array suffix and inner/$ parts."""
    if not name:
        return ""
    while name.endswith("[]"):
        name = name[:-2]
    return name.split("$", 1)[0]


def _simple(name: str) -> str:
    return name.rsplit(".", 1)[-1] if name else name


def _fmt_bytes(n: int) -> str:
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:.1f} PB"


def _heap_classes_of_interest(heap: Dict[str, Any], source=None) -> Dict[str, Dict[str, Any]]:
    """Map outer user-class FQCN -> heap evidence, drawn from the histogram and
    from Phase-1 static leak suspects embedded in heap findings."""
    interest: Dict[str, Dict[str, Any]] = {}

    def consider(entry: Dict[str, Any]):
        raw = entry.get("class_name") or ""
        outer = _outer_class(raw)
        if not outer or not (is_user_code(outer) or (source and source.lookup(outer))):
            return
        prev = interest.get(outer)
        cand = {
            "class_name": outer,
            "instance_count": entry.get("instance_count", 0) or 0,
            "shallow_size_bytes": entry.get("shallow_size_bytes", 0) or 0,
            "pct_of_total_size": entry.get("pct_of_total_size"),
            "is_static_suspect": False,
        }
        if prev is None or cand["instance_count"] > prev["instance_count"]:
            # keep static-suspect flag sticky across merges
            if prev:
                cand["is_static_suspect"] = prev["is_static_suspect"]
            interest[outer] = cand

    for entry in (heap.get("top_classes_by_size") or [])[:30]:
        consider(entry)
    for entry in (heap.get("top_classes_by_count") or [])[:30]:
        consider(entry)

    # Phase-1 static leak suspects: heap findings carry source_locations whose
    # class_name is a user static-field holder. Mark those as high-interest.
    for f in heap.get("findings") or []:
        if f.get("category") != "memory":
            continue
        for loc in f.get("source_locations") or []:
            if not loc.get("is_user_code"):
                continue
            outer = _outer_class(loc.get("class_name") or "")
            if not outer or not (is_user_code(outer) or (source and source.lookup(outer))):
                continue
            interest.setdefault(outer, {
                "class_name": outer, "instance_count": 0,
                "shallow_size_bytes": 0, "pct_of_total_size": None,
                "is_static_suspect": False,
            })
            interest[outer]["is_static_suspect"] = True

    return interest


def _index_thread_frames(thread: Dict[str, Any], source=None) -> Dict[str, List[Tuple[str, Dict[str, Any]]]]:
    """outer user-class -> list of (thread_name, frame) where that class executes."""
    hits: Dict[str, List[Tuple[str, Dict[str, Any]]]] = {}
    for t in thread.get("threads") or []:
        tname = t.get("name") or "?"
        for fr in t.get("stack") or []:
            cn = fr.get("class_name")
            if not cn:
                continue
            outer = _outer_class(cn)
            if not (is_user_code(outer) or (source and source.lookup(outer))):
                continue
            hits.setdefault(outer, []).append((tname, fr))
    return hits


def _best_frame(hits: List[Tuple[str, Dict[str, Any]]]) -> Tuple[str, Dict[str, Any]]:
    """Prefer a frame that carries a line number (resolvable to source)."""
    for tname, fr in hits:
        if fr.get("line"):
            return tname, fr
    return hits[0]


def _allocator_hits(
    simple_name: str,
    source: SourceIndex,
    thread: Dict[str, Any],
) -> List[Tuple[str, Dict[str, Any]]]:
    """Find live thread frames whose code *constructs or holds* `simple_name`.

    The class filling the heap (e.g. `Order`) is usually created by a *different*
    class (e.g. `OrderService`), so matching only on the frame's own class misses
    the common case. With source attached we can bridge it: find every file/method
    that references the heap class, then see if any thread is currently executing
    in one of those methods. That ties the *allocator* to a live stack — with a
    real line number from the thread frame.
    """
    try:
        refs = source.find_references(simple_name, max_results=30)
    except Exception:
        refs = []
    if not refs:
        return []
    methods_by_file: Dict[str, set] = {}
    files: set = set()
    for r in refs:
        rp = r.get("repo_path")
        if not rp:
            continue
        files.add(rp)
        if r.get("method"):
            methods_by_file.setdefault(rp, set()).add(r["method"])

    out: List[Tuple[str, Dict[str, Any]]] = []
    for t in thread.get("threads") or []:
        for fr in t.get("stack") or []:
            cn = fr.get("class_name")
            if not cn or not (source.lookup(cn) or is_user_code(_outer_class(cn))):
                continue
            resolved = source.lookup(cn)
            if not resolved:
                continue
            rp = source.relative_path(resolved[0])
            if rp not in files:
                continue
            methods = methods_by_file.get(rp)
            # Same file is a hit; if we know the referencing methods, require the
            # frame's method to be one of them (tighter, fewer false positives).
            if not methods or fr.get("method") in methods:
                out.append((t.get("name") or "?", fr))
    return out


def correlate(
    heap: Dict[str, Any],
    thread: Dict[str, Any],
    source: Optional[SourceIndex] = None,
    gc: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Return {findings, summary, matched_classes} cross-referencing the dumps.

    `gc` is an optional serialized GCLogAnalysis. When present, its over-time
    signal (is the post-GC live set actually growing?) is married to the heap
    snapshot's dominant class — turning a "this class is big right now" snapshot
    into a "this class is big AND the heap is trending toward OOM" diagnosis.
    """
    compatible, limitations = compatibility(heap, thread)
    if not compatible:
        return {"findings": [Finding(severity=Severity.WARNING, category="coverage",
                title="Captures cannot be correlated", description=" ".join(limitations)).model_dump()],
                "summary": "Incompatible or partial captures.", "matched_classes": 0}
    heap_interest = _heap_classes_of_interest(heap, source)
    frame_hits = _index_thread_frames(thread, source)
    total_threads = thread.get("total_threads") or len(thread.get("threads") or [])

    findings: List[Finding] = []
    matched: List[str] = []

    # Rank candidates: static suspects first, then by heap instance count.
    ordered = sorted(
        heap_interest.values(),
        key=lambda e: (not e["is_static_suspect"], -(e["instance_count"] or 0)),
    )

    ref_scans = 0   # budget the expensive whole-repo reference scans
    for entry in ordered:
        outer = entry["class_name"]
        simple = _simple(outer)

        # (a) a thread executing *inside* the heap class itself, or
        # (b) — with source — a thread in code that constructs/holds it.
        hits = frame_hits.get(outer)
        kind = "executing"
        if not hits and source is not None and ref_scans < 6:
            ref_scans += 1
            hits = _allocator_hits(outer, source, thread)
            kind = "allocating"
        if not hits:
            continue

        if len(matched) >= 8:
            break
        matched.append(outer)

        tname, fr = _best_frame(hits)
        thread_names = sorted({h[0] for h in hits})

        loc = SourceLocation(
            class_name=fr.get("class_name") or outer,
            method=fr.get("method") or "",
            file=fr.get("file"),
            line=fr.get("line"),
            is_user_code=True,
        )
        if source and fr.get("line"):
            resolved = source.lookup(fr.get("class_name") or outer, fr.get("line"))
            if resolved:
                abs_path, snippet = resolved
                loc.repo_path = source.relative_path(abs_path)
                loc.snippet = snippet

        pct = entry.get("pct_of_total_size")
        dominant = (pct is not None and pct >= 20) or entry["is_static_suspect"]
        severity = Severity.WARNING

        frame_ref = f"{loc.class_name}.{loc.method}" + (f":{loc.line}" if loc.line else "")

        heap_bits = []
        if entry["instance_count"]:
            heap_bits.append(f"{entry['instance_count']:,} instances")
        if entry["shallow_size_bytes"]:
            heap_bits.append(f"≈{_fmt_bytes(entry['shallow_size_bytes'])}")
        if pct is not None:
            heap_bits.append(f"{pct}% of measured heap")
        heap_desc = ", ".join(heap_bits) if heap_bits else "present in the heap"

        if kind == "executing":
            rel_phrase = f"executing its code at {frame_ref}"
            thread_evidence = f"thread: executing in {frame_ref} on {len(thread_names)} thread(s)"
        else:
            rel_phrase = f"in code that constructs/holds `{simple}` at {frame_ref}"
            thread_evidence = f"thread: constructs/holds `{simple}` in {frame_ref} on {len(thread_names)} thread(s)"

        evidence = []
        if entry["is_static_suspect"]:
            evidence.append(f"heap: `{outer}` flagged as a static leak suspect")
        if heap_bits:
            evidence.append(f"heap: {heap_desc}")
        evidence.append(thread_evidence)
        evidence += [f"thread: {n}" for n in thread_names[:5]]

        suspect_phrase = "is a static leak suspect and " if entry["is_static_suspect"] else ""
        findings.append(Finding(
            severity=severity,
            title=f"`{simple}` heap presence overlaps {len(thread_names)} thread stack(s)",
            description=(
                f"`{outer}` shows up in two independent places: it {suspect_phrase}"
                f"accounts for {heap_desc} in the heap dump, and {len(thread_names)} "
                f"thread(s) are currently {rel_phrase}. This is a candidate relationship, not proof of allocation or retention at that line."
            ),
            impact=(
                "Memory is being consumed by this class while it is actively on the hot "
                "path. If it keeps growing, you get rising GC pressure and eventually "
                "OutOfMemoryError; if the live threads are blocked here, you also get "
                "latency or stalls."
            ),
            likely_cause=(
                f"Inspect {frame_ref} as a candidate. Workload growth, bounded caching, and unintended retention remain alternative explanations."
            ),
            evidence=evidence,
            remediation=(
                f"Open {frame_ref} (shown below) and check how `{simple}` is produced or "
                "retained on this path. Bound the work (paginate, stream, or cap batch "
                "size), release references when done, or add cache eviction. Because both "
                "dumps provide context, verify a GC-root path before attributing retained objects to this line."
            ),
            category="correlation",
            source_locations=[loc],
        ))

    # A global occupancy trend cannot identify a particular leaking class.
    gc_compatible, gc_limits = compatibility(heap, gc) if gc else (True, [])
    if gc and not gc_compatible:
        findings.append(Finding(severity=Severity.WARNING, category="coverage", title="GC log cannot be correlated", description=" ".join(gc_limits)))
    if gc and gc_compatible and (gc.get("heap_after_trend_mb_per_min") or 0) > 1:
        findings.append(Finding(severity=Severity.WARNING, category="correlation",
            title="GC occupancy trend adds memory-pressure context",
            description="Post-collection occupancy rises in the supplied GC log. This does not prove a leak or identify the class causing growth.",
            evidence=[f"post-GC trend: {gc['heap_after_trend_mb_per_min']} MB/min"],
            limitations=["GC capture identity and window must match the incident; young/mixed collections do not establish a full live-set baseline."],
            remediation="Compare complete heap histograms and retained ownership across compatible captures and a representative GC window."))
    elif not gc and any(f.get("category") == "gc" for f in thread.get("findings", [])):
        findings.append(Finding(severity=Severity.INFO, category="correlation", title="GC CPU observation needs a GC log",
                                description="Lifetime GC CPU and a heap snapshot do not establish current leak growth."))

    if not findings:
        findings.append(Finding(
            severity=Severity.INFO,
            title="No direct overlap between the two dumps",
            description=(
                "None of the heap-dominant application classes appear on a live thread "
                "stack in this thread dump. That's common: the threads that *created* the "
                "retained objects may be idle or gone by the time the dumps were taken. "
                "The heap and thread findings above each still stand on their own."
            ),
            impact=None,
            likely_cause="The allocation happened earlier, or the holder is a static/framework structure with no thread currently inside it.",
            remediation=(
                "For a tighter correlation, capture the thread dump and heap dump within a "
                "few seconds of each other during the incident. The Phase-1 static-field "
                "suspects (heap view) remain the best source-level lead."
            ),
            category="correlation",
        ))

    summary = (
        f"Cross-referenced {len(heap_interest)} heap-dominant application class(es) "
        f"against {total_threads} thread(s): {len(matched)} appear on live stacks"
        + (f" — start with `{_simple(matched[0])}`." if matched else ".")
    )

    for f in findings:
        f.limitations.extend(limitations)
        for loc in f.source_locations:
            loc.role = "executing_frame"
            loc.resolution = "lexical_symbol" if loc.repo_path else "unresolved"
    stamp(findings)
    return {
        "findings": [f.model_dump() for f in findings],
        "summary": summary,
        "matched_classes": len(matched),
    }
