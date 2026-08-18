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


def _heap_classes_of_interest(heap: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Map outer user-class FQCN -> heap evidence, drawn from the histogram and
    from Phase-1 static leak suspects embedded in heap findings."""
    interest: Dict[str, Dict[str, Any]] = {}

    def consider(entry: Dict[str, Any]):
        raw = entry.get("class_name") or ""
        outer = _outer_class(raw)
        if not outer or not is_user_code(outer):
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
            if not outer or not is_user_code(outer):
                continue
            interest.setdefault(outer, {
                "class_name": outer, "instance_count": 0,
                "shallow_size_bytes": 0, "pct_of_total_size": None,
                "is_static_suspect": False,
            })
            interest[outer]["is_static_suspect"] = True

    return interest


def _index_thread_frames(thread: Dict[str, Any]) -> Dict[str, List[Tuple[str, Dict[str, Any]]]]:
    """outer user-class -> list of (thread_name, frame) where that class executes."""
    hits: Dict[str, List[Tuple[str, Dict[str, Any]]]] = {}
    for t in thread.get("threads") or []:
        tname = t.get("name") or "?"
        for fr in t.get("stack") or []:
            cn = fr.get("class_name")
            if not cn:
                continue
            outer = _outer_class(cn)
            if not is_user_code(outer):
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
            if not cn or not is_user_code(_outer_class(cn)):
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
    heap_interest = _heap_classes_of_interest(heap)
    frame_hits = _index_thread_frames(thread)
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
            hits = _allocator_hits(simple, source, thread)
            kind = "allocating"
        if not hits:
            continue

        matched.append(outer)
        if len(matched) > 8:
            break

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
        severity = Severity.CRITICAL if dominant else Severity.WARNING

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
            title=f"`{simple}` fills the heap and is live on {len(thread_names)} thread(s)",
            description=(
                f"`{outer}` shows up in two independent places: it {suspect_phrase}"
                f"accounts for {heap_desc} in the heap dump, and {len(thread_names)} "
                f"thread(s) are currently {rel_phrase}. Two signals pointing at the same "
                "class is a strong indication this is where the problem lives — and the "
                "thread frame gives you an exact line to open."
            ),
            impact=(
                "Memory is being consumed by this class while it is actively on the hot "
                "path. If it keeps growing, you get rising GC pressure and eventually "
                "OutOfMemoryError; if the live threads are blocked here, you also get "
                "latency or stalls."
            ),
            likely_cause=(
                f"The code at {frame_ref} is creating or holding `{simple}` instances "
                "faster than they're released — an unbounded accumulation, a missing "
                "limit/pagination, or a cache without eviction."
            ),
            evidence=evidence,
            remediation=(
                f"Open {frame_ref} (shown below) and check how `{simple}` is produced or "
                "retained on this path. Bound the work (paginate, stream, or cap batch "
                "size), release references when done, or add cache eviction. Because both "
                "dumps agree, fixing this single spot should move the needle."
            ),
            category="correlation",
            source_locations=[loc],
        ))

    # Three-pillar marriage: a real GC log proves whether the heap snapshot's
    # dominant class is part of a genuine upward trend (a leak) vs a big-but-stable
    # working set. This is the signal a single heap dump structurally cannot give.
    if gc:
        trend = gc.get("heap_after_trend_mb_per_min") or 0.0
        gc_verdict = gc.get("verdict")
        top = (heap.get("top_classes_by_size") or [None])[0]
        leak_trend = trend > 1.0 and gc_verdict in ("critical", "degraded")
        if leak_trend and top:
            top_name = _simple(top.get("class_name") or "the top class")
            who = f"`{top_name}`"   # the class actually filling the heap
            evidence = [
                f"gc: post-GC live set rising +{trend:.1f} MB/min (verdict {gc_verdict})",
                f"gc: throughput {gc.get('throughput_pct')}%, {gc.get('full_gc_count')} Full GC(s)",
                f"heap: dominant class `{top.get('class_name')}` "
                f"(≈{_fmt_bytes(top.get('shallow_size_bytes', 0))})",
            ]
            if matched:
                evidence.append(f"thread: `{_simple(matched[0])}` live on a stack with a source line")
            findings.insert(0, Finding(
                severity=Severity.CRITICAL,
                title=f"Confirmed memory leak: heap, GC trend, and threads all point at {who}",
                description=(
                    "Three independent signals agree. The GC log shows the live set climbing "
                    f"~{trend:.1f} MB/min after every collection (so the heap is genuinely "
                    f"trending toward OutOfMemoryError, not just momentarily large); the heap "
                    f"dump shows `{top.get('class_name')}` dominating that memory" +
                    (f"; and a thread is live in the code that produces/holds {who}, giving "
                     "you an exact line to open." if matched else ".")
                ),
                impact=(
                    "Left alone this ends in OutOfMemoryError. As the heap fills, GC runs more "
                    "often for less, throughput drops, and latency spikes — then the JVM dies."
                ),
                likely_cause=(
                    f"{who} is accumulating without bound — a cache/registry/collection that's "
                    "added to but never evicted or cleared."
                ),
                evidence=evidence,
                remediation=(
                    "This is the one to fix first: all three artifacts agree. Bound or evict "
                    "the structure holding these instances; if the live set is legitimately "
                    "this large and growing, the app needs more than -Xmx can give it."
                ),
                category="correlation",
                source_locations=findings[0].source_locations if (matched and findings) else [],
            ))

    # Bonus: GC CPU pressure (thread dump) confirming heap fill (heap dump).
    gc_findings = [f for f in (thread.get("findings") or []) if f.get("category") == "gc"]
    if not gc and gc_findings and (heap.get("verdict") in ("critical", "degraded")):
        top = (heap.get("top_classes_by_size") or [None])[0]
        top_txt = (f" The heap is led by `{top['class_name']}` "
                   f"(≈{_fmt_bytes(top.get('shallow_size_bytes', 0))})." if top else "")
        findings.append(Finding(
            severity=Severity.WARNING,
            title="GC CPU pressure in the thread dump matches a filling heap",
            description=(
                "The thread dump shows garbage-collection threads burning significant "
                "CPU, and the heap dump independently looks unhealthy. Together these "
                "confirm real memory pressure rather than a transient blip." + top_txt
            ),
            impact="Application threads are repeatedly paused for GC; latency gets spiky and throughput drops as the heap approaches its limit.",
            likely_cause="The live set is growing toward -Xmx (often a leak), so GC runs more and more often for less and less reclaimed memory.",
            evidence=[f"thread: {f.get('title')}" for f in gc_findings[:3]]
                     + [f"heap verdict: {heap.get('verdict')}"],
            remediation="Treat the top heap consumers above as the priority. Confirm with GC logs (-Xlog:gc*); if the live set is legitimately large, raise -Xmx, otherwise fix the accumulation.",
            category="correlation",
        ))

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

    return {
        "findings": [f.model_dump() for f in findings],
        "summary": summary,
        "matched_classes": len(matched),
    }
