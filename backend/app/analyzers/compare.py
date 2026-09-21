"""Compatible-capture histogram deltas and full-stack persistence observations.

Growth is not proof of a leak; recurring stacks do not prove a lack of progress.
Missing partial-histogram entries remain unknown rather than being treated as zero.
"""
from __future__ import annotations
from typing import Dict, List, Optional, Any, Tuple

from ..schemas import (
    Finding, Severity, SourceLocation,
    ClassDelta, HeapComparison, StuckThread, ThreadComparison,
)
from .source import SourceIndex, is_user_code
from .evidence import compatibility, stamp


def _outer(name: str) -> str:
    if not name:
        return ""
    while name.endswith("[]"):
        name = name[:-2]
    return name.split("$", 1)[0]


def _simple(name: str) -> str:
    return name.rsplit(".", 1)[-1] if name else name


def _fmt_bytes(n: float) -> str:
    n = float(n or 0)
    sign = "-" if n < 0 else ""
    n = abs(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{sign}{n:.1f} {unit}" if unit != "B" else f"{sign}{int(n)} B"
        n /= 1024
    return f"{sign}{n:.1f} PB"


def _class_index(heap: Dict[str, Any]) -> Dict[str, Tuple[int, int]]:
    """class_name -> (instance_count, shallow_size_bytes), unioned from both
    histograms the analysis retained (top-by-count and top-by-size)."""
    out: Dict[str, Tuple[int, int]] = {}
    for key in (("histogram",) if heap.get("histogram_complete") else ("top_classes_by_size", "top_classes_by_count")):
        for e in heap.get(key) or []:
            name = e.get("class_name")
            if not name:
                continue
            cnt = e.get("instance_count", 0) or 0
            sz = e.get("shallow_size_bytes", 0) or 0
            prev = out.get(name)
            # keep the larger reading if the class shows up in both lists
            if prev is None or sz > prev[1] or cnt > prev[0]:
                out[name] = (max(cnt, prev[0]) if prev else cnt,
                             max(sz, prev[1]) if prev else sz)
    return out


def _resolve_grower(simple_name: str, source: Optional[SourceIndex]) -> Optional[SourceLocation]:
    """Point a growing user class at where the code constructs/holds it."""
    if source is None:
        return None
    try:
        refs = source.find_references(simple_name, max_results=10)
    except Exception:
        refs = []
    # Prefer a constructor site; fall back to any reference.
    ref = next((r for r in refs if r.get("kind") == "new"), None) or (refs[0] if refs else None)
    if not ref or not ref.get("repo_path"):
        return None
    return SourceLocation(
        class_name=simple_name, method=ref.get("method") or "",
        line=ref.get("line"), is_user_code=True,
        repo_path=ref.get("repo_path"), snippet=ref.get("snippet"),
    )


def compare_heaps(
    before: Dict[str, Any],
    after: Dict[str, Any],
    source: Optional[SourceIndex] = None,
) -> Dict[str, Any]:
    """Diff two heap analyses → growers, new classes, and leak-suspect findings."""
    bi = _class_index(before)
    ai = _class_index(after)

    compatible, limitations = compatibility(before, after, ordered=True)
    complete = bool(before.get("histogram_complete") and after.get("histogram_complete"))
    if not complete:
        limitations.append("Only classes present in both partial histograms can be compared; missing entries are unknown, not zero.")
    names = (set(bi) | set(ai)) if complete else (set(bi) & set(ai))
    if not compatible:
        names = set()
    deltas: List[ClassDelta] = []
    for name in names:
        bc, bsz = bi.get(name, (0, 0))
        ac, asz = ai.get(name, (0, 0))
        deltas.append(ClassDelta(
            class_name=name, count_before=bc, count_after=ac, count_delta=ac - bc,
            bytes_before=bsz, bytes_after=asz, bytes_delta=asz - bsz,
            is_new=(name not in bi and name in ai),
        ))

    growers = sorted([d for d in deltas if d.bytes_delta > 0],
                     key=lambda d: d.bytes_delta, reverse=True)
    new_classes = sorted([d for d in deltas if d.is_new and d.bytes_after > 0],
                         key=lambda d: d.bytes_after, reverse=True)
    total_before = sum(bi.get(n, (0, 0))[1] for n in names)
    total_after = sum(ai.get(n, (0, 0))[1] for n in names)
    growth = total_after - total_before

    findings = _heap_delta_findings(growers, new_classes, growth, total_before, source)
    if not compatible or (not complete and not names):
        findings = [Finding(severity=Severity.WARNING, category="coverage", title="No valid comparison established",
                            description=" ".join(limitations), limitations=limitations)]
    stamp(findings)
    verdict = _verdict(findings) if compatible and complete else "insufficient_evidence"
    summary = (
        f"Tracked {len(deltas)} class(es) across the two heaps: net "
        f"{_fmt_bytes(growth)} change"
        + (f", led by `{_simple(growers[0].class_name)}` (+{_fmt_bytes(growers[0].bytes_delta)})."
           if growers else " — nothing grew materially.")
    )
    if not compatible:
        summary = "Comparison unavailable: " + " ".join(limitations)
    return {
        "coverage": "complete" if complete and compatible else "partial",
        "limitations": limitations,
        "total_bytes_before": total_before,
        "total_bytes_after": total_after,
        "bytes_growth": growth,
        "growers": [d.model_dump() for d in growers[:25]],
        "new_classes": [d.model_dump() for d in new_classes[:25]],
        "findings": [f.model_dump() for f in findings],
        "summary": summary,
        "verdict": verdict,
    }


def _heap_delta_findings(growers, new_classes, growth, total_before, source) -> List[Finding]:
    findings: List[Finding] = []
    if not growers:
        findings.append(Finding(
            severity=Severity.INFO,
            title="No material growth between the two heaps",
            description=(
                "No tracked class grew in shallow size from the first capture to the second. "
                "If you expected a leak, capture the two dumps further apart, or under the "
                "load that triggers it."
            ),
            category="comparison",
        ))
        return findings

    resolved = 0
    for d in growers[:5]:
        simple = _simple(d.class_name)
        outer = _outer(d.class_name)
        user = is_user_code(outer)
        # A class that grew a lot — especially a doubling, or a user class — is the
        # prime leak suspect.
        doubled = d.bytes_before > 0 and d.bytes_after >= 2 * d.bytes_before
        big_share = total_before > 0 and d.bytes_delta / max(total_before, 1) > 0.10
        severity = Severity.WARNING

        loc = None
        if user and resolved < 3:
            loc = _resolve_grower(simple, source)
            resolved += 1

        grew_txt = (f"{_fmt_bytes(d.bytes_before)} → {_fmt_bytes(d.bytes_after)} "
                    f"(+{_fmt_bytes(d.bytes_delta)})")
        cnt_txt = f"{d.count_before:,} → {d.count_after:,} instances (+{d.count_delta:,})"
        findings.append(Finding(
            severity=severity,
            title=f"`{simple}` grew by {_fmt_bytes(d.bytes_delta)} between the two captures",
            description=(
                f"`{d.class_name}` went from {grew_txt}; {cnt_txt}. The biggest growers between "
                "two snapshots are the strongest leak suspects — this is what's accumulating."
                + (" It was absent from the first capture entirely." if d.is_new else "")
            ),
            impact=(
                "Sustained growth can increase memory pressure. A rate and exhaustion forecast require capture intervals, capacity, and comparable workloads."
            ),
            likely_cause=(
                f"`{simple}` growth may reflect workload changes or retention in a cache/registry/"
                "collection added to but never evicted, keyed by something unbounded."
            ),
            evidence=[f"shallow size: {grew_txt}", f"instances: {cnt_txt}"]
                     + (["present only in the second capture"] if d.is_new else []),
            remediation=(
                "Investigate this class as a growth candidate. Capture a heap dump at the high-water mark and "
                "analyze it here to get the retaining field/line, then bound or evict the holder."
            ),
            category="comparison",
            source_locations=[loc] if loc else [],
        ))

    if growth > 0:
        findings.append(Finding(
            severity=Severity.INFO,
            title=f"Net heap growth: {_fmt_bytes(growth)} across tracked classes",
            description="Total shallow size of the tracked classes increased between the two captures.",
            evidence=[f"before: {_fmt_bytes(total_before)}", f"growth: +{_fmt_bytes(growth)}"],
            category="comparison",
        ))
    return findings


def _thread_index(thread):
    buckets = {}
    for t in thread.get("threads") or []:
        key = next((f"{k}:{t[k]}" for k in ("tid", "id", "nid") if t.get(k)), "name:" + t.get("name", ""))
        buckets.setdefault(key, []).append(t)
    # Duplicate identities are not safe to pair.
    return {k: v[0] for k, v in buckets.items() if len(v) == 1}


def _idle(t):
    frames = {f"{f.get('class_name')}.{f.get('method')}" for f in t.get("stack", [])}
    return any(any(p in f for p in ("ThreadPoolExecutor.getTask", "ForkJoinPool.awaitWork",
                                    "ReferenceQueue.remove", "Finalizer$FinalizerThread.run",
                                    "ScheduledThreadPoolExecutor$DelayedWorkQueue.take")) for f in frames)


def compare_threads(before, after):
    bi, ai = _thread_index(before), _thread_index(after)
    compatible, limitations = compatibility(before, after, ordered=True)
    stuck = []
    for key in sorted(set(bi) & set(ai)) if compatible else []:
        tb, ta = bi[key], ai[key]
        sig = lambda t: [(f.get("class_name"), f.get("method"), f.get("line")) for f in t.get("stack", [])]
        sb, sa = sig(tb), sig(ta)
        if not sb or sb != sa or _idle(ta) or tb.get("state") != ta.get("state"):
            continue
        elapsed = None
        if ta.get("elapsed_s") is not None and tb.get("elapsed_s") is not None:
            elapsed = ta["elapsed_s"] - tb["elapsed_s"]
            if elapsed <= 0:
                continue
        cpu = None
        if ta.get("cpu_ms") is not None and tb.get("cpu_ms") is not None:
            cpu = ta["cpu_ms"] - tb["cpu_ms"]
            if cpu < 0: continue  # likely thread reuse or restarted process
        state = ta.get("state", "UNKNOWN")
        classification = "persistent_wait" if state in ("BLOCKED", "WAITING", "TIMED_WAITING") else "repeated_stack"
        if cpu and cpu > 0:
            classification = "active_repeated_stack"
        cn, method, line = sa[0]
        stuck.append(StuckThread(name=ta.get("name", key), identity=key, state=state,
                                  top_frame=f"{cn}.{method}:{line}", blocked=state == "BLOCKED",
                                  cpu_delta_ms=cpu, interval_s=elapsed, classification=classification))
    if stuck:
        findings = [Finding(severity=Severity.WARNING, title=f"{len(stuck)} thread(s) with persistent stacks",
                            description="The full stack and state recur. This is a sampling observation, not proof that no work progressed between captures.",
                            category="comparison", conclusion="observation", confidence="medium",
                            evidence=[f"{t.name}: {t.classification} at {t.top_frame}; CPU delta {t.cpu_delta_ms} ms" for t in stuck],
                            remediation="Inspect wait reasons and lock owners; capture additional samples and dependency latency before changing timeouts or pool sizes.")]
    else:
        findings = [Finding(severity=Severity.INFO, category="comparison", title="No persistently stuck threads established",
                            description="No non-idle unchanged full stacks were paired. Different stacks do not establish forward progress.")]
    stamp(findings)
    return {"stuck_threads": [t.model_dump() for t in stuck], "findings": [f.model_dump() for f in findings],
            "limitations": limitations, "summary": f"Compared {len(bi)} and {len(ai)} unambiguous thread identities; {len(stuck)} persistent stacks.",
            "verdict": _verdict(findings) if compatible else "insufficient_evidence"}


def _verdict(findings):
    if any(f.severity == Severity.CRITICAL for f in findings): return "critical"
    if any(f.severity == Severity.WARNING for f in findings): return "degraded"
    return "healthy"
