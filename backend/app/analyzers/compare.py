"""
Dump comparison / delta — the "what changed between two captures?" view.

A single dump is a snapshot; two dumps taken minutes apart turn a guess into a
measurement. This is the classic leak workflow (and yCrash's headline feature):

  * Two heap dumps → which classes *grew*. The biggest grower between a healthy
    baseline and a struggling capture is almost always the leak — far more
    decisive than eyeballing one histogram.
  * Two thread dumps → which threads are *still stuck in the same place*. A thread
    parked at the same line across both snapshots hasn't progressed: a real hang,
    not a sampling artifact.

Stateless over the already-serialized analysis dicts (the same JSON the UI holds),
so it composes with the existing analyzers and the source index for `file:line`.
"""
from __future__ import annotations
from typing import Dict, List, Optional, Any, Tuple

from ..schemas import (
    Finding, Severity, SourceLocation,
    ClassDelta, HeapComparison, StuckThread, ThreadComparison,
)
from .source import SourceIndex, is_user_code


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
    for key in ("top_classes_by_size", "top_classes_by_count"):
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

    deltas: List[ClassDelta] = []
    for name in set(bi) | set(ai):
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
    total_before = sum(sz for _, sz in bi.values())
    total_after = sum(sz for _, sz in ai.values())
    growth = total_after - total_before

    findings = _heap_delta_findings(growers, new_classes, growth, total_before, source)
    verdict = _verdict(findings)
    summary = (
        f"Tracked {len(deltas)} class(es) across the two heaps: net "
        f"{_fmt_bytes(growth)} change"
        + (f", led by `{_simple(growers[0].class_name)}` (+{_fmt_bytes(growers[0].bytes_delta)})."
           if growers else " — nothing grew materially.")
    )
    return {
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
        severity = Severity.CRITICAL if (user or doubled or big_share) else Severity.WARNING

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
                "If this keeps growing at this rate, the heap fills and the JVM ends in "
                "OutOfMemoryError. The growth rate between these two dumps tells you how long "
                "you have."
            ),
            likely_cause=(
                f"`{simple}` instances are being retained without bound — a cache/registry/"
                "collection added to but never evicted, keyed by something unbounded."
            ),
            evidence=[f"shallow size: {grew_txt}", f"instances: {cnt_txt}"]
                     + (["present only in the second capture"] if d.is_new else []),
            remediation=(
                "Treat this class as the leak. Capture a heap dump at the high-water mark and "
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


def _thread_index(thread: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {t.get("name"): t for t in (thread.get("threads") or []) if t.get("name")}


def _top_frame_sig(t: Dict[str, Any]) -> Optional[str]:
    stack = t.get("stack") or []
    if not stack:
        return None
    fr = stack[0]
    cn, m = fr.get("class_name"), fr.get("method")
    if not cn:
        return None
    return f"{cn}.{m}" + (f":{fr['line']}" if fr.get("line") else "")


def compare_threads(before: Dict[str, Any], after: Dict[str, Any]) -> Dict[str, Any]:
    """Diff two thread dumps → threads still stuck at the same spot in both."""
    bi = _thread_index(before)
    ai = _thread_index(after)

    stuck: List[StuckThread] = []
    for name in set(bi) & set(ai):
        tb, ta = bi[name], ai[name]
        sb, sa = _top_frame_sig(tb), _top_frame_sig(ta)
        if sb and sb == sa:
            state = ta.get("state") or "UNKNOWN"
            stuck.append(StuckThread(
                name=name, state=str(state), top_frame=sa,
                blocked=str(state) in ("BLOCKED", "WAITING", "TIMED_WAITING"),
            ))

    stuck.sort(key=lambda s: (not s.blocked, s.name))
    findings = _thread_delta_findings(stuck, len(bi), len(ai))
    verdict = _verdict(findings)
    summary = (
        f"Compared {len(bi)} vs {len(ai)} threads: "
        + (f"{len(stuck)} stuck in the same place across both captures."
           if stuck else "no threads are stuck at the same spot in both captures.")
    )
    return {
        "stuck_threads": [s.model_dump() for s in stuck],
        "findings": [f.model_dump() for f in findings],
        "summary": summary,
        "verdict": verdict,
    }


def _thread_delta_findings(stuck: List[StuckThread], n_before, n_after) -> List[Finding]:
    if not stuck:
        return [Finding(
            severity=Severity.INFO,
            title="No persistently stuck threads",
            description=(
                "No thread is parked at the same stack frame in both captures. Threads are "
                "progressing between snapshots — what you saw in a single dump was likely "
                "transient, not a hang."
            ),
            category="comparison",
        )]
    blocked = [s for s in stuck if s.blocked]
    severity = Severity.CRITICAL if blocked else Severity.WARNING
    lead = stuck[0]
    return [Finding(
        severity=severity,
        title=f"{len(stuck)} thread(s) stuck in the same place across both dumps",
        description=(
            "These threads are parked at the identical stack frame in both captures, so they "
            "have not progressed between the two snapshots — a real hang, not a sampling blip. "
            f"Lead: `{lead.name}` at `{lead.top_frame}` (state {lead.state})."
        ),
        impact=(
            "Stuck worker threads don't return to the pool: throughput drops, queues back up, "
            "and the service can wedge entirely if enough threads are pinned here."
        ),
        likely_cause=(
            "A blocking call with no timeout, lock contention on a hot monitor, or an external "
            "dependency (DB/HTTP) not responding. " +
            ("Several are BLOCKED/WAITING — check what holds the lock or resource they want."
             if blocked else "They are progressing through the same code repeatedly or wedged in a loop.")
        ),
        evidence=[f"{s.name} @ {s.top_frame} ({s.state})" for s in stuck[:8]],
        remediation=(
            "Open the shared frame above. Add timeouts to blocking calls, reduce lock scope, "
            "and confirm the downstream dependency is healthy. If BLOCKED, find the lock owner."
        ),
        category="comparison",
    )]


def _verdict(findings: List[Finding]) -> str:
    if any(f.severity == Severity.CRITICAL for f in findings):
        return "critical"
    if any(f.severity == Severity.WARNING for f in findings):
        return "degraded"
    return "healthy"
