"""
GC-log analyzer — the third diagnostic pillar alongside thread and heap dumps.

GC logs are the cheapest, most common, PII-free JVM diagnostic artifact, and they
answer the one question a heap dump can't on its own: *is the live set actually
growing over time?* A single heap dump is a snapshot; the trend of heap-occupancy
**after** each collection is what separates "legitimately large heap" from "leak".

This parser is line-oriented and streaming (GC logs are text, often tens of MB),
and deliberately dependency-free — it mirrors the streaming/Counter style of
`heap_dump.py` and reuses the shared `Finding`/`Severity` model so its output
slots straight into the existing findings UI and the correlation engine.

Formats handled:
  * JDK 9+ unified logging (`-Xlog:gc*`) — the primary target. The summary line
        [ts] GC(10) Pause Young (Normal) (G1 Evacuation Pause) 33M->5M(128M) 7.285ms
    carries everything we need: id, phase, cause, before->after(total), pause.
  * Legacy `-XX:+PrintGCDetails` (JDK 8) — the whole-heap `A->B(C), D secs` tail.

It extracts per-event (before, after, total, pause, timestamp) and derives:
throughput %, pause percentiles, allocation rate, and — the headline — the
linear-regression slope of post-GC heap occupancy (the leak signal).

Region/concurrent collectors (ZGC, Shenandoah) are detected and their pauses and
allocation stalls are surfaced, but their generational internals get a lighter
treatment than G1/Parallel/Serial — an honest v1 boundary.
"""
from __future__ import annotations
import re
from typing import BinaryIO, Iterable, List, Optional, Tuple

from ..schemas import Finding, Severity, GCEvent, GCLogAnalysis

# --- size + event regexes -------------------------------------------------

_UNIT = {"B": 1 / (1024 * 1024), "K": 1 / 1024, "M": 1.0, "G": 1024.0}


def _mb(num: str, unit: str) -> float:
    return float(num) * _UNIT.get(unit, 1.0)


# before->after(total) followed by a pause in ms (unified) or secs (legacy).
_SIZES = re.compile(
    r"(\d+(?:\.\d+)?)([BKMG])->(\d+(?:\.\d+)?)([BKMG])\((\d+(?:\.\d+)?)([BKMG])\)"
)
_PAUSE_MS = re.compile(r"(\d+(?:\.\d+)?)\s*ms\b")
_PAUSE_SECS = re.compile(r",\s*(\d+(?:\.\d+)?)\s*secs\b")
_GC_ID = re.compile(r"GC\((\d+)\)")

# Timestamp decorators: ISO date, and/or uptime seconds in brackets.
_ISO = re.compile(r"\[(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?[^\]]*)\]")
_UPTIME = re.compile(r"\[(\d+(?:\.\d+)?)s\]")
# Legacy leading "1.234:" uptime stamp.
_LEGACY_UPTIME = re.compile(r"^(?:[\d\-T:.+]+:\s*)?(\d+(?:\.\d+)?):\s")

# Phase classification keywords (checked in order).
_PHASE_RULES: Tuple[Tuple[str, str], ...] = (
    ("full", "full"),
    ("mixed", "mixed"),
    ("young", "young"),
    ("allocation stall", "stall"),
)

# Collector fingerprints — substrings that only appear for one collector.
_COLLECTOR_HINTS: Tuple[Tuple[str, str], ...] = (
    ("ZGC", "ZGC"),
    ("Shenandoah", "Shenandoah"),
    ("G1 Evacuation", "G1"),
    ("Pause Young (Normal)", "G1"),
    ("Pause Remark", "G1"),
    ("PSYoungGen", "Parallel"),
    ("ParOldGen", "Parallel"),
    ("Parallel", "Parallel"),
    ("ParNew", "CMS"),
    ("CMS", "CMS"),
    ("DefNew", "Serial"),
    ("Tenured", "Serial"),
)


def _classify_phase(text: str) -> str:
    low = text.lower()
    for kw, phase in _PHASE_RULES:
        if kw in low:
            return phase
    if "concurrent" in low or "remark" in low or "mark" in low or "cleanup" in low:
        return "concurrent"
    return "other"


def _extract_cause(text: str) -> str:
    """Last parenthesized group is usually the GC cause."""
    groups = re.findall(r"\(([^)]*)\)", text)
    return groups[-1].strip() if groups else ""


def _timestamp_s(line: str) -> Optional[float]:
    """A monotonic-ish seconds value for the event, preferring uptime."""
    m = _UPTIME.search(line)
    if m:
        return float(m.group(1))
    m = _LEGACY_UPTIME.match(line)
    if m:
        return float(m.group(1))
    return None  # ISO-only lines handled by the caller (needs epoch baseline)


def _iso_epoch(line: str) -> Optional[float]:
    m = _ISO.search(line)
    if not m:
        return None
    raw = m.group(1)
    # Normalize "+0000" -> "+00:00" so fromisoformat accepts it; drop trailing tags.
    raw = raw.strip()
    try:
        import datetime as _dt
        fixed = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", raw)
        return _dt.datetime.fromisoformat(fixed).timestamp()
    except Exception:
        return None


def _detect_collector(lines_sample: List[str]) -> str:
    blob = "\n".join(lines_sample)
    for token, name in _COLLECTOR_HINTS:
        if token in blob:
            return name
    return "Unknown"


def _percentile(sorted_vals: List[float], p: float) -> float:
    if not sorted_vals:
        return 0.0
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    idx = p / 100 * (len(sorted_vals) - 1)
    lo = int(idx)
    frac = idx - lo
    hi = min(lo + 1, len(sorted_vals) - 1)
    return sorted_vals[lo] * (1 - frac) + sorted_vals[hi] * frac


def _linreg_slope(xs: List[float], ys: List[float]) -> float:
    """Least-squares slope (units: y per x). 0 when undefined."""
    n = len(xs)
    if n < 2:
        return 0.0
    mx = sum(xs) / n
    my = sum(ys) / n
    denom = sum((x - mx) ** 2 for x in xs)
    if denom == 0:
        return 0.0
    return sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / denom


def _parse_lines(lines: Iterable[str]) -> Tuple[List[GCEvent], List[str], List[float]]:
    """Return (events, sample_lines, pure_pause_ms_with_no_sizes)."""
    events: List[GCEvent] = []
    sample: List[str] = []
    standalone_pauses: List[float] = []   # ZGC/Shenandoah pause lines w/o A->B(C)
    epoch0: Optional[float] = None
    seq = 0

    for line in lines:
        if len(sample) < 200:
            sample.append(line)

        sizes = _SIZES.search(line)
        if not sizes:
            # Concurrent-collector pause line (e.g. "Pause Mark Start 0.012ms")?
            if "Pause" in line:
                pm = _PAUSE_MS.search(line)
                if pm:
                    standalone_pauses.append(float(pm.group(1)))
            continue

        before = _mb(sizes.group(1), sizes.group(2))
        after = _mb(sizes.group(3), sizes.group(4))
        total = _mb(sizes.group(5), sizes.group(6))

        pause_ms = 0.0
        pm = _PAUSE_MS.search(line, sizes.end())
        if pm:
            pause_ms = float(pm.group(1))
        else:
            ps = _PAUSE_SECS.search(line)
            if ps:
                pause_ms = float(ps.group(1)) * 1000.0

        # timestamp: uptime if present, else ISO epoch normalized to first seen.
        ts = _timestamp_s(line)
        if ts is None:
            ep = _iso_epoch(line)
            if ep is not None:
                if epoch0 is None:
                    epoch0 = ep
                ts = ep - epoch0
        if ts is None:
            ts = float(seq)  # last resort: ordinal

        gid_m = _GC_ID.search(line)
        gc_id = int(gid_m.group(1)) if gid_m else seq

        # phase text = between the GC(id)/start and the size token
        head = line[:sizes.start()]
        phase = _classify_phase(head)
        cause = _extract_cause(head)

        events.append(GCEvent(
            seq=seq, timestamp_s=round(ts, 3), gc_id=gc_id, phase=phase,
            cause=cause, before_mb=round(before, 2), after_mb=round(after, 2),
            total_mb=round(total, 2), pause_ms=round(pause_ms, 3),
        ))
        seq += 1

    return events, sample, standalone_pauses


def parse_gc_log(text: str) -> GCLogAnalysis:
    return _build(*_parse_lines(text.splitlines()))


def parse_gc_log_stream(fp: BinaryIO) -> GCLogAnalysis:
    def _decoded() -> Iterable[str]:
        for raw in fp:
            yield raw.decode("utf-8", errors="replace").rstrip("\n")
    return _build(*_parse_lines(_decoded()))


# --- analysis assembly ----------------------------------------------------

def _build(events: List[GCEvent], sample: List[str],
           standalone_pauses: List[float]) -> GCLogAnalysis:
    collector = _detect_collector(sample)
    unified = any(_UPTIME.search(l) or _ISO.search(l) or "][info][gc" in l for l in sample)
    logging_kind = "unified" if unified else "legacy"

    if not events and not standalone_pauses:
        return GCLogAnalysis(
            collector=collector, jdk_logging=logging_kind, duration_s=0.0,
            total_pause_ms=0.0, gc_count=0, full_gc_count=0, throughput_pct=100.0,
            pause_p50_ms=0.0, pause_p95_ms=0.0, pause_p99_ms=0.0, pause_max_ms=0.0,
            alloc_rate_mb_s=0.0, heap_after_trend_mb_per_min=0.0, events=[],
            findings=[Finding(
                severity=Severity.INFO,
                title="No GC events recognized",
                description=(
                    "No parseable garbage-collection events were found. Make sure the file "
                    "is JVM GC output — unified logging (`-Xlog:gc*`) or legacy "
                    "`-XX:+PrintGCDetails` — and not an application log."
                ),
                category="gc",
            )],
            summary="No GC events recognized in this file.",
            verdict="healthy",
        )

    sizeful = [e for e in events if e.phase in ("young", "mixed", "full")]
    timestamps = [e.timestamp_s for e in events] or [0.0]
    duration_s = max(timestamps) - min(timestamps)
    if duration_s <= 0:
        duration_s = float(len(events))  # degenerate: ordinal spacing

    all_pauses = [e.pause_ms for e in events if e.pause_ms > 0] + list(standalone_pauses)
    total_pause_ms = sum(all_pauses)
    full_gc_count = sum(1 for e in events if e.phase == "full")
    stall_count = sum(1 for e in events if e.phase == "stall") + sum(
        1 for l in sample if "Allocation Stall" in l)

    wall_ms = duration_s * 1000.0
    throughput_pct = 100.0 if wall_ms <= 0 else max(
        0.0, min(100.0, (wall_ms - total_pause_ms) / wall_ms * 100.0))

    sp = sorted(all_pauses)
    p50, p95, p99 = _percentile(sp, 50), _percentile(sp, 95), _percentile(sp, 99)
    pmax = sp[-1] if sp else 0.0

    # allocation rate: heap grows from the previous post-GC point to this pre-GC point.
    alloc_mb = 0.0
    prev_after: Optional[float] = None
    for e in sizeful:
        if prev_after is not None and e.before_mb > prev_after:
            alloc_mb += e.before_mb - prev_after
        prev_after = e.after_mb
    alloc_rate = alloc_mb / duration_s if duration_s > 0 else 0.0

    # leak signal: slope of post-GC occupancy over time (MB/min), plus a
    # baseline-reset check so a heap that sawtooths back down isn't flagged.
    after_xs = [e.timestamp_s for e in sizeful]
    after_ys = [e.after_mb for e in sizeful]
    slope_mb_s = _linreg_slope(after_xs, after_ys)
    trend_mb_min = slope_mb_s * 60.0
    baseline_reset = _has_baseline_reset(after_ys)

    findings = _gc_findings(
        collector, throughput_pct, full_gc_count, stall_count, total_pause_ms,
        duration_s, p99, pmax, alloc_rate, trend_mb_min, baseline_reset, sizeful)
    verdict = _verdict(findings)
    summary = _summary(collector, len(events), throughput_pct, trend_mb_min,
                       full_gc_count, duration_s)

    # Downsample the event list for transport/charting (keep <= 400 points).
    transport = _downsample(events, 400)

    return GCLogAnalysis(
        collector=collector, jdk_logging=logging_kind, duration_s=round(duration_s, 2),
        total_pause_ms=round(total_pause_ms, 1), gc_count=len(events),
        full_gc_count=full_gc_count, throughput_pct=round(throughput_pct, 2),
        pause_p50_ms=round(p50, 2), pause_p95_ms=round(p95, 2),
        pause_p99_ms=round(p99, 2), pause_max_ms=round(pmax, 2),
        alloc_rate_mb_s=round(alloc_rate, 2),
        heap_after_trend_mb_per_min=round(trend_mb_min, 3),
        events=transport, findings=findings, summary=summary, verdict=verdict,
    )


def _has_baseline_reset(after_ys: List[float]) -> bool:
    """True if late-window minimum occupancy returns near the early-window minimum
    (i.e. the heap genuinely empties out — not a leak)."""
    if len(after_ys) < 8:
        return True   # too few points to call it a leak
    q = max(2, len(after_ys) // 4)
    early_min = min(after_ys[:q])
    late_min = min(after_ys[-q:])
    base = max(early_min, 1.0)
    return late_min <= early_min * 1.5 or (late_min - early_min) / base < 0.5


def _downsample(events: List[GCEvent], cap: int) -> List[GCEvent]:
    if len(events) <= cap:
        return events
    step = len(events) / cap
    return [events[int(i * step)] for i in range(cap)]


def _gc_findings(collector, throughput, full_gc, stalls, total_pause_ms, duration_s,
                 p99, pmax, alloc_rate, trend_mb_min, baseline_reset,
                 sizeful) -> List[Finding]:
    findings: List[Finding] = []
    peak_after = max((e.after_mb for e in sizeful), default=0.0)

    # 1) The headline: live set trending up with no baseline reset = leak.
    if trend_mb_min > 1.0 and not baseline_reset and len(sizeful) >= 8:
        findings.append(Finding(
            severity=Severity.CRITICAL,
            title=f"Live set is growing ~{trend_mb_min:.1f} MB/min — likely a memory leak",
            description=(
                "Heap occupancy measured immediately *after* each garbage collection is "
                "trending upward and never returns to its earlier baseline. A healthy app "
                "sawtooths around a flat post-GC line; a rising post-GC floor means objects "
                "are being retained for good — the signature of a leak."
            ),
            impact=(
                "Each GC reclaims less than the last. The heap marches toward -Xmx, GC "
                "runs more often for smaller wins, and the JVM eventually throws "
                "OutOfMemoryError."
            ),
            likely_cause=(
                "An unbounded cache/collection or a registry that's added to but never "
                "evicted. Pair this log with a heap dump to name the exact class, and a "
                "thread dump to find the allocating code path."
            ),
            evidence=[
                f"post-GC occupancy slope: +{trend_mb_min:.2f} MB/min over {duration_s:.0f}s",
                f"peak post-GC live set: {peak_after:.0f} MB",
                "no baseline reset: the heap never drains back to its starting floor",
            ],
            remediation=(
                "Capture a heap dump while the heap is high and analyze it here — the "
                "dominant class is your leak. Then bound/evict the structure holding it."
            ),
            category="gc",
        ))

    # 2) Full-GC thrash / allocation stalls = pre-OOM.
    if full_gc >= 3 or stalls >= 1:
        sev = Severity.CRITICAL if (full_gc >= 5 or stalls >= 3) else Severity.WARNING
        what = []
        if full_gc:
            what.append(f"{full_gc} Full GC(s)")
        if stalls:
            what.append(f"{stalls} allocation stall(s)")
        findings.append(Finding(
            severity=sev,
            title=f"GC is struggling: {', '.join(what)}",
            description=(
                "Repeated Full GCs (or allocation stalls on a concurrent collector) mean "
                "the collector can't keep up with allocation or can't free enough — the "
                "classic state right before an OutOfMemoryError or a long stop-the-world "
                "freeze."
            ),
            impact="Application threads are paused or throttled while the JVM fights to reclaim memory; latency spikes and throughput collapses.",
            likely_cause="The live set is too close to -Xmx (leak or undersized heap), or allocation rate outruns the collector.",
            evidence=[f"{', '.join(what)} in {duration_s:.0f}s",
                      f"peak post-GC live set: {peak_after:.0f} MB"],
            remediation="Fix the underlying growth (heap dump) or raise -Xmx if the live set is legitimately large. For high churn, reduce allocation on the hot path.",
            category="gc",
        ))

    # 3) Throughput / pause quality.
    if throughput < 90.0:
        sev = Severity.CRITICAL if throughput < 70.0 else Severity.WARNING
        findings.append(Finding(
            severity=sev,
            title=f"Low GC throughput: {throughput:.1f}% of wall-clock time was application work",
            description=(
                f"The application spent {100 - throughput:.1f}% of wall-clock time stopped "
                "for garbage collection. Healthy services typically sit above 95%."
            ),
            impact="Direct latency and throughput loss — every request can be paused mid-flight by a collection.",
            likely_cause="Heap pressure (live set near -Xmx), an allocation-heavy workload, or a collector/heap-size mismatch.",
            evidence=[f"throughput: {throughput:.1f}%",
                      f"total STW pause: {total_pause_ms/1000:.1f}s of {duration_s:.0f}s",
                      f"collector: {collector}"],
            remediation="Address heap growth first; then consider a low-pause collector (G1/ZGC) or a larger heap if the live set is genuinely large.",
            category="gc",
        ))
    elif p99 > 1000.0:
        findings.append(Finding(
            severity=Severity.WARNING,
            title=f"Long GC pauses: P99 {p99:.0f} ms (max {pmax:.0f} ms)",
            description="Throughput is acceptable but individual pauses are long enough to hurt tail latency and trip timeouts/health checks.",
            impact="Occasional multi-hundred-ms to multi-second stalls that show up as p99 latency spikes and flaky timeouts.",
            likely_cause="Large young/mixed collections, a big live set to scan, or Full GCs.",
            evidence=[f"pause P99: {p99:.0f} ms", f"pause max: {pmax:.0f} ms"],
            remediation="Tune the collector for pause time (e.g. G1 MaxGCPauseMillis, or move to ZGC/Shenandoah for sub-ms pauses), and reduce live-set size.",
            category="gc",
        ))

    # 4) Allocation churn (informational lead toward the allocator).
    if alloc_rate > 512.0:
        findings.append(Finding(
            severity=Severity.WARNING,
            title=f"High allocation rate: ~{alloc_rate:.0f} MB/s",
            description="The app is allocating heap very fast. Even without a leak, high churn drives frequent young GCs and CPU overhead.",
            impact="Frequent young collections, higher GC CPU, and more chances for objects to be promoted and create old-gen pressure.",
            likely_cause="A hot loop creating short-lived objects (boxing, string concatenation, per-request buffers, large intermediate collections).",
            evidence=[f"allocation rate: ~{alloc_rate:.0f} MB/s"],
            remediation="Profile allocations (or correlate with a heap dump's dominant short-lived class) and reduce per-iteration allocation on the hot path.",
            category="gc",
        ))

    if not findings:
        findings.append(Finding(
            severity=Severity.INFO,
            title="GC looks healthy",
            description=(
                f"{collector} kept throughput high with a stable post-GC live set and no "
                "Full-GC thrash. No memory-pressure red flags in this window."
            ),
            evidence=[f"throughput: {throughput:.1f}%",
                      f"post-GC slope: {trend_mb_min:+.2f} MB/min",
                      f"P99 pause: {p99:.0f} ms"],
            category="gc",
        ))
    return findings


def _verdict(findings: List[Finding]) -> str:
    if any(f.severity == Severity.CRITICAL for f in findings):
        return "critical"
    if any(f.severity == Severity.WARNING for f in findings):
        return "degraded"
    return "healthy"


def _summary(collector, n_events, throughput, trend_mb_min, full_gc, duration_s) -> str:
    trend = (f"live set climbing {trend_mb_min:+.1f} MB/min"
             if abs(trend_mb_min) >= 0.1 else "live set flat")
    fg = f", {full_gc} Full GC(s)" if full_gc else ""
    return (f"{collector}: {n_events} GC event(s) over {duration_s:.0f}s, "
            f"throughput {throughput:.1f}%, {trend}{fg}.")
