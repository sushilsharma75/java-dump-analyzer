"""GC-log analyzer: parsing, metrics, leak-trend detection, and the
three-pillar correlation marriage."""
from app.analyzers.gc_log import parse_gc_log
from app.analyzers.correlate import correlate


def _g1_line(i, t, before, after, total=2048, pause=8.5, phase="Pause Young (Normal)",
             cause="G1 Evacuation Pause"):
    return (f"[{t:.3f}s][info][gc] GC({i}) {phase} ({cause}) "
            f"{int(before)}M->{int(after)}M({total}M) {pause}ms")


def _leak_log(n=14):
    """A ratcheting post-GC floor — the classic leak sawtooth that never resets."""
    lines, after = [], 50.0
    for i in range(n):
        before = after + 30
        after = after + 25            # the floor climbs every cycle
        lines.append(_g1_line(i, 10 + i * 5, before, after))
    return "\n".join(lines)


def _healthy_log(n=14):
    """A stable post-GC floor oscillating around ~110 MB."""
    lines, prev = [], 100.0
    afters = [100, 140, 105, 142, 103, 138, 101, 140, 104, 139, 102, 141, 100, 138]
    for i in range(n):
        after = float(afters[i % len(afters)])
        before = prev + 80
        lines.append(_g1_line(i, 10 + i * 5, before, after))
        prev = after
    return "\n".join(lines)


def _full_gc_storm(n=5):
    lines = []
    for i in range(n):
        lines.append(_g1_line(
            i, 10 + i * 2, 1900, 1850, pause=950.0,
            phase="Pause Full", cause="G1 Compaction Pause"))
    return "\n".join(lines)


# --- parsing ----------------------------------------------------------------

def test_parses_unified_g1_and_detects_collector():
    a = parse_gc_log(_healthy_log())
    assert a.collector == "G1"
    assert a.jdk_logging == "unified"
    assert a.gc_count == 14
    assert a.events and a.events[0].phase == "young"
    assert a.events[0].before_mb > a.events[0].after_mb  # a collection freed memory


def test_throughput_and_pause_percentiles():
    a = parse_gc_log(_healthy_log())
    assert 95.0 <= a.throughput_pct <= 100.0     # tiny pauses, mostly app work
    assert a.pause_max_ms >= a.pause_p99_ms >= a.pause_p50_ms >= 0


def test_parses_legacy_printgcdetails():
    log = "\n".join([
        "2024-06-27T10:00:00.000+0000: 1.234: [GC (Allocation Failure) 33M->5M(128M), 0.0072 secs]",
        "2024-06-27T10:00:02.000+0000: 3.234: [GC (Allocation Failure) 40M->6M(128M), 0.0081 secs]",
    ])
    a = parse_gc_log(log)
    assert a.jdk_logging == "legacy"
    assert a.gc_count == 2
    assert a.events[0].pause_ms > 0


# --- the headline: leak-trend detection -------------------------------------

def test_leak_trend_is_flagged_critical():
    a = parse_gc_log(_leak_log())
    assert a.verdict == "critical"
    assert a.heap_after_trend_mb_per_min > 0
    leak = [f for f in a.findings if "leak" in f.title.lower()]
    assert leak and leak[0].severity == "critical"


def test_healthy_log_has_no_leak_finding():
    a = parse_gc_log(_healthy_log())
    assert a.verdict == "healthy"
    assert not any("leak" in f.title.lower() for f in a.findings)


def test_full_gc_storm_flagged():
    a = parse_gc_log(_full_gc_storm())
    assert a.full_gc_count == 5
    assert a.verdict == "critical"
    assert any("Full GC" in f.title for f in a.findings)


def test_empty_input_is_graceful():
    a = parse_gc_log("this is just an application log\nnothing to see here\n")
    assert a.gc_count == 0
    assert a.verdict == "healthy"
    assert any("No GC events" in f.title for f in a.findings)


# --- three-pillar correlation marriage --------------------------------------

def test_correlation_marries_gc_trend_with_heap_and_thread(source_index):
    gc = parse_gc_log(_leak_log()).model_dump()
    heap = {
        "verdict": "critical",
        "top_classes_by_size": [{
            "class_name": "com.example.Order", "instance_count": 3000,
            "shallow_size_bytes": 240_000, "pct_of_total_size": 49.0,
        }],
        "top_classes_by_count": [], "findings": [],
    }
    thread = {
        "total_threads": 1, "findings": [],
        "threads": [{"name": "worker-1", "stack": [
            {"class_name": "com.example.OrderService", "method": "loadAll",
             "file": "OrderService.java", "line": 21}]}],
    }
    r = correlate(heap, thread, source=source_index, gc=gc)
    leak = [f for f in r["findings"] if "Confirmed memory leak" in f["title"]]
    assert leak, "expected a three-pillar confirmed-leak finding"
    f = leak[0]
    assert f["severity"] == "critical"
    ev = " ".join(f["evidence"])
    assert "MB/min" in ev and "Order" in ev
