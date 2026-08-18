"""Phase 3 cross-dump correlation: executing/allocating matches, GC cross-check."""
from app.analyzers.correlate import correlate


def _heap(class_name, pct=61.0, instances=2_000_000, verdict="critical"):
    return {
        "verdict": verdict,
        "top_classes_by_size": [{
            "class_name": class_name, "instance_count": instances,
            "shallow_size_bytes": 800_000_000, "pct_of_total_size": pct,
        }],
        "top_classes_by_count": [],
        "findings": [],
    }


def _thread(frames, findings=None, total=1):
    return {
        "total_threads": total,
        "findings": findings or [],
        "threads": [{"name": "http-exec-7", "stack": frames}],
    }


def test_executing_match():
    heap = _heap("com.example.Leaf")
    thread = _thread([{"class_name": "com.example.Leaf", "method": "process",
                       "file": "Leaf.java", "line": 5}])
    r = correlate(heap, thread, source=None)
    assert r["matched_classes"] == 1
    titles = " ".join(f["title"] for f in r["findings"])
    assert "Leaf" in titles


def test_allocating_match_bridges_via_source(source_index):
    # Heap is full of Order; the live thread is in OrderService.loadAll, which
    # constructs Order. With source, correlation should bridge to that line.
    heap = _heap("com.example.Order")
    thread = _thread([{"class_name": "com.example.OrderService", "method": "loadAll",
                       "file": "OrderService.java", "line": 21}])
    r = correlate(heap, thread, source=source_index)
    assert r["matched_classes"] >= 1
    f = next(f for f in r["findings"] if "Order" in f["title"])
    assert f["severity"] == "critical"
    loc = f["source_locations"][0]
    assert loc["repo_path"].endswith("OrderService.java")
    assert loc["line"] == 21


def test_no_overlap_is_reported():
    heap = _heap("com.example.Widget", verdict="degraded")
    thread = _thread([{"class_name": "java.lang.Thread", "method": "run", "line": 1}])
    r = correlate(heap, thread, source=None)
    assert r["matched_classes"] == 0
    assert any("No direct overlap" in f["title"] for f in r["findings"])


def test_gc_pressure_cross_check():
    heap = _heap("com.example.Order", verdict="degraded")
    thread = _thread(
        [{"class_name": "java.lang.Thread", "method": "run", "line": 1}],
        findings=[{"category": "gc", "title": "GC threads consuming significant CPU"}],
    )
    r = correlate(heap, thread, source=None)
    assert any(f["category"] == "correlation" and "GC" in f["title"] for f in r["findings"])
