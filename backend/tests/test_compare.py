"""Dump comparison / delta: heap growers + persistently-stuck threads."""
from app.analyzers.compare import compare_heaps, compare_threads


def _heap(classes):
    """classes: list of (name, count, bytes) -> a minimal serialized heap analysis."""
    entries = [{"class_name": n, "instance_count": c, "shallow_size_bytes": b}
               for n, c, b in classes]
    return {"top_classes_by_size": entries, "top_classes_by_count": entries}


def test_heap_grower_is_flagged_as_leak_suspect():
    before = _heap([("com.example.Order", 1000, 100_000),
                    ("java.lang.String", 5000, 200_000)])
    after = _heap([("com.example.Order", 9000, 900_000),     # 9x growth
                   ("java.lang.String", 5200, 205_000)])
    r = compare_heaps(before, after)
    assert r["verdict"] == "critical"
    top = r["growers"][0]
    assert top["class_name"] == "com.example.Order"
    assert top["bytes_delta"] == 800_000
    assert top["count_delta"] == 8000
    assert any("Order" in f["title"] and "grew" in f["title"] for f in r["findings"])


def test_heap_grower_resolves_to_source(source_index):
    before = _heap([("com.example.Order", 100, 10_000)])
    after = _heap([("com.example.Order", 5000, 500_000)])
    r = compare_heaps(before, after, source=source_index)
    f = next(f for f in r["findings"] if "Order" in f["title"])
    assert f["source_locations"], "user-class grower should resolve to source"
    assert f["source_locations"][0]["repo_path"].endswith(".java")


def test_new_class_detected():
    before = _heap([("com.example.Order", 100, 10_000)])
    after = _heap([("com.example.Order", 100, 10_000),
                   ("com.example.Session", 4000, 400_000)])
    r = compare_heaps(before, after)
    assert any(d["class_name"] == "com.example.Session" and d["is_new"]
               for d in r["new_classes"])


def test_no_growth_is_healthy():
    h = _heap([("com.example.Order", 1000, 100_000)])
    r = compare_heaps(h, h)
    assert r["verdict"] == "healthy"
    assert any("No material growth" in f["title"] for f in r["findings"])


# --- thread comparison ------------------------------------------------------

def _thread(threads):
    """threads: list of (name, state, [frames]) where frame=(class,method,line)."""
    return {"threads": [
        {"name": n, "state": s,
         "stack": [{"class_name": c, "method": m, "line": l} for c, m, l in frames]}
        for n, s, frames in threads
    ]}


def test_persistently_stuck_thread_flagged_critical():
    frames = [("com.example.OrderService", "loadAll", 21)]
    before = _thread([("worker-1", "BLOCKED", frames), ("worker-2", "RUNNABLE", [("X", "run", 1)])])
    after = _thread([("worker-1", "BLOCKED", frames), ("worker-2", "RUNNABLE", [("Y", "run", 2)])])
    r = compare_threads(before, after)
    assert r["verdict"] == "critical"               # worker-1 stuck + BLOCKED
    assert len(r["stuck_threads"]) == 1
    assert r["stuck_threads"][0]["name"] == "worker-1"
    assert r["stuck_threads"][0]["blocked"] is True


def test_no_stuck_threads_when_all_progress():
    before = _thread([("w", "RUNNABLE", [("A", "a", 1)])])
    after = _thread([("w", "RUNNABLE", [("B", "b", 2)])])   # moved on
    r = compare_threads(before, after)
    assert r["stuck_threads"] == []
    assert any("No persistently stuck" in f["title"] for f in r["findings"])
