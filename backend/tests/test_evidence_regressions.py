import io
import json
import random
import sqlite3

from app.analyzers.diagnostics import analyze
from app.analyzers.compare import compare_heaps, compare_threads
from app.analyzers.correlate import correlate
from app.analyzers.source import SourceIndex
from app.analyzers.heap_index import build_index, retained, object_detail, root_paths
from app.analyzers.heap_dump import parse_heap_dump
from app.analyzers.llm import _bounded_json, _trim_for_llm
from tests.hprof_builder import HprofBuilder


def test_modern_frames_and_adjacent_threads():
    text = """"worker" #1 tid=0x1 nid=0x1 runnable
 java.lang.Thread.State: RUNNABLE
 at java.base@17.0.6/java.lang.Thread.run(Thread.java:833)
 at app//com.example.OrderService.run(OrderService.java:42)
"worker" #2 tid=0x2 nid=0x2 runnable
 java.lang.Thread.State: RUNNABLE
 at loader/java.base/java.lang.Thread.run(Thread.java:833)
"""
    a = analyze(text)
    assert a.total_threads == 2
    assert a.parse_coverage["frames_parsed"] == 3
    assert a.threads[0].stack[1].class_name == "com.example.OrderService"
    assert a.threads[0].stack[1].class_loader == "app"
    assert a.threads[1].stack[0].module == "java.base"
    assert analyze("garbage").verdict == "invalid"
    assert analyze(text + " at ???badframe\n").parse_coverage["frames_rejected"] == 1


def test_synchronizer_cycle_without_jvm_deadlock_report():
    text = """"a" #1 tid=0x1 nid=0x1 waiting on condition
 java.lang.Thread.State: WAITING
 at com.example.A.run(A.java:4)
 - parking to wait for <0xb> (a java.util.concurrent.locks.ReentrantLock$NonfairSync)
 Locked ownable synchronizers:
 - <0xa> (a java.util.concurrent.locks.ReentrantLock$NonfairSync)

"b" #2 tid=0x2 nid=0x2 waiting on condition
 java.lang.Thread.State: WAITING
 at com.example.B.run(B.java:8)
 - parking to wait for <0xa> (a java.util.concurrent.locks.ReentrantLock$NonfairSync)
 Locked ownable synchronizers:
 - <0xb> (a java.util.concurrent.locks.ReentrantLock$NonfairSync)
"""
    a = analyze(text)
    assert len(a.deadlocks) == 1
    assert a.verdict == "critical"
    assert len(a.blocked_chains) == 2


def test_idle_and_duplicate_thread_names_are_not_hangs():
    t = {
        "name": "worker",
        "state": "WAITING",
        "stack": [
            {
                "class_name": "java.util.concurrent.ThreadPoolExecutor",
                "method": "getTask",
            }
        ],
    }
    assert not compare_threads({"threads": [t]}, {"threads": [t]})["stuck_threads"]
    t["stack"] = [{"class_name": "Example", "method": "work"}]
    assert not compare_threads({"threads": [t, t]}, {"threads": [t, t]})[
        "stuck_threads"
    ]


def test_partial_histogram_absence_is_unknown():
    a = {
        "top_classes_by_size": [
            {"class_name": "A", "instance_count": 1, "shallow_size_bytes": 10}
        ]
    }
    b = {
        "top_classes_by_size": [
            {"class_name": "B", "instance_count": 1, "shallow_size_bytes": 20}
        ]
    }
    r = compare_heaps(a, b)
    assert r["new_classes"] == [] and r["growers"] == []
    assert r["verdict"] == "insufficient_evidence"
    a["histogram_complete"] = b["histogram_complete"] = True
    a["histogram"] = a["top_classes_by_size"]
    b["histogram"] = b["top_classes_by_size"]
    assert compare_heaps(a, b)["new_classes"][0]["class_name"] == "B"
    b["capture"] = {"process_id": "two"}
    a["capture"] = {"process_id": "one"}
    assert not compare_heaps(a, b)["growers"]


def test_correlation_cannot_confirm_from_gc_or_wrong_capture():
    heap = {
        "top_classes_by_size": [{"class_name": "byte[]", "shallow_size_bytes": 1000}]
    }
    r = correlate(
        heap,
        {"threads": []},
        gc={"heap_after_trend_mb_per_min": 20, "verdict": "critical"},
    )
    assert not any("confirmed" in f["title"].lower() for f in r["findings"])
    heap["capture"] = {"process_id": "one"}
    r = correlate(heap, {"capture": {"process_id": "two"}, "threads": []})
    assert r["matched_classes"] == 0


def test_source_ambiguity_comments_and_method_boundaries(tmp_path):
    (tmp_path / "A.java").write_text(
        "package a; class A { void first() { Other x = new Other(); } void second() { } }"
    )
    (tmp_path / "Other.java").write_text("package a; class Other {}")
    (tmp_path / "B.java").write_text(
        "package b; class Other {} class B { void wrong() { Other o = new Other(); } }"
    )
    (tmp_path / "Comment.java").write_text(
        'package a; class Comment { /* new Other() */ String s = "new Other()"; }'
    )
    idx = SourceIndex(tmp_path)
    idx.build()
    refs = idx.find_references("a.Other")
    assert refs and all(r["repo_path"] == "A.java" for r in refs)
    assert all(r["method"] == "first" for r in refs)
    assert not idx.find_references("Other")
    assert idx.lookup("unrelated.A") is None
    (tmp_path / "dup").mkdir()
    (tmp_path / "dup" / "A.java").write_text("package a; class A {}")
    idx = SourceIndex(tmp_path)
    idx.build()
    assert idx.lookup("a.A") is None


def test_nonroot_static_and_weak_referents(tmp_path):
    b = HprofBuilder()
    leaf = b.load_class("sample.Leaf")
    ref = b.load_class("java.lang.ref.Reference")
    cache = b.load_class("sample.Cache")
    b.class_dump(leaf)
    b.class_dump(ref, instance_fields=[("referent", b.OBJECT)])
    target = b.instance(leaf)
    r = b.instance(ref, refs=[target])
    b.gc_root(r)
    b.class_dump(cache, static_object_fields=[("cache", target)])
    path = tmp_path / "graph.sqlite"
    build_index(io.BytesIO(b.build()), path)
    result = retained(path)
    assert result["reachable_bytes"] == 16
    assert result["unreachable_count"] == 1
    assert not root_paths(path, hex(target))["paths"]
    assert root_paths(path, hex(target), include_weak=True)["paths"]
    assert object_detail(path, hex(r))["outgoing_count"] == 2  # referent + class


def test_disk_dominators_against_independent_removal_oracle(tmp_path):
    # Independently recompute reachability after deleting each object. This catches
    # shared nodes, irreducible cycles, unreachable subgraphs and multiple roots.
    for seed in range(12):
        rng = random.Random(seed)
        n = 14
        links = [
            [rng.randrange(n) if rng.random() < 0.7 else None for _ in range(2)]
            for i in range(n)
        ]
        roots = {0, 1}

        def reachable(exclude=None):
            seen = set()
            work = list(roots - {exclude})
            while work:
                node = work.pop()
                if node in seen or node == exclude:
                    continue
                seen.add(node)
                work.extend(x for x in links[node] if x is not None and x != exclude)
            return seen

        live = reachable()
        b = HprofBuilder()
        cls = b.load_class("sample.Node")
        b.class_dump(cls, instance_fields=[("left", b.OBJECT), ("right", b.OBJECT)])
        for i in range(n):
            b.instance(
                cls,
                refs=[0x10000 + j if j is not None else 0 for j in links[i]],
                oid=0x10000 + i,
            )
        for i in roots:
            b.gc_root(0x10000 + i)
        path = tmp_path / f"{seed}.sqlite"
        build_index(io.BytesIO(b.build()), path)
        result = retained(path)
        assert result["reachable_bytes"] == len(live) * 24
        with sqlite3.connect(path) as db:
            for i in live:
                size = db.execute(
                    "SELECT retained FROM dom WHERE oid=?", (hex(0x10000 + i),)
                ).fetchone()[0]
                assert size == len(live - reachable(i)) * 24, (seed, i)


def test_complete_histogram_and_failed_stage_visible(monkeypatch):
    from app.analyzers import heap_waste

    b = HprofBuilder()
    c = b.load_class("sample.C")
    b.class_dump(c)
    o = b.instance(c)
    b.gc_root(o)

    def fail(*a, **kw):
        raise RuntimeError("test failure")

    monkeypatch.setattr(heap_waste, "find_wasted_memory", fail)
    a = parse_heap_dump(io.BytesIO(b.build()))
    assert a.histogram_complete and a.histogram
    assert any(s.status == "failed" and "duplicate" in s.stage for s in a.stages)


def test_llm_context_selection_and_json_budget():
    threads = [{"name": f"t{i}", "stack": []} for i in range(100)]
    out = _trim_for_llm(
        {"threads": threads, "findings": [{"affected_threads": ["t99"]}]}, "thread"
    )
    assert out["threads"][0]["name"] == "t99"
    data = json.loads(
        _bounded_json({"findings": [{"text": "a" * 1000} for _ in range(100)]}, 5000)
    )
    assert data["context_omissions"]


def test_collection_fill_and_reference_pages(tmp_path):
    b = HprofBuilder()
    leaf = b.load_class("sample.Leaf")
    lst = b.load_class("java.util.ArrayList")
    b.class_dump(leaf)
    b.class_dump(lst, instance_fields=[("size", b.INT), ("elementData", b.OBJECT)])
    children = [b.instance(leaf) for _ in range(3)]
    array = b.object_array(leaf, children + [0] * 7)
    owner = b.instance(lst, body=b.pack_fields([(b.INT, 3), (b.OBJECT, array)]))
    b.gc_root(owner)
    path = tmp_path / "collections.sqlite"
    build_index(io.BytesIO(b.build()), path)
    detail = object_detail(path, hex(owner))
    assert detail["collection"]["size"] == 3
    assert detail["collection"]["capacity"] == 10
    assert detail["collection"]["fill_ratio"] == 0.3
    first = object_detail(path, hex(array), limit=2)
    second = object_detail(path, hex(array), offset=2, limit=2)
    assert len(first["outgoing"]) == 2 and len(second["outgoing"]) == 2
    assert not set(e["field"] for e in first["outgoing"]) & set(
        e["field"] for e in second["outgoing"]
    )


def test_unknown_subrecord_is_partial():
    import struct

    b = HprofBuilder()
    c = b.load_class("sample.A")
    b.class_dump(c)
    b.instance(c)
    data = b.build() + b"\x1c" + struct.pack(">II", 0, 1) + b"\xaa"
    result = parse_heap_dump(io.BytesIO(data))
    assert result.truncated and not result.histogram_complete
    assert any(s.status == "partial" for s in result.stages)


def test_retention_finding_follows_actual_field_to_source(tmp_path):
    from app.analyzers.heap_dominators import compute_retained

    (tmp_path / "Owner.java").write_text(
        "package sample;\nclass Owner {\n byte[] payload;\n void clear() { payload = null; }\n}\n"
    )
    source = SourceIndex(tmp_path)
    source.build()
    b = HprofBuilder()
    c = b.load_class("sample.Owner")
    b.class_dump(c, instance_fields=[("payload", b.OBJECT)])
    array = b.primitive_array(b.BYTE, 1_500_000)
    owner = b.instance(c, refs=[array])
    b.gc_root(owner)
    result = compute_retained(io.BytesIO(b.build()), source=source)
    loc = result.findings[0].source_locations[0]
    assert (
        loc.repo_path == "Owner.java"
        and loc.line == 3
        and loc.role == "retaining_field"
    )
    assert result.entries[0].root_paths["paths"]
    context = source.context("sample.Owner", line=3)
    if source.provenance["java_ast_files"]:
        assert context["related_field_methods"][0]["method"] == "clear"


def test_full_index_duplicate_scan_exceeds_legacy_array_limit(tmp_path):
    from app.analyzers.heap_index import duplicate_arrays

    b = HprofBuilder()
    b.primitive_array(b.BYTE, 10000)
    b.primitive_array(b.BYTE, 10000)
    b.primitive_array(b.CHAR, 5000)  # same bytes, different primitive type
    path = tmp_path / "duplicates.sqlite"
    build_index(io.BytesIO(b.build()), path)
    duplicates = duplicate_arrays(path)
    assert len(duplicates["groups"]) == 1
    assert duplicates["potential_duplicate_bytes"] == 10016


def test_numeric_fields_preserve_java_values_in_valid_json(tmp_path):
    import struct

    b = HprofBuilder()
    c = b.load_class("sample.Numbers")
    b.class_dump(c, instance_fields=[("value", b.DOUBLE), ("id", b.LONG)])
    oid = b.instance(c, body=struct.pack(">dq", float("nan"), 2**63 - 1))
    path = tmp_path / "numbers.sqlite"
    build_index(io.BytesIO(b.build()), path)
    result = object_detail(path, hex(oid))
    json.dumps(result, allow_nan=False)
    assert result["values"]["sample.Numbers.id"] == str(2**63 - 1)


def test_source_session_does_not_silently_read_changed_build(tmp_path):
    path = tmp_path / "App.java"
    path.write_text("class App { void run() {} }")
    source = SourceIndex(tmp_path)
    source.build()
    assert source.lookup("App")
    path.write_text("class App { void other() {} }")
    assert source.lookup("App") is None
    assert source.provenance["source_changed"]


def test_disk_dominator_gate_and_explicit_disable(tmp_path, monkeypatch):
    b = HprofBuilder()
    c = b.load_class("sample.Holder")
    b.class_dump(c)
    owner = b.instance(c)
    b.gc_root(owner)
    monkeypatch.setenv("HEAP_DOMINATOR_MAX_BYTES", "1")
    monkeypatch.setenv("HEAP_DISK_DOMINATORS", "1")
    result = parse_heap_dump(io.BytesIO(b.build()), index_path=tmp_path / "full.sqlite")
    assert result.dominators
    monkeypatch.setenv("HEAP_DOMINATOR", "0")
    disabled = parse_heap_dump(
        io.BytesIO(b.build()), index_path=tmp_path / "disabled.sqlite"
    )
    assert not disabled.dominators
    assert any(
        s.stage.startswith("dominator") and s.status == "skipped"
        for s in disabled.stages
    )
