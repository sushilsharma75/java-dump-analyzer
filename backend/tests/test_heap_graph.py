"""Phase 2 retention tracer: reverse-path from the top consumer to the holder."""
import io

from app.analyzers.heap_dump import parse_heap_dump
from app.analyzers.heap_graph import trace_retention
from app.schemas import Severity
from hprof_builder import HprofBuilder


def _holder_chain_dump(n_leaves=50):
    """Leaf  <-  Leaf[]  <-  Holder.leaves  <-  GC root."""
    b = HprofBuilder()
    leaf = b.load_class("com.example.Leaf")
    holder = b.load_class("com.example.Holder")
    b.class_dump(leaf)
    b.class_dump(holder, instance_fields=[("leaves", b.OBJECT)])
    leaves = [b.instance(leaf, body=b"\x00" * 4) for _ in range(n_leaves)]
    arr = b.object_array(leaf, leaves)
    holder_oid = b.instance(holder, refs=[arr])    # Holder.leaves -> arr
    b.gc_root(holder_oid)
    return b.build()


def test_trace_retention_recovers_holder_chain(source_index):
    data = _holder_chain_dump()
    finding = trace_retention(io.BytesIO(data), "com.example.Leaf", source=source_index)
    assert finding is not None
    assert "Retention path" in finding.title
    # Chain should climb Leaf -> Leaf[] -> Holder.leaves.
    chain_evidence = " ".join(finding.evidence)
    assert "com.example.Leaf[]" in chain_evidence
    assert "Holder.leaves" in chain_evidence
    loc = finding.source_locations[0]
    assert loc.method == "leaves"
    assert loc.repo_path.endswith("Holder.java")
    assert loc.line is not None


def test_tracer_finding_present_in_full_parse(source_index):
    a = parse_heap_dump(io.BytesIO(_holder_chain_dump()), source=source_index)
    retention = [f for f in a.findings if "Retention path" in f.title]
    assert retention and retention[0].severity == Severity.WARNING
    assert retention[0].conclusion == "observation"
    assert retention[0].limitations


def test_trace_graph_flag_disables_tracing(source_index):
    a = parse_heap_dump(io.BytesIO(_holder_chain_dump()), source=source_index,
                        trace_graph=False)
    assert not any("Retention path" in f.title for f in a.findings)


def test_tracer_returns_none_when_unheld():
    # Leaves referenced by nobody — there's no retention path to report.
    b = HprofBuilder()
    leaf = b.load_class("com.example.Leaf")
    b.class_dump(leaf)
    for _ in range(20):
        b.instance(leaf, body=b"\x00" * 4)
    finding = trace_retention(io.BytesIO(b.build()), "com.example.Leaf")
    assert finding is None


def test_deep_flag_lifts_size_ceiling_but_not_disable(source_index, monkeypatch):
    # A dump above the retention-tracing ceiling is skipped unless the analysis opts in.
    monkeypatch.setenv("HEAP_GRAPH_MAX_BYTES", "1")
    data = _holder_chain_dump()
    skipped = parse_heap_dump(io.BytesIO(data), source=source_index)
    assert not any("Retention path" in f.title for f in skipped.findings)
    assert any("deep retention analysis" in (s.enable_hint or "") for s in skipped.skipped_analyses)
    deep = parse_heap_dump(io.BytesIO(data), source=source_index, deep=True)
    assert any("Retention path" in f.title for f in deep.findings)
    # Configuration that disables tracing still wins over the per-analysis opt-in.
    monkeypatch.setenv("HEAP_GRAPH_TRACE", "0")
    disabled = parse_heap_dump(io.BytesIO(data), source=source_index, deep=True)
    assert not any("Retention path" in f.title for f in disabled.findings)


def test_weak_referent_is_not_reported_as_retaining_leaf():
    b = HprofBuilder()
    leaf = b.load_class("example.Leaf")
    reference = b.load_class("java.lang.ref.Reference")
    weak = b.load_class("example.WeakReference")
    b.class_dump(leaf)
    b.class_dump(reference, instance_fields=[("referent", b.OBJECT)])
    b.class_dump(weak, super_id=reference)
    obj = b.instance(leaf)
    ref = b.instance(weak, refs=[obj])
    b.gc_root(ref)
    assert trace_retention(io.BytesIO(b.build()), "example.Leaf") is None


def test_static_field_directly_holding_array_is_found():
    b = HprofBuilder()
    leaf = b.load_class("example.Leaf")
    array = b.load_class("[Lexample.Leaf;")
    owner = b.load_class("example.Cache")
    b.class_dump(leaf)
    b.class_dump(array)
    obj = b.instance(leaf)
    arr = b.object_array(array, [obj])
    b.class_dump(owner, static_object_fields=[("entries", arr)])
    finding = trace_retention(io.BytesIO(b.build()), "example.Leaf")
    assert "example.Cache.entries" in " ".join(finding.evidence)
    assert "[][]" not in " ".join(finding.evidence)
    array_finding = trace_retention(io.BytesIO(b.build()), "example.Leaf[]")
    assert "example.Cache.entries" in " ".join(array_finding.evidence)


def test_array_payload_memory_is_bounded_and_early_match_consumes_remainder():
    import tracemalloc
    b = HprofBuilder()
    leaf = b.load_class("example.Leaf")
    holder = b.load_class("example.Holder")
    b.class_dump(leaf)
    b.class_dump(holder, instance_fields=[("items", b.OBJECT)])
    obj = b.instance(leaf)
    arr = b.object_array(leaf, [obj] * 1_000_000)
    b.instance(holder, refs=[arr])
    stream = io.BytesIO(b.build())
    tracemalloc.start()
    try:
        finding = trace_retention(stream, "example.Leaf")
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert "Holder.items" in " ".join(finding.evidence)
    assert peak < 20 * 1024 * 1024


def test_reported_chain_does_not_mix_separate_branches():
    b = HprofBuilder()
    leaf = b.load_class("example.Leaf")
    a = b.load_class("java.util.BranchA")
    z = b.load_class("java.util.BranchZ")
    holder = b.load_class("example.Holder")
    b.class_dump(leaf)
    b.class_dump(a, instance_fields=[("left", b.OBJECT)])
    b.class_dump(z, instance_fields=[("right", b.OBJECT)])
    b.class_dump(holder, instance_fields=[("branch", b.OBJECT)])
    obj = b.instance(leaf)
    for _ in range(10):
        b.instance(a, refs=[obj])
    branch = b.instance(z, refs=[obj])
    b.instance(holder, refs=[branch])
    finding = trace_retention(io.BytesIO(b.build()), "example.Leaf")
    evidence = " ".join(finding.evidence)
    assert "BranchZ.right" in evidence
    assert "BranchA.left" not in evidence
    assert "Holder.branch" in evidence


def test_large_dump_tracing_is_enabled_by_default(monkeypatch):
    from app.analyzers.heap_dump import _graph_max_bytes
    monkeypatch.delenv("HEAP_GRAPH_MAX_BYTES", raising=False)
    monkeypatch.delenv("HEAP_GRAPH_TRACE", raising=False)
    assert _graph_max_bytes() > 11 * 1024**3


def test_automatic_tracing_finds_owner_in_sparse_10_gib_dump(tmp_path, monkeypatch):
    import struct
    monkeypatch.setenv('HEAP_DOMINATOR', '0')  # isolate sampled-tracing stage
    monkeypatch.delenv('HEAP_GRAPH_MAX_BYTES', raising=False)
    monkeypatch.delenv('HEAP_GRAPH_TRACE', raising=False)
    b = HprofBuilder()
    cache = b.load_class('example.Cache')
    b.class_dump(cache, instance_fields=[('payload', b.OBJECT)])
    owner = b.instance(cache, refs=[0x70000000])
    b.gc_root(owner)
    # Few huge arrays test offsets and automatic stage routing, not the runtime
    # of millions of small objects. Sparse holes avoid allocating 10.5 GiB.
    with (tmp_path / 'large.hprof').open('w+b') as fp:
        fp.write(b.build())
        for i in range(3):
            count = 7 * 1024**3 // 2
            header = bytes([0x23]) + struct.pack('>QIIB', 0x70000000 + i, 0, count, 8)
            fp.write(bytes([0x1c]) + struct.pack('>II', 0, len(header) + count))
            fp.write(header)
            fp.seek(count - 1, 1)
            fp.write(b'\0')
        fp.seek(0)
        result = parse_heap_dump(fp)
    assert result.histogram_complete and result.total_instances == 4
    trace = next(f for f in result.findings if f.title.startswith('Retention path'))
    assert 'Cache.payload' in trace.title
    assert 'byte[]' in trace.title
