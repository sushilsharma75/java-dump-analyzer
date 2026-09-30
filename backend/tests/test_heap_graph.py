"""Phase 2 retention tracer: reverse-path from the top consumer to the holder."""
import io
import pytest

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


def test_static_field_directly_holding_array_is_found(tmp_path):
    from app.analyzers.heap_index import build_index
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
    path = tmp_path / 'heap.sqlite'
    build_index(io.BytesIO(b.build()), path)
    assert trace_retention(io.BytesIO(b.build()), 'example.Leaf', index_path=path) == finding
    assert trace_retention(io.BytesIO(b.build()), 'example.Leaf[]', index_path=path) == array_finding


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


def test_reported_chain_does_not_mix_separate_branches(tmp_path):
    from app.analyzers.heap_index import build_index
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
    path = tmp_path / 'heap.sqlite'
    build_index(io.BytesIO(b.build()), path)
    assert trace_retention(io.BytesIO(b.build()), 'example.Leaf', index_path=path) == finding


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


@pytest.mark.parametrize('anchor', ['user', 'root', 'static', 'none'])
@pytest.mark.parametrize('leaf_name', ['example.Leaf', 'example.Leaf[]', 'byte[]'])
def test_indexed_trace_preserves_stream_chain_without_reading_dump(tmp_path, anchor, leaf_name):
    from app.analyzers.heap_index import build_index
    b = HprofBuilder()
    leaf = b.load_class('example.Leaf')
    array = b.load_class('[Lexample.Leaf;')
    parent = b.load_class('java.util.Parent')
    owner = b.load_class('example.Owner' if anchor == 'user' else 'java.util.Owner')
    b.class_dump(leaf)
    b.class_dump(array)
    b.class_dump(parent, instance_fields=[('padding', b.INT), ('items', b.OBJECT)])
    b.class_dump(owner, super_id=parent)
    obj = b.instance(leaf)
    if leaf_name == 'byte[]':
        target = b.primitive_array(b.BYTE, 3, data=b'\x01\x02\x03')
    else:
        target = b.object_array(array, [obj, obj])
    held = b.instance(owner, body=b.pack_fields([(b.INT, 42), (b.OBJECT, target)]))
    if anchor == 'root':
        b.gc_root(held)
    elif anchor == 'static':
        cache = b.load_class('example.Cache')
        b.class_dump(cache, static_object_fields=[('entries', held)])
    data = b.build()
    path = tmp_path / 'heap.sqlite'
    build_index(io.BytesIO(data), path)
    expected = trace_retention(io.BytesIO(data), leaf_name)
    class Unreadable:
        def read(self, *args):
            raise AssertionError('indexed retention must not reread the dump')
        seek = read
    actual = trace_retention(Unreadable(), leaf_name, index_path=path)
    assert actual == expected
    assert actual is not None


def test_indexed_trace_keeps_sample_order_and_excludes_weak_and_metadata_edges(tmp_path):
    from app.analyzers.heap_index import build_index
    b = HprofBuilder()
    leaf = b.load_class('example.Leaf')
    other_leaf = b.load_class('example.Leaf', fresh=True)
    reference = b.load_class('java.lang.ref.Reference')
    weak = b.load_class('example.WeakReference')
    holder = b.load_class('example.Holder')
    b.class_dump(leaf)
    b.class_dump(other_leaf)
    b.class_dump(reference, instance_fields=[('referent', b.OBJECT)])
    b.class_dump(weak, super_id=reference)
    b.class_dump(holder, instance_fields=[('payload', b.OBJECT)])
    first = b.instance(other_leaf)
    second = b.instance(leaf)
    b.instance(weak, refs=[first])
    b.instance(holder, refs=[second])
    path = tmp_path / 'heap.sqlite'
    data = b.build()
    build_index(io.BytesIO(data), path)
    for cap in (0, 1, 2):
        assert trace_retention(io.BytesIO(data), 'example.Leaf', sample_cap=cap, index_path=path) == \
               trace_retention(io.BytesIO(data), 'example.Leaf', sample_cap=cap)
    assert trace_retention(io.BytesIO(data), 'example.Leaf', sample_cap=1, index_path=path) is None
    # A class's <class> edges are not instance holding fields.
    assert trace_retention(io.BytesIO(data), 'example.Leaf[]', index_path=path) is None


def test_streaming_trace_stops_at_first_terminal_and_reports_progress():
    from app.analyzers.heap_graph import _Tracer
    b = HprofBuilder()
    leaf = b.load_class('example.Leaf')
    holder = b.load_class('example.Holder')
    b.class_dump(leaf)
    b.class_dump(holder, instance_fields=[('payload', b.OBJECT)])
    target = b.instance(leaf)
    b.instance(holder, refs=[target])
    # Tail is deliberately larger than the reader's 4 MiB read-ahead buffer.
    for _ in range(150_000):
        b.instance(holder, refs=[0])
    class CountingStream(io.BytesIO):
        bytes_read = 0
        def read(self, n=-1):
            data = super().read(n)
            self.bytes_read += len(data)
            return data
    data = b.build()
    stream = CountingStream(data)
    stages = []
    tracer = _Tracer(stream, sample_cap=1, stage_callback=stages.append)
    tracer.scan_meta()
    stream.bytes_read = 0
    chain, terminal = tracer.trace('example.Leaf')
    assert terminal == ('user', 'example.Holder', 'payload')
    assert chain == ['example.Leaf', 'example.Holder.payload']
    assert stream.bytes_read < 2 * len(data)
    assert any('reference level 1' in stage for stage in stages)


def test_indexed_trace_resolves_array_load_class_without_class_dump(tmp_path):
    from app.analyzers.heap_index import build_index
    b = HprofBuilder()
    leaf = b.load_class('example.Leaf')
    array = b.load_class('[Lexample.Leaf;')
    holder = b.load_class('example.Holder')
    b.class_dump(leaf)
    b.class_dump(holder, instance_fields=[('items', b.OBJECT)])
    obj = b.instance(leaf)
    arr = b.object_array(array, [obj])
    b.instance(holder, refs=[arr])
    data = b.build()
    path = tmp_path / 'heap.sqlite'
    build_index(io.BytesIO(data), path)
    for name in ('example.Leaf', 'example.Leaf[]'):
        expected = trace_retention(io.BytesIO(data), name)
        assert expected is not None
        assert trace_retention(io.BytesIO(data), name, index_path=path) == expected


def test_trace_supports_four_byte_object_ids(tmp_path):
    import struct
    from app.analyzers.heap_index import build_index
    def record(tag, body):
        return struct.pack('>BII', tag, 0, len(body)) + body
    top = b''
    for sid, text in ((1, 'example.Leaf'), (2, 'example.Holder'), (3, 'items')):
        top += record(1, struct.pack('>I', sid) + text.encode())
    for serial, cid, sid in ((1, 10, 1), (2, 20, 2)):
        top += record(2, struct.pack('>IIII', serial, cid, 0, sid))
    segment = b''
    for cid in (10, 20):
        segment += struct.pack('>B', 0x20) + struct.pack('>IIIIIIIII', cid, 0, 0, 0, 0, 0, 0, 0, 4)
        segment += struct.pack('>HHH', 0, 0, int(cid == 20))
        if cid == 20:
            segment += struct.pack('>IB', 3, 2)
    segment += struct.pack('>BIIII', 0x21, 100, 0, 10, 0)
    segment += struct.pack('>BIIII I', 0x21, 200, 0, 20, 4, 100)
    segment += struct.pack('>BI', 0xff, 200)
    data = b'JAVA PROFILE 1.0.2\0' + struct.pack('>III', 4, 0, 0) + top + record(0x1c, segment)
    expected = trace_retention(io.BytesIO(data), 'example.Leaf')
    assert expected is not None and 'Holder.items' in expected.title
    path = tmp_path / 'heap.sqlite'
    build_index(io.BytesIO(data), path)
    assert trace_retention(io.BytesIO(data), 'example.Leaf', index_path=path) == expected
