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
    assert retention and retention[0].severity == Severity.CRITICAL


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
