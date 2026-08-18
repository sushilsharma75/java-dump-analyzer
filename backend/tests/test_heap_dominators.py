"""
Tests for the dominator tree / exact retained sizes.

Each test builds an exact object graph with HprofBuilder and asserts the retained
numbers to the byte — that's the point of a dominator tree over the heuristic
tracer: the answers are exact, so the tests can be too.

Shallow-size conventions (must match heap_dump's histogram — see heap_sizing).
These fixtures use the default compressed-oops layout: a 12-byte object header,
a 16-byte array header, 4-byte references, everything aligned to 8. Note that
hprof writes each reference field at the 8-byte identifier size, so a class with
one reference field has an 8-byte payload but only a 4-byte slot in the live heap:

    instance        = align8(12 + payload - 4 * n_reference_fields)
    primitive array = align8(16 + n * elem_size)
    object array    = align8(16 + n * 4)
"""
import io

from app.analyzers.heap_dump import parse_heap_dump
from app.analyzers.heap_dominators import compute_retained
from app.analyzers.heap_sizing import COMPRESSED, UNCOMPRESSED, size_model
from tests.hprof_builder import HprofBuilder, OBJECT, LONG, BYTE


def _parse(b: HprofBuilder):
    return parse_heap_dump(io.BytesIO(b.build()))


def test_exact_retained_size_of_holder():
    """root -> Holder -> Object[50] -> 50 Leaf(8-byte body)."""
    b = HprofBuilder()
    leaf = b.load_class("com.example.Leaf")
    holder = b.load_class("com.example.Holder")
    b.class_dump(leaf, instance_fields=[("v", LONG)])
    b.class_dump(holder, instance_fields=[("arr", OBJECT)])

    leaves = [b.instance(leaf, body=b"\x00" * 8) for _ in range(50)]   # align8(12+8)=24 each
    arr = b.object_array(leaf, leaves)                                  # align8(16+50*4)=216
    h = b.instance(holder, refs=[arr])                                  # align8(12+8-4)=16
    b.gc_root(h)

    rr = compute_retained(io.BytesIO(b.build()))
    expected = 16 + (16 + 50 * 4) + 50 * 24     # 1432
    top = rr.entries[0]
    assert top.class_name == "com.example.Holder"
    assert top.retained_bytes == expected
    assert top.shallow_bytes == 16
    assert rr.reachable_bytes == expected
    assert rr.unreachable_count == 0
    # accumulation chain descends through the array
    assert "com.example.Leaf[]" in top.chain


def test_shared_object_dominated_by_root_only():
    """A -> C and B -> C, both A and B rooted: neither retains C."""
    b = HprofBuilder()
    node = b.load_class("com.example.Node")
    b.class_dump(node, instance_fields=[("ref", OBJECT)])
    plain = b.load_class("com.example.Plain")
    b.class_dump(plain)

    c = b.instance(plain)                    # align8(12+0)=16, no fields
    a = b.instance(node, refs=[c])           # align8(12+8-4)=16
    b2 = b.instance(node, refs=[c])          # 16
    b.gc_root(a)
    b.gc_root(b2)

    rr = compute_retained(io.BytesIO(b.build()))
    by_name = {}
    for e in rr.entries:
        by_name.setdefault(e.class_name, []).append(e)
    # C is a top-level dominator entry itself (dominated only by the root)
    assert any(e.retained_bytes == 16 for e in by_name["com.example.Plain"])
    for e in by_name["com.example.Node"]:
        assert e.retained_bytes == 16, "a shared object must not be retained by either referrer"
    assert rr.reachable_bytes == 16 + 16 + 16


def test_cycle_retained_by_entry_point():
    """root -> A <-> B (cycle): A retains B."""
    b = HprofBuilder()
    node = b.load_class("com.example.CNode")
    b.class_dump(node, instance_fields=[("ref", OBJECT)])
    a_oid = 0x500000
    b_oid = 0x500001
    b.instance(node, refs=[b_oid], oid=a_oid)
    b.instance(node, refs=[a_oid], oid=b_oid)
    b.gc_root(a_oid)

    rr = compute_retained(io.BytesIO(b.build()))
    top = rr.entries[0]
    assert top.object_id == hex(a_oid)
    assert top.retained_bytes == 32          # both 16-byte nodes


def test_unreachable_objects_counted():
    b = HprofBuilder()
    plain = b.load_class("com.example.Plain")
    b.class_dump(plain)
    rooted = b.instance(plain)
    b.instance(plain)                         # never rooted, nothing references it
    b.gc_root(rooted)

    rr = compute_retained(io.BytesIO(b.build()))
    assert rr.reachable_bytes == 16
    assert rr.unreachable_count == 1
    assert rr.unreachable_bytes == 16


def test_static_field_retained_via_class_node():
    """Static fields hang off the class object; the class must dominate them."""
    b = HprofBuilder()
    plain = b.load_class("com.example.Plain")
    b.class_dump(plain)
    val = b.instance(plain)                   # 16
    cache = b.load_class("com.example.Cache")
    b.class_dump(cache, static_object_fields=[("HELD", val)])

    rr = compute_retained(io.BytesIO(b.build()))
    cls_entry = next(e for e in rr.entries if e.class_name == "class com.example.Cache")
    assert cls_entry.retained_bytes == 16


def test_leak_suspect_finding_over_threshold():
    """A dominator retaining >=1MB and >=20% of the heap must raise the MAT-style
    leak-suspect finding, and it must reach parse_heap_dump's findings."""
    b = HprofBuilder()
    holder = b.load_class("com.example.BigHolder")
    b.class_dump(holder, instance_fields=[("buf", OBJECT)])
    big = b.primitive_array(BYTE, 2_000_000)          # align8(16+2_000_000)=2,000,016
    h = b.instance(holder, refs=[big])                 # align8(12+8-4)=16
    b.gc_root(h)

    a = _parse(b)
    assert a.dominators, "dominator entries should be attached to the analysis"
    assert a.dominators[0].retained_bytes == 2_000_032
    assert a.reachable_bytes == 2_000_032
    suspects = [f for f in a.findings if f.title.startswith("Leak suspect")]
    assert suspects, "expected a leak-suspect finding"
    assert suspects[0].severity.value == "critical"    # 100% of reachable heap
    assert "BigHolder" in suspects[0].title


def test_small_heap_produces_no_suspect_noise():
    """Below the absolute floor no leak-suspect finding fires, however dominant
    one object is — tiny fixtures and healthy small heaps must stay quiet."""
    b = HprofBuilder()
    holder = b.load_class("com.example.SmallHolder")
    b.class_dump(holder, instance_fields=[("buf", OBJECT)])
    buf = b.primitive_array(BYTE, 1000)
    h = b.instance(holder, refs=[buf])
    b.gc_root(h)

    a = _parse(b)
    assert a.dominators[0].class_name == "com.example.SmallHolder"
    assert not [f for f in a.findings if f.title.startswith("Leak suspect")]


def test_histogram_and_dominators_agree_on_shallow_size():
    """The two halves of the report must size the same object identically —
    a histogram row and a dominator row that disagree is the loophole this
    shared size model exists to close."""
    b = HprofBuilder()
    holder = b.load_class("com.example.Agree")
    b.class_dump(holder, instance_fields=[("buf", OBJECT)])
    buf = b.primitive_array(BYTE, 4096)
    h = b.instance(holder, refs=[buf])
    b.gc_root(h)

    a = _parse(b)
    hist = {e.class_name: e for e in a.top_classes_by_size}
    dom = next(e for e in a.dominators if e.class_name == "com.example.Agree")
    assert dom.shallow_bytes == hist["com.example.Agree"].shallow_size_bytes
    assert hist["byte[]"].shallow_size_bytes == 4096 + 16


def test_size_model_reference_width_correction():
    """A reference field occupies 8 bytes in the hprof record but 4 in a
    compressed-oops heap — the model must subtract the difference."""
    # one reference field: payload 8 -> align8(12 + 8 - 4) == 16
    assert COMPRESSED.instance_size(8, 1, id_size=8) == 16
    # same class without compressed oops: align8(16 + 8) == 24
    assert UNCOMPRESSED.instance_size(8, 1, id_size=8) == 24
    # a long field is 8 bytes either way, and pads to the alignment boundary
    assert COMPRESSED.instance_size(8, 0, id_size=8) == 24
    # arrays: header + elements, aligned
    assert COMPRESSED.object_array_size(50) == 216
    assert COMPRESSED.prim_array_size(1000, 1) == 1016


def test_size_model_selection_follows_heap_size():
    """Compressed oops is HotSpot's default below a 32GB heap and off above it."""
    assert size_model(8, 512 * 1024 * 1024) is COMPRESSED
    assert size_model(8, 40 * 1024 * 1024 * 1024) is UNCOMPRESSED
    assert size_model(4, 512 * 1024 * 1024).oop_size == 4       # 32-bit JVM


def test_duplicate_classes_reported():
    """Same FQCN under two classloaders -> MAT's Duplicate Classes signal."""
    b = HprofBuilder()
    obj = b.load_class("java.lang.Object")
    b.class_dump(obj)
    cl = b.load_class("java.lang.ClassLoader")
    b.class_dump(cl, super_id=obj)
    loader1 = b.instance(cl)
    loader2 = b.instance(cl)

    dup_a = b.load_class("com.acme.Shared")
    b.class_dump(dup_a, loader_id=loader1)
    dup_b = b.load_class("com.acme.Shared", fresh=True)
    b.class_dump(dup_b, loader_id=loader2)

    a = _parse(b)
    dups = [d for d in a.duplicate_classes if d.class_name == "com.acme.Shared"]
    assert dups and dups[0].loader_count == 2
