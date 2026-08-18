"""Wasteful-memory detector: duplicate byte[]/char[] content → reclaimable bytes."""
import io
from app.analyzers.heap_dump import parse_heap_dump
from app.analyzers.heap_waste import find_wasted_memory
from hprof_builder import HprofBuilder, BYTE


def _dump_with_byte_arrays(values):
    """values: list of (content_bytes, copies)."""
    b = HprofBuilder()
    cls = b.load_class("[B")            # a byte[] class load (cosmetic)
    b.class_dump(cls)
    for content, copies in values:
        for _ in range(copies):
            b.primitive_array(BYTE, len(content), data=content)
    return b.build()


def test_finds_duplicate_arrays_and_quantifies_waste():
    url = b"https://api.example.com/v1/orders?page=1"   # 40 bytes
    key = b"X-Correlation-Id"                            # 16 bytes
    data = _dump_with_byte_arrays([(url, 50), (key, 30), (b"unique-one", 1)])

    # ~3.7 KB wasted; a 50 KB "heap" puts it over the reporting threshold.
    findings, wasted = find_wasted_memory(io.BytesIO(data), total_heap_bytes=50_000)
    assert findings, "expected a duplicate-waste finding"
    f = findings[0]
    # waste = redundant copies * (content + 16B header): 49*(40+16) + 29*(16+16)
    assert wasted == 49 * (40 + 16) + 29 * (16 + 16)
    ev = " ".join(f.evidence)
    assert "api.example.com" in ev          # the hot value is shown as an example
    assert "redundant array copies" in ev


def test_no_duplicates_no_finding():
    data = _dump_with_byte_arrays([(b"alpha", 1), (b"beta", 1), (b"gamma", 1)])
    findings, wasted = find_wasted_memory(io.BytesIO(data), total_heap_bytes=200_000)
    assert findings == []
    assert wasted == 0


def test_below_threshold_yields_no_finding():
    # A couple of small duplicates — under both the 1MB and 3% thresholds.
    data = _dump_with_byte_arrays([(b"hi", 3)])
    findings, wasted = find_wasted_memory(io.BytesIO(data), total_heap_bytes=10_000_000)
    assert findings == []


def test_waste_surfaces_in_full_parse():
    big = b"the-same-long-repeated-payload-value-over-and-over-1234567890"  # 60 B
    data = _dump_with_byte_arrays([(big, 5000)])
    a = parse_heap_dump(io.BytesIO(data))
    assert a.wasted_bytes_estimate and a.wasted_bytes_estimate > 0
    assert any("Duplicate data wastes" in f.title for f in a.findings)


def test_severity_scales_with_share():
    big = b"x" * 200
    data = _dump_with_byte_arrays([(big, 4000)])
    # Make duplicates ~90% of a small declared heap → CRITICAL.
    findings, wasted = find_wasted_memory(io.BytesIO(data), total_heap_bytes=wasted_floor(big, 4000))
    assert findings and findings[0].severity == "critical"


def wasted_floor(content, copies):
    # total "heap" just a bit above the wasted bytes so pct is high
    per = len(content) + 16
    return int((copies - 1) * per / 0.9)
