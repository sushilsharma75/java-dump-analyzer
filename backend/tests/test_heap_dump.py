"""Heap parser: header validation, histogram, and the static-field leak finder."""
import io

import pytest

from app.analyzers.heap_dump import parse_heap_dump
from app.schemas import Severity
from hprof_builder import HprofBuilder


def _parse(data, **kw):
    return parse_heap_dump(io.BytesIO(data), **kw)


def test_rejects_thread_dump_text():
    text = (b"2024-03-15 14:30:22\nFull thread dump Java HotSpot(TM) 64-Bit "
            b"Server VM\n" + b"x" * 80)
    with pytest.raises(ValueError) as e:
        _parse(text)
    assert "thread dump" in str(e.value).lower()


def test_rejects_non_hprof_binary():
    with pytest.raises(ValueError):
        _parse(bytes([1, 2, 3, 4]) * 40)


def test_histogram_counts_instances():
    b = HprofBuilder()
    foo = b.load_class("com.example.Foo")
    b.class_dump(foo)
    for _ in range(10):
        b.instance(foo, body=b"\x00" * 16)
    a = _parse(b.build())
    entry = next(e for e in a.top_classes_by_count if e.class_name == "com.example.Foo")
    assert entry.instance_count == 10
    assert a.total_instances == 10
    assert a.header.startswith("JAVA PROFILE")
    assert a.identifier_size == 8


def _static_leak_dump():
    """SessionRegistry with a static collection (SESSIONS) and a static logger (LOG),
    plus enough ConcurrentHashMap$Node to make the heap look container-dominated."""
    b = HprofBuilder()
    reg = b.load_class("com.example.SessionRegistry")
    chm = b.load_class("java.util.concurrent.ConcurrentHashMap")
    node = b.load_class("java.util.concurrent.ConcurrentHashMap$Node")
    logger = b.load_class("org.slf4j.Logger")
    b.class_dump(chm)
    b.class_dump(node)
    b.class_dump(logger)
    chm_oid = b.instance(chm)
    log_oid = b.instance(logger)
    b.class_dump(reg, static_object_fields=[("SESSIONS", chm_oid), ("LOG", log_oid)])
    for _ in range(200):
        b.instance(node, body=b"\x00" * 24)
    return b.build()


def test_static_field_finder_with_source(source_index):
    a = _parse(_static_leak_dump(), source=source_index)
    leak = [f for f in a.findings if "SESSIONS" in f.title]
    assert leak, "expected a SESSIONS leak-suspect finding"
    f = leak[0]
    assert f.severity == Severity.WARNING
    locs = {(loc.method, loc.repo_path) for loc in f.source_locations}
    assert any(m == "SESSIONS" and rp and rp.endswith("SessionRegistry.java")
               for m, rp in locs)
    # The static logger must NOT be flagged as a leak.
    all_methods = {loc.method for ff in a.findings for loc in ff.source_locations}
    assert "LOG" not in all_methods


def test_static_field_finder_without_source_emits_info():
    a = _parse(_static_leak_dump())
    info = [f for f in a.findings if "static field" in f.title.lower()]
    assert info, "expected an INFO nudge listing static object fields"
    assert info[0].severity == Severity.INFO
    assert any("SESSIONS" in e for e in info[0].evidence)


def test_quick_mode_truncates(monkeypatch):
    # max_bytes set => parser stops early and tracer is skipped; should not raise.
    a = _parse(_static_leak_dump(), max_bytes=64)
    assert a.header.startswith("JAVA PROFILE")


def test_quick_mode_declares_itself_partial():
    """A sampled prefix must never be presented as a whole-heap analysis."""
    a = _parse(_static_leak_dump(), max_bytes=64)
    assert a.truncated is True
    assert a.analyzed_bytes < a.file_size_bytes
    assert a.summary.startswith("PARTIAL")
    warn = [f for f in a.findings if f.title.startswith("Partial analysis")]
    assert warn and warn[0].severity == Severity.WARNING
    # and the stages that need the whole file must say why they didn't run
    stages = {s.stage for s in a.skipped_analyses}
    assert any("dominator tree" in s for s in stages)


def test_quick_mode_stops_inside_a_heap_segment():
    """HotSpot writes the heap as a few enormous HEAP_DUMP_SEGMENT records. A byte
    budget honoured only between top-level records would read the whole file — so
    quick mode has to be able to bail out mid-segment."""
    b = HprofBuilder()
    c = b.load_class("com.example.Wide")
    b.class_dump(c)
    for _ in range(60_000):
        b.instance(c, body=b"\x00" * 16)
    data = b.build()

    a = _parse(data, max_bytes=50_000, progress_interval_records=500)
    assert a.truncated is True
    # It must actually stop, not merely report that it should have.
    assert a.analyzed_bytes < len(data) // 2
    assert a.total_instances < 60_000


def test_full_parse_is_not_marked_partial():
    a = _parse(_static_leak_dump())
    assert a.truncated is False
    assert a.analyzed_bytes == a.file_size_bytes
    assert not [f for f in a.findings if f.title.startswith("Partial analysis")]
    assert a.sizing_model  # the layout assumption is always reported


def test_total_strings_counts_string_instances_not_symbols():
    """`total_strings` used to report the hprof symbol table (class/field names),
    which has nothing to do with how many Strings are on the heap."""
    b = HprofBuilder()
    s = b.load_class("java.lang.String")
    b.class_dump(s)
    for _ in range(7):
        b.instance(s, body=b"\x00" * 8)
    a = _parse(b.build())
    assert a.total_strings == 7
    # the symbol table is now reported separately, and is a different number
    assert a.total_utf8_records == 1
