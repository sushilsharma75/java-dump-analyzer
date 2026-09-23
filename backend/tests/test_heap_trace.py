import io
import json
import shutil

import pytest

from app.analyzers.heap_index import build_index, connect, root_paths
from app.analyzers.source import SourceIndex
from hprof_builder import HprofBuilder


@pytest.fixture
def trace_fixture(tmp_path):
    src = tmp_path / 'src'
    src.mkdir()
    (src / 'Cache.java').write_text('''package sample;
class Cache {
    static Object retained;
    void store(Object value) {
        retained = value;
    }
    static class Other {
        void store(Object value) { }
    }
}
''')
    source = SourceIndex(src)
    source.build()
    b = HprofBuilder()
    cache = b.load_class('sample.Cache')
    leaf = b.load_class('sample.Leaf')
    b.class_dump(leaf)
    target = b.instance(leaf)
    b.class_dump(cache, static_object_fields=[('retained', target)])
    b.gc_root(cache, 'sticky_class')
    path = tmp_path / 'heap.sqlite'
    build_index(io.BytesIO(b.build()), path)
    return path, source, hex(cache), hex(target)


def test_static_trace_includes_declaring_source_and_method_candidates(trace_fixture):
    path, source, owner, target = trace_fixture
    data = root_paths(path, target, source=source)
    edge = data['paths'][0]['edges'][0]
    assert edge['owner']['name'] == 'sample.Cache'
    assert edge['target']['name'] == 'sample.Leaf'
    assert edge['source']['class_name'] == 'sample.Cache'
    assert edge['source']['line'] == 3
    assert not edge['source']['build_verified']
    if shutil.which('javac'):
        methods = edge['source']['context']['related_field_methods']
        assert [m['method'] for m in methods] == ['store']
        assert 'retained = value;' in '\n'.join(methods[0]['lines'])
    assert data['paths'][0]['root'][0]['kind_name'] == 'Sticky class'


def test_local_root_connects_frame_index_to_correct_trace(trace_fixture):
    path, source, owner, target = trace_fixture
    with connect(path) as db:
        db.execute('DELETE FROM roots')
        db.execute("INSERT INTO roots VALUES(?, '0x3', 7, 0)", (target,))
        db.execute("INSERT INTO roots VALUES(?, '0x8', 7, 91)", (owner,))
        db.execute("INSERT INTO strings VALUES('method-test', 'store')")
        db.execute("INSERT INTO strings VALUES('file-test', 'Cache.java')")
        serial = db.execute('SELECT serial FROM class_serial WHERE cid=?', (owner,)).fetchone()[0]
        db.execute("INSERT INTO frames VALUES('frame-test', 'method-test', 'file-test', ?, 5)", (serial,))
        db.execute('INSERT INTO traces VALUES(91, 7, ?)', (json.dumps(['frame-test']),))
    result = root_paths(path, target, source=source)
    root = result['paths'][0]['root'][0]
    assert result['paths'][0]['edges'] == []
    assert root['frames'][0]['holds_root']
    loc = root['frames'][0]['source']
    assert loc['role'] == 'executing_frame'
    assert loc['context']['method']['start_line'] == 4
    assert 'retained = value;' in '\n'.join(loc['context']['method']['lines'])


def test_refresh_clears_stale_source(trace_fixture):
    from app.analyzers.heap_trace import enrich_root_paths
    path, source, owner, target = trace_fixture
    result = root_paths(path, target, source=source)
    (source.root / 'Cache.java').write_text('class Changed {}')
    enrich_root_paths(path, result, source)
    edge = result['paths'][0]['edges'][0]
    assert 'source' not in edge
    assert edge['source_status'] == 'field_unresolved'


def test_context_does_not_select_sibling_class_method(trace_fixture):
    _, source, _, _ = trace_fixture
    context = source.context('sample.Cache', 'store')
    assert context['method']['start_line'] == 4
