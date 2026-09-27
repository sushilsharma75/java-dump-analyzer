import gzip
import io
import pytest

from app.analyzers.heap_index import build_index, retained
from app.analyzers import heap_queries as q
from app.analyzers.heap_input import native_input, detect_format
from app.analyzers.source import SourceIndex
from hprof_builder import HprofBuilder


@pytest.fixture
def graph(tmp_path):
    b = HprofBuilder()
    leaf = b.load_class('example.Leaf')
    owner = b.load_class('example.Owner')
    b.class_dump(leaf)
    b.class_dump(owner, instance_fields=[('value', b.OBJECT)])
    shared = b.instance(leaf)
    a = b.instance(owner, refs=[shared])
    c = b.instance(owner, refs=[shared])
    lost = b.instance(leaf)
    b.gc_root(a); b.gc_root(c)
    db = tmp_path / 'heap.sqlite'
    build_index(io.BytesIO(b.build()), db)
    retained(db)
    return db, hex(a), hex(c), hex(shared), hex(lost)


def test_group_retained_set_includes_shared_child_without_double_count(graph):
    db, a, b, shared, _ = graph
    one = q.retained_set(db, [a], view='objects')
    both = q.retained_set(db, [a, b, a], view='objects')
    assert shared not in {r['oid'] for r in one['rows']}
    assert {a, b, shared} <= {r['oid'] for r in both['rows']}
    assert both['object_count'] == len(both['rows'])
    assert both['retained_bytes'] == sum(r['shallow_bytes'] for r in both['rows'])


def test_dominator_navigation_and_missing_retention(graph):
    db, a, _, _, lost = graph
    result = q.dominators(db, limit=1)
    assert len(result['rows']) == 1 and result['total'] >= 3
    assert q.dominators(db, a)['parent_of_parent'] == '0x0'
    with pytest.raises(q.Unavailable):
        q.retained_set(db, [lost])
    with q.connect(db) as conn:
        conn.execute("DELETE FROM meta WHERE key='dominators_complete'")
    with pytest.raises(q.Unavailable):
        q.dominators(db)


def test_histogram_finds_classes_outside_top_thirty():
    data = {'histogram_complete': True, 'histogram': [dict(class_name=f'p.C{i}', instance_count=1, shallow_size_bytes=i) for i in range(100)]}
    assert q.histogram(data, query='p.C0')['rows'][0]['class_name'] == 'p.C0'
    assert q.histogram(data, group='package')['rows'][0]['instance_count'] == 100
    assert q.histogram(data, offset=95, limit=10)['total'] == 100
    assert not q.histogram({'top_classes_by_size': data['histogram'][:30]})['complete']


def test_group_suspects_and_unreachable_histogram(graph):
    db, a, b, _, _ = graph
    result = q.suspects(db, threshold=0, min_bytes=0)
    group = next(r for r in result['rows'] if r['kind'] == 'group')
    assert set(group['sample_ids']) == {a, b}
    assert group['instance_count'] == 2
    assert q.unreachable(db)['rows'][0]['instance_count'] == 1
    assert q.root_browser(db)['total'] == 2
    assert q.loaders(db)['rows'][0]['instance_count'] == 4


def test_gzip_uses_expanded_size_and_rejects_other_formats(tmp_path):
    b = HprofBuilder(); c = b.load_class('X'); b.class_dump(c); b.instance(c)
    path = tmp_path / 'misleading.phd'
    path.write_bytes(gzip.compress(b.build()))
    with native_input(path, 100000) as (fp, info):
        assert fp.read() == b.build()
        assert info['compression'] == 'gzip'
    with pytest.raises(ValueError, match='Expanded heap'):
        with native_input(path, 10): pass
    path.write_bytes(b'\x00\x12portable heap dump')
    assert detect_format(path.read_bytes()) == 'openj9_phd'
    with pytest.raises(ValueError, match='not yet implemented'):
        with native_input(path, 10000): pass


def test_source_operations_bind_fields_and_exclude_shadowing(tmp_path):
    (tmp_path / 'Cache.java').write_text('''package example;
import java.util.Map;
class Cache {
  Map<String,Object> entries;
  void save(Object o) { entries.put("key", o); }
  void release() { this.entries.clear(); }
  void shadow(Map<String,Object> entries) { entries.put("wrong", null); this.entries.remove("key"); }
  void clear() { entries = null; }
  void other(Cache other) { other.entries.put("other", null); }
  // entries.put("comment", null);
}''')
    source = SourceIndex(tmp_path); source.build()
    if not source.provenance['java_ast_files']:
        pytest.skip('JDK compiler unavailable')
    result = source.field_investigation('example.Cache', 'entries')
    assert result['write_count'] == 1
    assert result['cleanup_count'] == 3
    assert not any(op['method'] == 'other' for op in result['operations'])
    assert len([op for op in result['operations'] if op['method'] == 'shadow']) == 1
    (tmp_path / 'Cache.java').write_text('changed')
    assert source.field_investigation('example.Cache', 'entries')['status'] == 'unresolved'


def test_query_budget_errors_not_silently_zero(graph, monkeypatch):
    db, *_ = graph
    with pytest.raises(ValueError): q.retained_set(db, [])
    with pytest.raises(ValueError): q.merged_paths(db, ['0x1'] * 21)
    with pytest.raises(ValueError): q.waste(db, 'sql')
