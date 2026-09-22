"""Guard runtime-sensitive behavior with deterministic I/O and policy checks."""
import io

import pytest

from app.analyzers.heap_dump import parse_heap_dump
from app.analyzers.heap_index import build_index, object_detail
from app.sessions import JobStore
from tests.hprof_builder import HprofBuilder


class CountingStream(io.BytesIO):
    def __init__(self, data):
        super().__init__(data)
        self.bytes_read = 0

    def read(self, n=-1):
        data = super().read(n)
        self.bytes_read += len(data)
        return data


def fixture(count=10):
    b = HprofBuilder()
    c = b.load_class('sample.Node')
    b.class_dump(c, instance_fields=[('value', b.INT)])
    objects = [b.instance(c, body=b.pack_fields([(b.INT, i)])) for i in range(count)]
    b.gc_root(objects[0])
    return b.build(), objects


def test_index_reads_sequentially_instead_of_rereading_per_object(tmp_path):
    data, objects = fixture(10_001)  # crosses catalog transaction boundary
    stream = CountingStream(data)
    path = tmp_path / 'graph.sqlite'
    stages = []
    build_index(stream, path, stage_callback=stages.append)
    assert stream.bytes_read <= 3 * len(data)
    assert object_detail(path, hex(objects[-1]))['values']['sample.Node.value'] == 10_000
    assert any(s.startswith('Decoding object references:') for s in stages)
    assert stages[-1] == 'Building reference lookup indexes'


@pytest.mark.parametrize('setting', ['HEAP_INDEX_MAX_BYTES', 'HEAP_INDEX_MAX_OBJECTS'])
def test_index_budget_preserves_full_report(tmp_path, monkeypatch, setting):
    data, _ = fixture()
    monkeypatch.setenv(setting, '1')
    monkeypatch.setenv('HEAP_DOMINATOR', '0')
    path = tmp_path / 'not-created.sqlite'
    result = parse_heap_dump(io.BytesIO(data), index_path=path)
    assert result.histogram_complete and result.total_instances == 10
    assert not path.exists()
    skipped = next(s for s in result.stages if s.stage == 'object index')
    assert skipped.status == 'skipped'
    assert any(s.stage == 'object index' for s in result.skipped_analyses)


def test_object_budget_also_protects_temporary_dominator_index(monkeypatch):
    data, _ = fixture()
    monkeypatch.setenv('HEAP_DOMINATOR_MAX_OBJECTS', '1')
    result = parse_heap_dump(io.BytesIO(data))
    assert result.histogram_complete and not result.dominators
    assert any(s.stage.startswith('dominator') and s.status == 'skipped' for s in result.stages)


def test_index_budget_can_be_explicitly_increased(tmp_path, monkeypatch):
    data, _ = fixture()
    monkeypatch.setenv('HEAP_INDEX_MAX_BYTES', str(len(data)))
    monkeypatch.setenv('HEAP_INDEX_MAX_OBJECTS', '10')
    result = parse_heap_dump(io.BytesIO(data), index_path=tmp_path / 'graph.sqlite')
    assert any(s.stage == 'object index' and s.status == 'completed' for s in result.stages)
    assert result.dominators


def test_post_parse_stages_have_no_false_zero_eta():
    store = JobStore()
    job = store.create(100)
    store.mark_running(job)
    stage = store.stage_callback(job)
    stage('Parsing heap records')
    progress = store.progress_callback(job)
    progress(50, 1, 1)
    assert store.get(job)['eta_seconds'] is not None
    progress(100, 2, 10)
    assert store.get(job)['eta_seconds'] is None
    stage('Computing retained sizes')
    assert store.get(job)['stage'] == 'Computing retained sizes'
    assert store.get(job)['eta_seconds'] is None
    store.mark_done(job, {})
    assert store.get(job)['stage'] == 'Complete'
