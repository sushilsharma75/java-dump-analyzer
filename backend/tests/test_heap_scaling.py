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


def test_default_index_and_dominators_cross_old_size_cutoff(tmp_path, monkeypatch):
    import struct
    data, _ = fixture()
    for setting in ('HEAP_INDEX_MAX_BYTES', 'HEAP_INDEX_MAX_OBJECTS',
                    'HEAP_DOMINATOR_MAX_BYTES', 'HEAP_DOMINATOR_MAX_OBJECTS'):
        monkeypatch.delenv(setting, raising=False)
    # Unknown top-level extension payloads are skipped by both parsers. Sparse
    # records exercise real large-file offsets without hashing GiB of arrays.
    with (tmp_path / 'large.hprof').open('w+b') as fp:
        fp.write(data)
        for _ in range(2):
            length = 3 * 1024**3
            fp.write(struct.pack('>BII', 0x77, 0, length))
            fp.seek(length - 1, 1)
            fp.write(b'\0')
        fp.seek(0)
        result = parse_heap_dump(fp, index_path=tmp_path / 'graph.sqlite')
    assert result.dominators
    assert any(s.stage == 'object index' and s.status == 'completed' for s in result.stages)
    assert not any(s.stage.startswith(('object index', 'dominator')) for s in result.skipped_analyses)


def test_failed_index_is_not_built_again_for_dominators(tmp_path, monkeypatch):
    data, _ = fixture()
    calls = []
    def fail(*args, **kwargs):
        calls.append(True)
        raise OSError('test disk full')
    monkeypatch.setattr('app.analyzers.heap_index.build_index', fail)
    result = parse_heap_dump(io.BytesIO(data), index_path=tmp_path / 'graph.sqlite')
    assert len(calls) == 1
    assert any(s.stage.startswith('dominator') and 'test disk full' in s.reason for s in result.skipped_analyses)


def test_deadline_preserves_full_histogram_and_finishes_all_stages(tmp_path, monkeypatch):
    from app.analyzers import heap_control
    data, _ = fixture()
    clock = [0.0]
    monkeypatch.setattr(heap_control.time, 'monotonic', lambda: clock[0])
    monkeypatch.setenv('HEAP_ANALYSIS_MAX_SECONDS', '1')
    checkpoints = []

    def report(result):
        checkpoints.append(result)
        clock[0] = 2.0  # Histogram consumed the budget; never truncate it.

    result = parse_heap_dump(io.BytesIO(data), index_path=tmp_path / 'graph.sqlite',
                             report_callback=report, deep=True)
    assert result.histogram_complete and result.total_instances == 10
    assert checkpoints[0].histogram_complete
    assert all(s.status != 'pending' for s in result.stages)
    assert any(s.status == 'partial' and 'time budget' in s.reason for s in result.stages)
    assert not (tmp_path / 'graph.sqlite').exists()
    assert heap_control.analysis_deadline.get() is None


def test_deadline_interrupts_sql_and_does_not_leak_to_next_run(tmp_path):
    from app.analyzers.heap_control import within_budget, HeapBudgetExceeded
    from app.analyzers.heap_index import connect
    import time
    db = connect(tmp_path / 'query.sqlite')
    try:
        with pytest.raises(HeapBudgetExceeded):
            with within_budget(time.monotonic() + .02):
                db.execute('WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<100000000) SELECT sum(x) FROM n').fetchone()
        assert db.execute('SELECT 1').fetchone()[0] == 1
    finally:
        db.close()


def test_expired_budget_interrupts_buffered_reference_walk():
    from app.analyzers.heap_control import within_budget, HeapBudgetExceeded
    from app.analyzers.heap_graph import _open, _walk
    from unittest.mock import patch
    data, _ = fixture(20_000)  # Fits in read-ahead; no further file read needed.
    reader, width = _open(io.BytesIO(data))
    clock = [0.0]
    def expire(oid, cid):
        clock[0] = 2.0
    with patch('app.analyzers.heap_control.time.monotonic', lambda: clock[0]):
        with pytest.raises(HeapBudgetExceeded):
            with within_budget(1.0):
                _walk(reader, width, on_instance_header=expire)


def test_timed_out_index_is_removed_and_not_rebuilt(tmp_path, monkeypatch):
    from app.analyzers.heap_control import HeapBudgetExceeded
    data, _ = fixture()
    path = tmp_path / 'graph.sqlite'
    calls = []
    def fail(fp, path, **kwargs):
        calls.append(True)
        path.write_bytes(b'partial catalog')
        raise HeapBudgetExceeded('test time budget')
    monkeypatch.setattr('app.analyzers.heap_index.build_index', fail)
    result = parse_heap_dump(io.BytesIO(data), index_path=path)
    assert len(calls) == 1 and not path.exists()
    assert result.histogram_complete
    assert next(s for s in result.stages if s.stage == 'object index').status == 'partial'


def test_no_byte_or_char_arrays_avoids_waste_rescan(monkeypatch):
    data, _ = fixture()
    def fail(*args, **kwargs):
        pytest.fail('No byte/char arrays exist, so a duplicate-array pass is unnecessary')
    monkeypatch.setattr('app.analyzers.heap_waste.find_wasted_memory', fail)
    result = parse_heap_dump(io.BytesIO(data), deep=True)
    assert result.histogram_complete and result.wasted_bytes_estimate == 0


def test_failed_build_does_not_delete_existing_catalog(tmp_path):
    data, objects = fixture()
    path = tmp_path / 'existing.sqlite'
    build_index(io.BytesIO(data), path)
    result = parse_heap_dump(io.BytesIO(data), index_path=path)
    assert result.histogram_complete
    assert next(s for s in result.stages if s.stage == 'object index').status == 'failed'
    assert object_detail(path, hex(objects[0]))['values']['sample.Node.value'] == 0
