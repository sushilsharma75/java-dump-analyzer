"""Exercise visible checkpoints while the worker is still inside retention tracing."""
import json
import threading
import time

import pytest
from fastapi.testclient import TestClient

from app import artifacts
from app.main import app
from app.sessions import JOBS
from app.heap_jobs import HeapCancelled, HeapRun, ScanStream
from app.schemas import Finding, Severity
from tests.hprof_builder import HprofBuilder


@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.setattr(artifacts, 'ROOT', tmp_path)
    monkeypatch.setenv('HEAP_INDEX_MAX_BYTES', '0')
    monkeypatch.setenv('HEAP_DOMINATOR', '0')
    monkeypatch.setenv('HEAP_WASTE_TRACE', '0')
    b = HprofBuilder()
    cls = b.load_class('example.Item')
    b.class_dump(cls)
    b.instance(cls)
    path = tmp_path / 'input.hprof'
    path.write_bytes(b.build())
    with TestClient(app) as client:
        yield client, path


def wait_terminal(client, jid):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        job = client.get(f'/api/jobs/{jid}').json()
        if job['status'] not in ('queued', 'running'):
            return job
        time.sleep(.01)
    pytest.fail('Heap worker did not terminate')


def test_report_is_readable_before_tracing_finishes_and_notes_survive(setup, monkeypatch):
    client, path = setup
    entered, release = threading.Event(), threading.Event()
    def trace(fp, *args, **kwargs):
        entered.set()
        assert release.wait(5)
        return Finding(severity=Severity.WARNING, category='memory', title='Background retention finding', description='Completed trace')
    monkeypatch.setattr('app.analyzers.heap_graph.trace_retention', trace)
    jid = client.post('/api/analyze/heap/path', json={'path': str(path), 'deep': True}).json()['job_id']
    try:
        assert entered.wait(5)
        job = client.get(f'/api/jobs/{jid}').json()
        assert job['status'] == 'running' and job['stage'] == 'Tracing retention'
        initial = job['result']
        identifier = initial['analysis_id']
        assert initial['histogram_complete'] and initial['total_instances'] == 1
        assert any(s['status'] == 'pending' for s in initial['stages'])
        assert initial['verdict'] != 'healthy'
        assert client.get(f'/api/heap/{identifier}/histogram').json()['rows']
        assert client.get(f'/api/jobs/{jid}?include_result=false').json()['result'] is None
        assert client.delete(f'/api/analyses/{identifier}').status_code == 409
        client.put(f'/api/heap/{identifier}/notes', json={'text': 'Keep this', 'bookmarks': ['0x1']}).raise_for_status()
        client.post(f'/api/analyses/{identifier}/capture', json={'build_id': 'custom-build'}).raise_for_status()
    finally:
        release.set()
    final = wait_terminal(client, jid)
    assert final['status'] == 'done'
    assert final['result']['analysis_id'] == identifier
    assert final['revision'] > job['revision']
    assert final['result']['investigation_notes']['text'] == 'Keep this'
    assert final['result']['capture']['build_id'] == 'custom-build'
    assert any(f['title'] == 'Background retention finding' for f in final['result']['findings'])
    assert not any(f['title'] == 'Background retention finding' for f in initial['findings'])
    assert all(s['status'] != 'pending' for s in final['result']['stages'])
    # Terminal SSE contains metadata, not a repeatedly transmitted histogram.
    event = client.get(f'/api/jobs/{jid}/events')
    assert event.headers['content-type'].startswith('text/event-stream')
    payload = json.loads(event.text.split('data: ', 1)[1])
    assert payload['status'] == 'done' and payload['result'] is None
    # Finished jobs may leave memory; reports and terminal metadata remain available.
    JOBS.remove(jid)
    assert client.get(f'/api/jobs/{jid}').json()['result']['analysis_id'] == identifier


def test_cancel_escapes_tracer_preserves_report_and_releases_file(setup, monkeypatch):
    client, path = setup
    entered = threading.Event()
    def trace(fp, *args, **kwargs):
        entered.set()
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            fp.seek(0)
            fp.read(8)
            time.sleep(.001)
        pytest.fail('Cancellation did not interrupt file scanning')
    monkeypatch.setattr('app.analyzers.heap_graph.trace_retention', trace)
    jid = client.post('/api/analyze/heap/path', json={'path': str(path)}).json()['job_id']
    assert entered.wait(5)
    response = client.post(f'/api/jobs/{jid}/cancel')
    assert response.status_code == 200
    job = wait_terminal(client, jid)
    assert job['status'] == 'cancelled'
    assert job['result']['histogram_complete']
    assert any(s['status'] == 'cancelled' for s in job['result']['stages'])
    assert job['result']['background_job']['status'] == 'cancelled'
    assert path.exists()  # Server-side inputs are never deleted.
    path.rename(path.with_suffix('.kept'))  # File handle was released (also on Windows).


def test_failure_keeps_histogram_and_restart_is_explicit(setup, monkeypatch):
    client, path = setup
    from app import main
    original = main.parse_heap_dump
    def fail_after_checkpoint(*args, **kwargs):
        callback = kwargs['report_callback']
        def report(result):
            callback(result)
            raise RuntimeError('worker failed after saving histogram')
        kwargs['report_callback'] = report
        return original(*args, **kwargs)
    monkeypatch.setattr(main, 'parse_heap_dump', fail_after_checkpoint)
    jid = client.post('/api/analyze/heap/path', json={'path': str(path)}).json()['job_id']
    job = wait_terminal(client, jid)
    assert job['status'] == 'error' and job['result']['histogram_complete']
    assert job['result']['background_job']['status'] == 'error'
    JOBS.remove(jid)
    metadata = artifacts.path_for(jid, '.job')
    persisted = json.loads(metadata.read_text())
    persisted['status'] = 'running'
    metadata.write_text(json.dumps(persisted))
    restored = client.get(f'/api/jobs/{jid}').json()
    assert restored['status'] == 'interrupted'
    report = client.get(f"/api/analyses/{job['analysis_id']}").json()['analysis']
    assert report['background_job']['status'] == 'interrupted'
    assert report['histogram_complete']


def test_scan_progress_counts_rewinds_and_cancellation(tmp_path, monkeypatch):
    monkeypatch.setattr(artifacts, 'ROOT', tmp_path)
    path = tmp_path / 'scan.bin'
    path.write_bytes(b'a' * 100)
    jid = JOBS.create(100)
    JOBS.mark_running(jid)
    run = HeapRun(jid, 'a' * 32)
    run.stage('Tracing retention')
    with path.open('rb') as fp:
        stream = ScanStream(fp, run)
        stream.read(100)
        assert JOBS.get(jid)['scan_bytes'] == 100
        stream.seek(0)
        assert JOBS.get(jid)['scan_pass'] == 2
        assert JOBS.get(jid)['scan_bytes'] == 0
        JOBS.cancel(jid)
        with pytest.raises(HeapCancelled):
            stream.read(1)
    run.finish('cancelled')


def test_stage_counter_updates_preserve_scan_progress(tmp_path, monkeypatch):
    monkeypatch.setattr(artifacts, 'ROOT', tmp_path)
    jid = JOBS.create(100)
    JOBS.mark_running(jid)
    run = HeapRun(jid, 'b' * 32)
    try:
        run.stage('Indexing object records')
        run.progress(40, 100, new_pass=True)
        started = JOBS.get(jid)['stage_started_at']
        for count in (10000, 20000, 30000):
            message = f'Indexing object records: {count:,}'
            run.stage(message)
            job = JOBS.get(jid)
            assert job['stage'] == message
            assert job['stage_started_at'] == started
            assert (job['scan_pass'], job['scan_bytes'], job['scan_total']) == (1, 40, 100)
        run.progress(0, 100, new_pass=True)
        assert JOBS.get(jid)['scan_pass'] == 2
        run.stage('Decoding object references')
        job = JOBS.get(jid)
        assert (job['scan_pass'], job['scan_bytes'], job['scan_total']) == (0, 0, 0)
        run.progress(10, 100)
        assert JOBS.get(jid)['scan_bytes'] == 10
    finally:
        run.finish('cancelled')
        JOBS.remove(jid)


def test_gzip_upload_checkpoints_use_expanded_size_and_cleanup(setup, monkeypatch):
    import gzip
    from app import main
    client, path = setup
    monkeypatch.setattr(main, 'TMP_DIR', path.parent)
    raw = path.read_bytes()
    response = client.post('/api/analyze/heap/async', files={'file': ('heap.gz', gzip.compress(raw))})
    assert response.status_code == 200
    job = wait_terminal(client, response.json()['job_id'])
    assert job['status'] == 'done'
    assert job['bytes_total'] == len(raw)
    assert job['result']['histogram_complete']
    assert job['result']['input_format']['compression'] == 'gzip'
    assert not (path.parent / f"heap_{job['job_id']}.hprof").exists()


def test_sql_work_honors_worker_cancellation(tmp_path):
    import sqlite3
    from app.analyzers.heap_control import cancel_requested
    from app.analyzers.heap_index import connect
    cancel = threading.Event()
    token = cancel_requested.set(cancel.is_set)
    try:
        db = connect(tmp_path / 'cancel.sqlite')
        try:
            cancel.set()
            with pytest.raises(sqlite3.OperationalError, match='interrupted'):
                db.execute('WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<1000000) SELECT sum(x) FROM n').fetchone()
        finally:
            db.close()
    finally:
        cancel_requested.reset(token)


def test_retention_budget_finishes_job_with_saved_histogram(setup, monkeypatch):
    from app.analyzers import heap_graph
    from app.analyzers.heap_control import analysis_deadline
    client, path = setup
    original = heap_graph.trace_retention
    def expired_trace(*args, **kwargs):
        analysis_deadline.set(time.monotonic() - 1)
        return original(*args, **kwargs)
    monkeypatch.setattr(heap_graph, 'trace_retention', expired_trace)
    jid = client.post('/api/analyze/heap/path', json={'path': str(path), 'deep': True}).json()['job_id']
    job = wait_terminal(client, jid)
    assert job['status'] == 'done'
    assert job['result']['histogram_complete']
    assert job['result']['background_job']['status'] == 'done'
    assert all(s['status'] != 'pending' for s in job['result']['stages'])
    stage = next(s for s in job['result']['stages'] if s['stage'].startswith('retention tracing'))
    assert stage['status'] == 'partial' and 'time budget' in stage['reason']
    assert job['result']['verdict'] != 'healthy'
