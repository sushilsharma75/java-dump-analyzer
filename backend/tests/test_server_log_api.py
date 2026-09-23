import asyncio
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request

from app import artifacts, server_logs
from app.main import app
from test_server_log import LOG
from hprof_builder import HprofBuilder


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(artifacts, 'ROOT', tmp_path)
    monkeypatch.setattr(server_logs, 'dump_directory', lambda: tmp_path)
    with TestClient(app) as c:
        yield c


def completed(client, job_id):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        response = client.get(f'/api/jobs/{job_id}')
        assert response.status_code == 200
        job = response.json()
        if job['status'] in ('done', 'error'):
            assert job['status'] == 'done', job.get('error')
            return job['result']
        time.sleep(.02)
    pytest.fail('Log job did not complete')


def upload(client, raw=LOG):
    response = client.post('/api/analyze/server-log?filename=server.log', content=raw,
                           headers={'Content-Type': 'application/octet-stream'})
    assert response.status_code == 200, response.text
    return completed(client, response.json()['job_id'])


def test_upload_persistence_query_source_incident_and_delete(client, tmp_path):
    report = upload(client)
    identifier = report['analysis_id']
    assert report['counts']['bytes'] == len(LOG)
    assert not list(tmp_path.glob('*.upload'))
    assert client.get(f'/api/analyses/{identifier}').json()['kind'] == 'server_log'
    events = client.get(f'/api/server-logs/{identifier}/events', params={'level': 'ERROR'}).json()['events']
    assert len(events) == 1
    assert client.get(f'/api/server-logs/{identifier}/events?limit=101').status_code == 422
    assert client.get(f'/api/server-logs/{identifier}/events?since=2026-09-22T00:00:00').status_code == 422
    src = tmp_path / 'source'; src.mkdir()
    (src / 'Cache.java').write_text('package com.example;\nclass Cache {\n Object value;\n void put() { value = new Object(); }\n}\n')
    source = client.post('/api/source/path', json={'path': str(src)}).json()['session_id']
    detailed = client.get(f'/api/server-logs/{identifier}/events/2', params={'source_session': source})
    assert detailed.status_code == 200
    assert detailed.json()['frames'][0]['source']['context']['method']['start_line'] == 4
    thread = client.post('/api/analyze/thread', files={'file': ('thread.txt',
        '"worker-1" #1 tid=0x1 nid=0x1 runnable\n java.lang.Thread.State: RUNNABLE\n at com.example.Cache.put(Cache.java:4)\n')}).json()
    b = HprofBuilder(); cls = b.load_class('com.example.Cache'); b.class_dump(cls); obj = b.instance(cls); b.gc_root(obj)
    heap = client.post('/api/analyze/heap', files={'file': ('heap.hprof', b.build())}).json()
    payload = {'server_log_id': identifier, 'thread_id': thread['analysis_id'], 'heap_id': heap['analysis_id'], 'source_session': source}
    result = client.post('/api/analyze/incident', json=payload)
    assert result.status_code == 200, result.text
    combined = result.json()
    assert combined['matches']
    assert combined['inputs']['heap'] == heap['analysis_id']
    assert not combined['coverage']['time_filter_applied']
    saved = client.get('/api/analyses/' + combined['analysis_id']).json()
    assert saved['kind'] == 'incident'
    assert saved['analysis']['matches'] == combined['matches']
    assert client.post('/api/analyze/incident', json={'server_log_id': identifier}).status_code == 422
    assert client.post('/api/analyze/incident', json={**payload, 'thread_id': identifier}).status_code == 422
    assert client.get(f'/api/server-logs/{identifier}/events/2?source_session=expired').status_code == 404
    client.delete(f'/api/analyses/{identifier}')
    assert not (tmp_path / (identifier + '.log.sqlite')).exists()
    assert client.get(f'/api/server-logs/{identifier}/events').status_code == 404


def test_upload_limit_early_and_streamed(client, tmp_path, monkeypatch):
    monkeypatch.setattr(server_logs, 'MAX_LOG_BYTES', 100)
    response = client.post('/api/analyze/server-log', content=b'x' * 101,
                           headers={'Content-Type': 'application/octet-stream'})
    assert response.status_code == 413
    assert not list(tmp_path.glob('*.upload'))
    # Exercise ASGI chunking without Content-Length, so the running count enforces the limit.
    chunks = iter([b'x' * 60, b'y' * 60])
    async def receive():
        chunk = next(chunks)
        return {'type': 'http.request', 'body': chunk, 'more_body': True}
    request = Request({'type': 'http', 'method': 'POST', 'headers': [(b'content-type', b'application/octet-stream')]}, receive)
    async def run():
        with pytest.raises(Exception) as raised:
            await server_logs.upload_log(request, filename='test.log')
        assert raised.value.status_code == 413
    asyncio.run(run())
    assert not list(tmp_path.glob('*.upload'))


def test_bad_uploads_and_failed_jobs_clean_up(client, tmp_path):
    assert client.post('/api/analyze/server-log', content=b'').status_code == 415
    assert client.post('/api/analyze/server-log', content=b'', headers={'Content-Type': 'text/plain'}).status_code == 400
    assert client.post('/api/analyze/server-log?timezone_offset=bad', content=LOG, headers={'Content-Type': 'text/plain'}).status_code == 422
    response = client.post('/api/analyze/server-log', content=b'\x1f\x8bcompressed', headers={'Content-Type': 'text/plain'})
    job_id = response.json()['job_id']
    for _ in range(100):
        job = client.get('/api/jobs/' + job_id).json()
        if job['status'] == 'error': break
        time.sleep(.02)
    assert job['status'] == 'error'
    assert not list(tmp_path.glob('*.upload'))
    assert not list(tmp_path.glob('*.log.sqlite'))


def test_cancel_in_progress_cleans_partial_index(client, tmp_path, monkeypatch):
    import threading
    entered = threading.Event()
    def blocked(fp, path, **kwargs):
        Path(path).write_bytes(b'partial')
        entered.set()
        for _ in range(500):
            if kwargs['cancelled']():
                raise server_logs.server_log.Cancelled()
            time.sleep(.01)
        raise AssertionError('Cancellation not delivered')
    monkeypatch.setattr(server_logs.server_log, 'build_log_index', blocked)
    response = client.post('/api/analyze/server-log', content=LOG, headers={'Content-Type': 'text/plain'})
    assert entered.wait(3)
    job_id = response.json()['job_id']
    assert client.delete('/api/jobs/' + job_id).status_code == 200
    for _ in range(100):
        if not list(tmp_path.glob('*.upload')): break
        time.sleep(.02)
    assert not list(tmp_path.glob('*.upload'))
    assert not list(tmp_path.glob('*.log.sqlite'))
    assert not list(tmp_path.glob('*.json'))


def test_startup_discards_interrupted_files_but_keeps_saved_indexes(tmp_path, monkeypatch):
    monkeypatch.setattr(artifacts, 'ROOT', tmp_path)
    monkeypatch.setattr(server_logs, 'dump_directory', lambda: tmp_path)
    orphan = 'd' * 32
    saved = 'e' * 32
    (tmp_path / f'log_{orphan}.upload').write_bytes(b'partial')
    (tmp_path / f'{orphan}.log.sqlite').write_bytes(b'partial')
    (tmp_path / f'{orphan}.log.sqlite-journal').write_bytes(b'partial')
    (tmp_path / f'{saved}.log.sqlite').write_bytes(b'keep')
    artifacts.save({'analysis_id': saved}, 'server_log')
    server_logs.discard_interrupted_log_jobs()
    assert not (tmp_path / f'log_{orphan}.upload').exists()
    assert not (tmp_path / f'{orphan}.log.sqlite').exists()
    assert not (tmp_path / f'{orphan}.log.sqlite-journal').exists()
    assert (tmp_path / f'{saved}.log.sqlite').exists()


def test_disconnect_removes_partial_upload(tmp_path, monkeypatch):
    from starlette.requests import ClientDisconnect
    monkeypatch.setattr(server_logs, 'dump_directory', lambda: tmp_path)
    messages = iter([{'type': 'http.request', 'body': b'partial', 'more_body': True}, {'type': 'http.disconnect'}])
    async def receive():
        return next(messages)
    req = Request({'type': 'http', 'method': 'POST', 'headers': [(b'content-type', b'text/plain')]}, receive)
    async def run():
        with pytest.raises(ClientDisconnect):
            await server_logs.upload_log(req, filename='test.log')
    asyncio.run(run())
    assert not list(tmp_path.glob('*.upload'))
