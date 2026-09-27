import gzip

import pytest
from fastapi.testclient import TestClient
from app.main import app
from app import artifacts
from hprof_builder import HprofBuilder


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(artifacts, 'ROOT', tmp_path)
    with TestClient(app) as client:
        yield client


def sample():
    b = HprofBuilder()
    cls = b.load_class('example.Cache'); leaf = b.load_class('example.Item')
    b.class_dump(leaf)
    obj = b.instance(leaf)
    b.class_dump(cls, static_object_fields=[('entries', obj)])
    b.gc_root(cls, 'sticky_class')
    return b.build(), hex(obj)


def test_queries_notes_exports_and_missing_indexes(client):
    raw, oid = sample()
    response = client.post('/api/analyze/heap', files={'file': ('test.gz', gzip.compress(raw))})
    assert response.status_code == 200, response.text
    data = response.json(); identifier = data['analysis_id']
    assert data['input_format']['compression'] == 'gzip'
    base = f'/api/heap/{identifier}'
    for endpoint in ['histogram', 'dominators', 'roots', 'loaders', 'suspects?threshold=0&min_bytes=0', 'unreachable', 'waste?query=constant_arrays', 'waste?query=references', 'waste?query=threadlocals', 'waste?query=duplicate_strings']:
        result = client.get(f'{base}/{endpoint}')
        assert result.status_code == 200, result.text
        assert 'rows' in result.json()
    assert client.get(f'{base}/histogram?sort=DROP').status_code == 422
    assert client.post(f'{base}/retained-set', json={'objects': [oid]}).status_code == 200
    assert client.post(f'{base}/merged-paths', json={'objects': [oid]}).status_code == 200
    assert client.post(f'{base}/retained-set', json={'objects': ['missing']}).status_code == 409
    assert client.put(f'{base}/notes', json={'text': 'Follow cleanup', 'bookmarks': [oid]}).status_code == 200
    assert client.get(f'/api/analyses/{identifier}').json()['analysis']['investigation_notes']['text'] == 'Follow cleanup'
    csv = client.get(f'{base}/histogram.csv?query=Item')
    assert 'example.Item' in csv.text and 'example.Cache' not in csv.text
    assert csv.headers['x-histogram-complete'] == 'true'
    data['object_index_id'] = None; artifacts.save(data, 'heap')
    assert client.get(f'{base}/dominators').status_code == 409
    assert client.get(f'{base}/histogram').status_code == 200
