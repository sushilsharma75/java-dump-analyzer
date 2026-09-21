"""DBDoctor integration and diagnostic regressions."""
import copy
import json
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from app import artifacts
from app.database import analyze_snapshot, correlate_database
from app.main import app
from app.vendor.dbdoctor.engine.models import Snapshot
from app.vendor.dbdoctor.engine.run import run_all


def sample(name='pg_full.json'):
    return json.loads((Path(__file__).parents[1] / 'samples/database' / name).read_text())


@pytest.mark.parametrize('name', ['pg_full.json', 'mysql_full.json', 'minimal_snapshot.json'])
def test_fixtures(name):
    result = analyze_snapshot(sample(name))
    assert result['findings'] and result['coverage']
    assert len({f['evidence_id'] for f in result['findings']}) == len(result['findings'])
    json.dumps(result, allow_nan=False)


def test_missing_is_not_healthy():
    result = analyze_snapshot({'meta': sample()['meta']})
    assert result['status'] == 'partial'
    assert all(c['status'] == 'missing' for c in result['coverage'])
    assert 'not a health' in result['score_label']


@pytest.mark.parametrize('value', [-1, float('nan'), float('inf')])
def test_invalid_numbers(value):
    data = sample(); data['queries'][0]['total_time_ms'] = value
    with pytest.raises(ValidationError): analyze_snapshot(data)


def test_delta_rates_and_identity():
    previous = sample(); current = copy.deepcopy(previous)
    previous['meta']['collected_at'] = '2026-07-01T00:00:00Z'
    current['meta']['collected_at'] = '2026-07-02T00:00:00Z'
    current['queries'][0]['calls'] += 100
    result = analyze_snapshot(current, previous)
    assert result['snapshot']['queries'][0]['calls_per_day'] == 100
    current['meta']['host_alias'] = 'another-db'
    with pytest.raises(ValueError, match='host_alias'): analyze_snapshot(current, previous)


def test_bad_capture_and_delta_baseline():
    data = sample(); data['meta']['collected_at'] = '2026-07-01T00:00:00'
    with pytest.raises(ValueError, match='timezone'): analyze_snapshot(data)
    data = sample(); older = copy.deepcopy(data); older['meta']['is_delta'] = True
    with pytest.raises(ValueError, match='cumulative'): analyze_snapshot(data, older)


def idx(name, definition='(email)', **kw):
    return dict(table='public.users', name=name, definition=definition, size_bytes=200*1024**2, **kw)


def index_findings(indexes):
    return run_all(Snapshot.model_validate({'meta': sample()['meta'], 'indexes': indexes})).findings


def test_unknown_scans_not_zero():
    assert not [f for f in index_findings([idx('a')]) if f.rule_id == 'R-I2']


@pytest.mark.parametrize('definition', [
    'CREATE INDEX b ON public.users USING btree (email) WHERE active',
    'CREATE INDEX b ON public.users USING hash (email)',
    'CREATE INDEX b ON public.users USING btree (email DESC)',
    'CREATE INDEX b ON public.users USING btree (lower(email))',
    'CREATE INDEX b ON public.users USING btree (email) INCLUDE (name)',
])
def test_index_semantics(definition):
    assert not [f for f in index_findings([idx('a'), idx('b', definition)]) if f.rule_id == 'R-I3']


def test_unique_not_dropped():
    assert not [f for f in index_findings([idx('a', is_unique=True), idx('b', '(email, name)')]) if f.rule_id == 'R-I3']


def test_query_claims():
    result = analyze_snapshot(sample())
    f = next(f for f in result['findings'] if f['rule_id'] == 'R-Q1')
    assert 'pct_of_captured_query_time' in f['evidence'] and 'captured' in f['title']


def test_correlation_gates():
    db = analyze_snapshot(sample())
    thread = {'threads': [{'name': 'worker', 'state': 'RUNNABLE', 'stack': [{'class_name': 'org.postgresql.core.QueryExecutorImpl', 'method': 'execute'}]}]}
    assert correlate_database(db, thread, False)['status'] == 'blocked'
    assert correlate_database(db, thread, True)['status'] == 'blocked'
    thread['capture'] = {'captured_at': db['collected_at']}
    assert correlate_database(db, thread, True)['status'] == 'leads'
    thread['capture']['captured_at'] = '2000-01-01T00:00:00Z'
    assert correlate_database(db, thread, True)['status'] == 'blocked'


def test_api_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(artifacts, 'ROOT', tmp_path)
    with TestClient(app) as client:
        r = client.post('/api/analyze/database', files={'file': ('snapshot.json', json.dumps(sample()))})
        assert r.status_code == 200, r.text
        identifier = r.json()['analysis_id']
        assert client.get('/api/analyses').json()[0]['kind'] == 'database'
        assert client.get(f'/api/analyses/{identifier}').json()['analysis']['findings']
        for invalid in ['{', '{"meta": {"password": "secret"}}']:
            r = client.post('/api/analyze/database', files={'file': ('bad.json', invalid)})
            assert r.status_code == 422 and 'secret' not in r.text
        assert client.get('/api/database/collectors/pg_collect.py').status_code == 200
        assert client.get('/api/database/collectors/main.py').status_code == 404
        assert client.delete(f'/api/analyses/{identifier}').status_code == 200
        assert client.get(f'/api/analyses/{identifier}').status_code == 404


def test_api_limit(monkeypatch):
    from app import database
    monkeypatch.setattr(database, 'MAX_SNAPSHOT_BYTES', 32)
    with TestClient(app) as client:
        assert client.post('/api/analyze/database', files={'file': ('big.json', ' '*33)}).status_code == 413


def test_delta_preserves_missing_coverage():
    current = {'meta': sample()['meta']}
    previous = copy.deepcopy(current)
    previous['meta']['collected_at'] = '2000-01-01T00:00:00Z'
    result = analyze_snapshot(current, previous)
    assert all(c['status'] == 'missing' for c in result['coverage'])


def test_nonfinite_config_setting():
    data = sample(); data['settings'] = [{'name': 'max_connections', 'value': 'NaN'}]
    with pytest.raises(ValidationError): analyze_snapshot(data)


def test_duplicate_digests_cannot_be_compared():
    data = sample(); data['queries'].append(copy.deepcopy(data['queries'][0]))
    with pytest.raises(ValueError, match='duplicate'): analyze_snapshot(data, data)


def test_ambiguous_table_does_not_bind():
    from app.vendor.dbdoctor.engine.rules.index_rules import _resolved_table
    data = sample('minimal_snapshot.json')
    other = copy.deepcopy(data['tables'][0]); other['schema_name'] = 'archive'
    data['tables'].append(other)
    snapshot = Snapshot.model_validate(data)
    assert _resolved_table(snapshot, 'SELECT * FROM orders WHERE id = ?') is None
    assert _resolved_table(snapshot, 'SELECT * FROM public.orders WHERE id = ?') == 'public.orders'
    assert _resolved_table(snapshot, 'SELECT * FROM public.orders JOIN users ON x = y') is None
