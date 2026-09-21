"""Stored routine source checks and conservative binding regressions."""
import json

import pytest
from app.database import analyze_snapshot


def document(body, engine='mysql', **routine):
    return {'meta': {'engine': engine, 'version': 'test', 'collected_at': '2026-09-21T00:00:00Z',
                     'host_alias': 'test'},
            'procedures': [dict(schema_name='app', name='find_orders', definition=body, **routine)],
            'columns': [dict(schema_name='app', table='orders', name='id', data_type='bigint'),
                        dict(schema_name='app', table='orders', name='amount', data_type='decimal(12,2)')]}


def findings(body, **kwargs):
    return [f for f in analyze_snapshot(document(body, **kwargs))['findings'] if f['category'] == 'procedures']


def test_parameter_and_local_types():
    body = 'BEGIN DECLARE v_id VARCHAR(12); SELECT o.id FROM app.orders o WHERE o.id = v_id; END'
    result = findings(body)
    f = next(f for f in result if f['rule_id'] == 'R-SP1')
    assert f['evidence']['right_type'] == 'varchar(12)'
    assert not findings('SELECT o.id FROM app.orders o WHERE o.id = p_id;',
                        parameters=[{'name': 'p_id', 'data_type': 'bigint(20)'}])
    assert findings('SELECT o.id FROM app.orders o WHERE p_id = o.id;',
                    parameters=[{'name': 'p_id', 'data_type': 'varchar(20)'}])


def test_pg_multiple_declarations_and_numeric_precision():
    result = findings('DECLARE v_id bigint; v_amount numeric(8,2); BEGIN SELECT o.id FROM app.orders o WHERE o.amount = v_amount; END', engine='postgres')
    assert result[0]['evidence']['right_type'] == 'numeric(8,2)'
    assert not findings('DECLARE v_amount numeric(12,2); BEGIN SELECT o.id FROM app.orders o WHERE o.amount = v_amount; END', engine='postgres')


def test_temp_join_type_and_index():
    body = 'CREATE TEMPORARY TABLE tmp (id varchar(20), amount decimal(12,2)); SELECT o.id FROM app.orders o JOIN tmp t ON t.id = o.id;'
    assert {f['rule_id'] for f in findings(body)} == {'R-SP1', 'R-SP2'}
    assert {f['rule_id'] for f in findings(body + 'CREATE INDEX ix_tmp ON tmp(id);')} == {'R-SP1'}
    assert not findings('CREATE TEMP TABLE tmp (id bigint PRIMARY KEY); SELECT t.id FROM tmp t WHERE t.id = x;')
    assert not findings('CREATE TEMP TABLE tmp (id bigint); INSERT INTO tmp VALUES (1);')


@pytest.mark.parametrize('body', [
    "-- SELECT * FROM orders\nSELECT 1;",
    "SELECT 'SELECT * FROM orders; WHILE x LOOP';",
    '/* CREATE TEMP TABLE t(id int); /* LOOP */ SELECT * FROM t; */ SELECT 1;',
    "EXECUTE $$SELECT * FROM orders WHERE id = 123$$;",
])
def test_comments_and_literals_are_not_code(body):
    assert not [f for f in findings(body) if f['rule_id'] != 'R-SP5']


def test_ambiguous_and_nested_binding_skipped():
    data = document('DECLARE p_id varchar(20); SELECT o.id FROM orders o WHERE o.id = p_id;')
    data['columns'].append(dict(schema_name='archive', table='orders', name='id', data_type='int'))
    assert not analyze_snapshot(data)['findings']
    assert not findings('DECLARE p_id varchar(20); SELECT o.id FROM app.orders o WHERE EXISTS (SELECT o.id FROM app.orders o WHERE o.id = p_id);')
    assert not findings('DECLARE id varchar(20); SELECT o.id FROM app.orders o WHERE o.id = id;')


def test_other_review_candidates():
    result = findings('BEGIN DECLARE c CURSOR FOR SELECT * FROM orders; SELECT o.id FROM app.orders o WHERE lower(o.id) = p; EXECUTE command; END')
    assert {f['rule_id'] for f in result} == {'R-SP3', 'R-SP4', 'R-SP5', 'R-SP6'}
    assert all('line' in f['evidence'] and f['suggested_action'] for f in result)


def test_missing_source_coverage_and_old_snapshots():
    for kwargs in ({'definition': None}, {'definition': 'print(1)', 'language': 'plpython3u'}):
        data = document(''); data['procedures'][0].update(kwargs)
        result = analyze_snapshot(data)
        assert next(c for c in result['coverage'] if c['section'] == 'procedures')['status'] == 'partial'
    data = document('SELECT 1;'); del data['procedures']
    assert next(c for c in analyze_snapshot(data)['coverage'] if c['section'] == 'procedures')['status'] == 'missing'


def test_sample_serializes():
    data = document('DECLARE p_id varchar(20); CREATE TEMPORARY TABLE tmp (id int); SELECT * FROM tmp t JOIN app.orders o ON t.id = o.id WHERE o.id = p_id;')
    result = analyze_snapshot(data)
    assert result['score']['category_deductions']['procedures'] > 0
    assert len({f['evidence_id'] for f in result['findings']}) == len(result['findings'])
    json.dumps(result, allow_nan=False)


def test_temp_insert_mapping():
    result = findings('CREATE TEMPORARY TABLE tmp (id int, amount decimal(8,2)); INSERT INTO tmp (amount, id) SELECT o.amount, o.id FROM app.orders o;')
    assert len(result) == 2
    assert {f['evidence']['left_operand'] for f in result} == {'tmp.id', 'tmp.amount'}
    assert not findings('CREATE TEMPORARY TABLE tmp (id int); INSERT INTO tmp (id) SELECT cast(o.id as int) FROM app.orders o;')


@pytest.mark.parametrize('engine', ['pg', 'mysql'])
def test_collector_source_and_bounds(engine):
    from importlib import import_module
    module = import_module(f'app.vendor.dbdoctor.collector.{engine}_collect')

    class Cursor:
        def __init__(self):
            self.responses = iter([
                [('app', 'sp', 'sp_1', 'app.sp(int)', 'sql', 'SELECT 1'),
                 ('app', 'hidden', 'hidden_2', 'app.hidden()', 'sql', None)],
                [('app', 'sp_1', 'p_id', 'bigint')],
                [('app', 'orders', 'id', 'bigint')],
            ])
        def execute(self, sql, *args):
            assert sql.strip().startswith('SELECT')
        def fetchall(self):
            return next(self.responses)

    notes = []
    data = module.collect_procedures(Cursor(), notes, 'app')
    assert data['procedures'][0]['parameters'][0]['data_type'] == 'bigint'
    assert data['procedures'][1]['definition'] is None
    assert any('unavailable' in n for n in notes)
    assert data['columns'][0]['table'] == 'orders'


def test_procedure_api_persistence_and_delta(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from app import artifacts
    from app.main import app
    monkeypatch.setattr(artifacts, 'ROOT', tmp_path)
    data = document('SELECT o.id FROM app.orders o WHERE o.id = p_id;',
                    parameters=[{'name': 'p_id', 'data_type': 'varchar(20)'}])
    previous = json.loads(json.dumps(data))
    previous['meta']['collected_at'] = '2026-09-20T00:00:00Z'
    with TestClient(app) as client:
        response = client.post('/api/analyze/database', files={
            'file': ('current.json', json.dumps(data)),
            'baseline': ('previous.json', json.dumps(previous)),
        })
        assert response.status_code == 200
        result = response.json()
        assert result['is_delta']
        saved = client.get('/api/analyses/' + result['analysis_id']).json()['analysis']
        assert saved['snapshot']['procedures'] == result['snapshot']['procedures']
        assert saved['findings'][0]['rule_id'] == 'R-SP1'


def test_procedure_sample():
    from pathlib import Path
    sample = Path(__file__).parents[1] / 'samples/database/mysql_procedures.json'
    result = analyze_snapshot(json.loads(sample.read_text()))
    assert {'R-SP1', 'R-SP2', 'R-SP4', 'R-SP6'} <= {f['rule_id'] for f in result['findings']}


def test_temp_as_select_and_inherited_indexes():
    assert 'R-SP2' in {f['rule_id'] for f in findings('CREATE TEMP TABLE tmp AS SELECT o.id FROM app.orders o; SELECT t.id FROM tmp t WHERE t.id = 1;')}
    assert 'R-SP2' not in {f['rule_id'] for f in findings('CREATE TEMPORARY TABLE tmp LIKE orders; SELECT t.id FROM tmp t WHERE t.id = 1;')}
