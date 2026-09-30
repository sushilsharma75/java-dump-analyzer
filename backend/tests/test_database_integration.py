"""DBDoctor branch integration: direct access, bounded DDL, persistent reports."""
import json

import pytest
from fastapi.testclient import TestClient

from app import artifacts, database
from app.main import app
from test_database import sample

PG = """CREATE TABLE public.orders(id int PRIMARY KEY, customer_id int);
CREATE PROCEDURE public.inspect_orders(IN p_id int) LANGUAGE plpgsql AS $body$
DECLARE v_count int := 0;
BEGIN
CREATE TEMP TABLE pending AS SELECT * FROM public.orders WHERE customer_id=p_id;
SELECT count(*) INTO v_count FROM pending;
DROP TABLE pending;
EXECUTE 'SELECT private_token';
END;
$body$;"""
MYSQL = """CREATE TABLE shop.orders(id INT PRIMARY KEY);
DELIMITER $$
CREATE PROCEDURE shop.inspect_orders(IN p_id INT)
BEGIN
DECLARE v_count INT DEFAULT 0;
CREATE TEMPORARY TABLE pending(id INT);
INSERT INTO pending SELECT id FROM shop.orders WHERE id=p_id;
SELECT count(*) INTO v_count FROM pending;
END$$
DELIMITER ;"""


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(artifacts, 'ROOT', tmp_path)
    with TestClient(app) as client:
        yield client


@pytest.mark.parametrize('engine,sql', [('postgres', PG), ('mysql', MYSQL), ('mariadb', MYSQL)])
def test_ddl_only_runs_without_login_and_exports(client, engine, sql):
    response = client.post('/api/analyze/database', data={'engine': engine, 'client_alias': 'My database'},
                           files=[('ddl', ('schema.sql', sql.encode(), 'text/plain'))])
    assert response.status_code == 200, response.text
    result = response.json()
    assert result['status'] == 'static' and result['score']['score'] is None
    assert result['client_alias'] == 'My database'
    assert result['upstream_revision'] == database.UPSTREAM_REVISION
    catalog = result['schema_catalog']
    assert catalog['tables'] and catalog['routines']
    routine = catalog['routines'][0]
    assert routine['parameters'][0]['name'] == 'p_id'
    assert routine['variables'][0]['name'] == 'v_count'
    assert routine['temporary_tables'][0]['name'] == 'pending'
    assert 'private_token' not in json.dumps(result)
    assert any(f['rule_id'] == 'R-SP1' for f in result['findings'])
    identifier = result['analysis_id']
    assert client.get('/api/analyses').json()[0]['kind'] == 'database'
    assert client.get(f'/api/analyses/{identifier}').json()['analysis']['schema_catalog'] == catalog
    for fmt, text in [('html', 'Schema'), ('tasks', 'Confidence'), ('schema', 'inspect_orders'), ('json', 'upstream_revision')]:
        report = client.get(f'/api/database/{identifier}/report', params={'fmt': fmt})
        assert report.status_code == 200, report.text
        assert text in report.text
        assert 'private_token' not in report.text
    html = client.get(f'/api/database/{identifier}/report').text
    assert 'insufficient evidence' in html and 'db-0001' in html
    assert 'static' in html.lower()


def test_snapshot_with_ddl_keeps_baseline_rates_and_redacts_persisted_text(client):
    current = sample()
    previous = sample()
    previous['meta']['collected_at'] = '2026-07-01T00:00:00Z'
    current['meta']['collected_at'] = '2026-07-02T00:00:00Z'
    current['queries'][0]['calls'] += 100
    current['queries'][0]['normalized_sql'] = "SELECT * FROM public.orders WHERE customer_id='private_token' /* private_token */"
    current['schema_catalog'] = {'engine': 'postgres', 'tables': [{'name': 'forged', 'columns': []}]}
    response = client.post('/api/analyze/database', files=[
        ('file', ('current.json', json.dumps(current), 'application/json')),
        ('baseline', ('previous.json', json.dumps(previous), 'application/json')),
        ('ddl', ('schema.sql', PG, 'text/plain')),
    ])
    assert response.status_code == 200, response.text
    result = response.json()
    assert result['is_delta'] and result['snapshot']['queries'][0]['calls_per_day'] == 100
    assert 'private_token' not in json.dumps(result)
    assert result['schema_catalog']['tables'][0]['name'] == 'public.orders'
    saved = artifacts.read(result['analysis_id'])['analysis']
    assert saved == result


def test_snapshot_catalog_is_not_trusted_without_ddl(client):
    document = sample()
    document['schema_catalog'] = {'engine': 'postgres', 'tables': [{'name': 'forged'}]}
    response = client.post('/api/analyze/database', files={'file': ('capture.json', json.dumps(document))})
    assert response.status_code == 200
    assert response.json()['schema_catalog'] is None


@pytest.mark.parametrize('engine,sql', [
    ('postgres', PG + """
CREATE TABLE public.customers(id bigint PRIMARY KEY, name varchar(100));
CREATE INDEX customer_name ON public.customers(name);
CREATE FUNCTION public.find_customer(p_id bigint) RETURNS bigint LANGUAGE sql AS $$
SELECT id FROM public.customers WHERE id=p_id;
$$;
"""),
    ('mysql', MYSQL + """
CREATE TABLE shop.customers(id BIGINT PRIMARY KEY, name VARCHAR(100));
CREATE INDEX customer_name ON shop.customers(name);
DELIMITER //
CREATE PROCEDURE shop.find_customer(IN p_id BIGINT)
BEGIN
SELECT id FROM shop.customers WHERE id=p_id;
SELECT 'private_token; embedded semicolon';
END//
DELIMITER ;
"""),
])
def test_one_combined_ddl_file_contains_all_schema_and_routines(client, engine, sql):
    response = client.post('/api/analyze/database', data={'engine': engine},
                           files={'ddl': ('combined-schema-and-procedures.ddl', sql, 'application/sql')})
    assert response.status_code == 200, response.text
    catalog = response.json()['schema_catalog']
    assert catalog['source_count'] == 1
    assert len(catalog['tables']) == 2
    assert len(catalog['routines']) == 2
    assert any(index['name'] == 'customer_name' for index in catalog['indexes'])
    assert all(routine['source_file'] == 1 for routine in catalog['routines'])
    assert any(routine['name'].endswith('.find_customer') for routine in catalog['routines'])
    assert 'private_token' not in json.dumps(catalog)
    assert not catalog['warnings']


@pytest.mark.parametrize('files,data,status', [
    ([('ddl', ('empty.sql', b'   '))], {}, 422),
    ([('ddl', ('bad.sql', b'\xff'))], {}, 422),
    ([('ddl', ('file.sql', PG))], {'engine': 'sqlserver'}, 422),
    ([('ddl', ('file.sql', PG)), ('baseline', ('baseline.json', '{}'))], {}, 422),
    ([('ddl', (f'{i}.sql', PG)) for i in range(21)], {}, 413),
])
def test_invalid_uploads_are_rejected_without_saving(client, files, data, status):
    response = client.post('/api/analyze/database', files=files, data=data)
    assert response.status_code == status, response.text
    assert client.get('/api/analyses').json() == []


def test_combined_ddl_limit(client, monkeypatch):
    monkeypatch.setattr(database, 'MAX_DDL_BYTES', 32)
    response = client.post('/api/analyze/database', files=[('ddl', ('one.sql', 'x'*20)), ('ddl', ('two.sql', 'x'*20))])
    assert response.status_code == 413


def test_delimiter_column_name_is_not_a_client_directive(client):
    sql = """CREATE TABLE shop.tokens (
delimiter VARCHAR(20),
id INT PRIMARY KEY
);
DELIMITER $$
CREATE PROCEDURE shop.read_tokens() BEGIN SELECT id FROM shop.tokens; END$$
DELIMITER ;
CREATE TABLE shop.tail(id INT PRIMARY KEY);"""
    response = client.post('/api/analyze/database', data={'engine': 'mysql'},
                           files={'ddl': ('combined.ddl', sql)})
    assert response.status_code == 200, response.text
    catalog = response.json()['schema_catalog']
    assert len(catalog['tables']) == 2 and len(catalog['routines']) == 1
    assert catalog['tables'][0]['columns'][0]['name'] == 'delimiter'


def test_reports_escape_content_and_support_older_saved_analyses(client):
    analysis = database.analyze_snapshot(sample())
    analysis['client_alias'] = '<script>private_token</script>'
    for key in ('engine_coverage', 'schema_catalog', 'upstream_revision'):
        analysis.pop(key, None)
    artifacts.save(analysis, 'database')
    identifier = analysis['analysis_id']
    html = client.get(f'/api/database/{identifier}/report').text
    assert '&lt;script&gt;private_token&lt;/script&gt;' in html
    assert '<script>private_token</script>' not in html
    assert client.get(f'/api/database/{identifier}/report?fmt=schema').status_code == 404
    assert client.get(f'/api/database/{identifier}/report?fmt=unknown').status_code == 422
    assert client.get('/api/database/invalid/report').status_code == 404


def test_integrated_database_has_no_jwt_or_auth_routes(client):
    schema = client.get('/openapi.json').json()
    assert not any('/auth/' in path or '/login' in path for path in schema['paths'])
    assert not schema['components'].get('securitySchemes')
    for path in ('/api/analyze/database', '/api/database/{identifier}/report'):
        assert not any(operation.get('security') for operation in schema['paths'][path].values())
    # A stale browser token cannot block the trusted-host workflow.
    response = client.post('/api/analyze/database', headers={'Authorization': 'Bearer expired'},
                           files={'file': ('capture.json', json.dumps(sample()))})
    assert response.status_code == 200
