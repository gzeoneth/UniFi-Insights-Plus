"""Log/CSV forwarding plus saved-view and rule-usage PostgreSQL tests."""

import importlib
import json
import os
import sys
from unittest.mock import MagicMock

import pytest


@pytest.fixture
def logs_client(monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    monkeypatch.delitem(sys.modules, 'routes.logs', raising=False)
    deps = MagicMock()
    monkeypatch.setitem(sys.modules, 'deps', deps)
    database = MagicMock()
    database.get_config.return_value = None
    database.get_wan_ips_from_config.return_value = []
    monkeypatch.setitem(sys.modules, 'db', database)
    monkeypatch.setitem(sys.modules, 'ip_identity', MagicMock())
    module = importlib.import_module('routes.logs')
    app = FastAPI()
    app.include_router(module.router)
    cursor = deps.get_conn.return_value.cursor.return_value.__enter__.return_value
    cursor.fetchone.return_value = {'total': 0}
    cursor.fetchall.return_value = []
    return TestClient(app), cursor


@pytest.mark.parametrize('path', ['/api/logs', '/api/logs/aggregate', '/api/export'])
def test_log_aggregate_and_csv_all_forward_advanced_filters(logs_client, path):
    client, cursor = logs_client
    rules = [{'field': 'ip', 'operator': 'exclude', 'value': '10.0.0.0/24'}]
    response = client.get(path, params={'filter_rules': json.dumps(rules), 'time_range': '24h', 'group_by': 'src_ip'})
    assert response.status_code == 200
    query, params = cursor.execute.call_args.args
    assert 'NOT (COALESCE(' in query
    assert 'src_ip <<= %s::inet' in query and 'dst_ip <<= %s::inet' in query
    assert params.count('10.0.0.0/24') == 2
    if path == '/api/export':
        import csv
        header = next(csv.reader(response.text.splitlines()))
        for field in ('event_source', 'ips_signature', 'ips_signature_id', 'ips_severity', 'ips_risk'):
            assert field in header


@pytest.fixture
def pg_client(monkeypatch):
    dsn = os.environ.get('TEST_POSTGRES_DSN')
    if not dsn:
        pytest.skip('set TEST_POSTGRES_DSN for disposable PostgreSQL integration tests')
    import psycopg2
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    connection = psycopg2.connect(dsn)
    with connection.cursor() as cursor:
        cursor.execute('''CREATE TEMP TABLE saved_views (
            id SERIAL PRIMARY KEY, name TEXT UNIQUE, filters JSONB,
            created_at TIMESTAMPTZ DEFAULT NOW())''')
        cursor.execute('''CREATE TEMP TABLE logs (
            id INTEGER, timestamp TIMESTAMPTZ DEFAULT NOW(), log_type TEXT,
            src_ip INET, dst_ip INET, protocol TEXT, dst_port INTEGER,
            rule_name TEXT, rule_desc TEXT, rule_action TEXT)''')
        cursor.executemany('''INSERT INTO logs
            (id,log_type,src_ip,dst_ip,protocol,dst_port,rule_name,rule_action)
            VALUES (%s,%s,%s,'203.0.113.1',%s,%s,'Example rule','allow')''', [
            (1, 'firewall', '10.0.0.1', 'tcp', 443),
            (2, 'firewall', '10.0.0.2', 'tcp', 443),
            (3, 'firewall', '10.0.0.1', 'udp', 53),
            (4, 'dns', '10.0.0.1', 'tcp', 443),
            (5, 'firewall', '10.0.0.1', 'tcp', 443),
        ])
    connection.commit()
    deps = MagicMock()
    deps.get_conn.return_value = connection
    monkeypatch.setitem(sys.modules, 'deps', deps)
    app = FastAPI()
    for name in ('routes.views', 'routes.rule_usage'):
        monkeypatch.delitem(sys.modules, name, raising=False)
        module = importlib.import_module(name)
        app.include_router(module.router)
    yield TestClient(app), connection
    connection.close()


def test_saved_log_view_persists_full_filters_and_custom_bounds(pg_client):
    client, _ = pg_client
    filters = {'view_type': 'logs', 'filter_rules': [
        {'field': 'ip', 'operator': 'exclude', 'value': '10.0.0.0/24'}],
        'src_ip': '203.0.113.1', 'protocol': 'tcp', 'time_range': None,
        'time_from': '2026-01-01T00:00:00Z', 'time_to': '2026-01-02T00:00:00Z'}
    created = client.post('/api/views', json={'name': 'Synthetic exclusions', 'filters': filters})
    assert created.status_code == 200
    assert created.json()['filters'] == filters
    listed = client.get('/api/views').json()['views']
    assert listed[0]['filters'] == filters
    assert client.post('/api/views', json={'name': 'Synthetic exclusions', 'filters': filters}).status_code == 409
    assert client.delete('/api/views/' + str(created.json()['id'])).status_code == 200
    assert client.get('/api/views').json()['views'] == []


@pytest.mark.parametrize('bad', [
    {'time_range': []}, {'src_ip': []}, {'protocol': {}}, {'vpn_only': 'false'},
    {'threat_min': True}, {'time_from': 'invalid'},
    {'filter_rules': [{'field': [], 'operator': 'present'}]},
])
def test_malformed_saved_view_rejected_without_persisting(pg_client, bad):
    client, _ = pg_client
    response = client.post('/api/views', json={
        'name': 'Malformed synthetic view', 'filters': {'view_type': 'logs', **bad}})
    assert response.status_code == 400
    assert client.get('/api/views').json()['views'] == []


def test_rule_usage_applies_saved_basic_and_advanced_filters(pg_client):
    client, _ = pg_client
    rules = [{'field': 'dst_port', 'operator': 'include', 'value': '443'}]
    response = client.get('/api/rules/usage', params={
        'rule_name': 'Example', 'src_ip': '10.0.0.1', 'protocol': 'tcp',
        'rule_action': 'allow', 'filter_rules': json.dumps(rules)})
    assert response.status_code == 200
    body = response.json()
    assert body['measurement'] == 'observed_log_hits'
    assert len(body['data']) == 1
    assert body['data'][0]['src_ip'] == '10.0.0.1'
    assert body['data'][0]['log_hits'] == 2
    assert body['data'][0]['dst_port'] == 443


def test_rule_usage_keeps_conflicting_saved_type_and_reports_truncation(pg_client):
    client, _ = pg_client
    assert client.get('/api/rules/usage?log_type=dns').json()['data'] == []
    body = client.get('/api/rules/usage?limit=1').json()
    assert len(body['data']) == 1
    assert body['truncated'] is True
    assert body['data'][0]['log_hits'] == 2
