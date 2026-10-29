"""Query-only exclusion profiles, using connection-local synthetic PostgreSQL rows."""

import importlib
import json
import os
import sys
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException

from field_filters import (append_exclusions, compile_exclusions, compile_filters,
                           parse_exclusion_groups, query_view_counts)


def condition(field, value=None, operator='include'):
    return {'field': field, 'operator': operator, 'value': value}


PROFILE = [{'name': 'Routine observations', 'conditions': [
    condition('rule_name_exact', 'Allow, media'),
    condition('hostname_exact', 'gateway-a'),
    condition('rule_action', 'allow'),
]}]


@pytest.mark.parametrize('value', [
    'not-json', {}, [None], [{'conditions': []}], [{'conditions': 'all'}],
    [{'conditions': [condition('unknown', 'x')]}],
    [{'name': None, 'conditions': [condition('protocol', 'tcp')]}],
    [{'name': 'x' * 101, 'conditions': [condition('protocol', 'tcp')]}],
    [{'sql': 'TRUE', 'conditions': [condition('protocol', 'tcp')]}],
    [{'conditions': [condition('protocol', 'tcp')] * 9}],
    [{'conditions': [condition('protocol', 'tcp')]}] * 13,
    [{'conditions': [condition('protocol', 'tcp')] * 8}] * 7,
    [{'conditions': [condition('src_ip', 'not-an-ip')]}],
    [{'conditions': [condition('rule_name_exact', ' ')]}],
    [{'conditions': [condition('rule_name_exact', 'x' * 1025)]}],
    [{'conditions': [condition('rule_name_exact', 'x' * 1024)] * 8}] * 3,
    '[' * 2000,
])
def test_bad_groups_fail_closed_as_400(value):
    with pytest.raises(HTTPException) as error:
        compile_exclusions(value)
    assert error.value.status_code == 400


def test_group_sql_parameterization_and_exact_literal_values():
    literal = "  rule, name' OR TRUE --  "
    conditions, params = compile_exclusions([{'conditions': [
        condition('rule_name_exact', literal), condition('hostname_exact', 'GW,a'),
    ]}])
    assert params == [literal, 'GW,a']
    assert literal not in conditions[0]
    assert 'rule_name = %s' in conditions[0]
    assert 'hostname = %s' in conditions[0]
    assert compile_exclusions(PROFILE) == compile_exclusions(json.dumps(PROFILE))
    assert parse_exclusion_groups(None) == []
    assert compile_exclusions([]) == ([], [])


def test_recursive_structured_input_is_rejected():
    cycle = []
    cycle.append(cycle)
    with pytest.raises(HTTPException):
        compile_exclusions(cycle)


def test_counts_use_one_aggregate_and_preserve_parameter_order():
    cursor = MagicMock()
    cursor.fetchone.return_value = {'total': 20, 'visible': 6}
    result = query_view_counts(cursor, 'protocol = %s', ['udp'], PROFILE)
    assert result == {'total': 20, 'visible': 6, 'hidden': 14}
    assert cursor.execute.call_count == 1
    sql, params = cursor.execute.call_args.args
    assert 'COUNT(*) FILTER (WHERE' in sql
    assert params == ['Allow, media', 'gateway-a', 'allow', 'udp']


@pytest.mark.parametrize('value', ['reputation', 'ips,,unparsed_cef', "ips') OR TRUE --", ','.join(['ips'] * 33)])
def test_security_category_is_a_fixed_whitelist(value):
    with pytest.raises(HTTPException) as error:
        compile_filters([condition('security_event', value)])
    assert error.value.status_code == 400


@pytest.fixture
def pg_scope(monkeypatch):
    dsn = os.environ.get('TEST_POSTGRES_DSN')
    if not dsn:
        pytest.skip('set TEST_POSTGRES_DSN for disposable PostgreSQL integration tests')
    import psycopg2
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    connection = psycopg2.connect(dsn)
    with connection.cursor() as cursor:
        cursor.execute('''CREATE TEMP TABLE logs (
            id INTEGER, timestamp TIMESTAMPTZ DEFAULT NOW(), log_type TEXT DEFAULT 'firewall',
            hostname TEXT, rule_name TEXT, rule_desc TEXT, rule_action TEXT,
            event_source TEXT, ips_signature_id TEXT, raw_log TEXT,
            src_ip INET DEFAULT '192.0.2.10', dst_ip INET DEFAULT '198.51.100.10',
            protocol TEXT DEFAULT 'tcp', src_port INTEGER DEFAULT 40000,
            dst_port INTEGER DEFAULT 443)''')
        # Nullable enrichment fields and empty controller tables let the real
        # row and CSV queries run without live controller or enrichment data.
        for column in ('direction', 'service_name', 'interface_in', 'interface_out',
                       'mac_address', 'dns_query', 'dns_type', 'dns_answer', 'geo_country',
                       'geo_city', 'asn_name', 'threat_categories', 'rdns', 'abuse_usage_type',
                       'abuse_last_reported', 'remote_ip', 'source', 'event_id', 'event_name',
                       'ips_signature', 'ips_risk', 'src_device_name', 'dst_device_name'):
            cursor.execute(f'ALTER TABLE logs ADD COLUMN {column} TEXT')
        for column in ('threat_score', 'abuse_total_reports', 'ips_severity'):
            cursor.execute(f'ALTER TABLE logs ADD COLUMN {column} INTEGER')
        cursor.execute('ALTER TABLE logs ADD COLUMN abuse_is_tor BOOLEAN')
        cursor.execute('''CREATE TEMP TABLE unifi_clients (
            mac TEXT, ip INET, device_name TEXT, hostname TEXT, oui TEXT, last_seen TIMESTAMPTZ)''')
        cursor.execute('''CREATE TEMP TABLE unifi_devices (
            mac TEXT, ip INET, device_name TEXT, model TEXT, updated_at TIMESTAMPTZ)''')
        # Only the first row matches the entire group; later rows isolate each
        # field, NULL handling, and the three independent security protections.
        cursor.executemany('''INSERT INTO logs
            (id,hostname,rule_name,rule_action,event_source,ips_signature_id,raw_log)
            VALUES (%s,%s,%s,%s,%s,%s,%s)''', [
            (1, 'gateway-a', 'Allow, media', 'allow', None, None, 'ordinary event'),
            (2, 'gateway-b', 'Allow, media', 'allow', None, None, 'ordinary event'),
            (3, 'gateway-a', 'Allow, media', 'block', None, None, 'ordinary event'),
            (4, 'gateway-a', 'Allow', 'allow', None, None, 'ordinary event'),
            (5, None, None, None, None, None, None),
            (6, 'gateway-a', 'Allow, media', 'allow', 'unifi_ips', None, 'detection'),
            (7, 'gateway-a', 'Allow, media', 'allow', None, '2000001', 'detection'),
            (8, 'gateway-a', 'Allow, media', 'allow', None, None,
             'CEF:0|Example|Gateway|1|200|Threat Detected|7|act=allowed'),
            (9, 'gateway-a', 'Allow, media', 'allow', 'ips', None, 'detection'),
            (10, 'gateway-a', 'allow, media', 'allow', None, None, 'ordinary event'),
        ])
        cursor.execute('''CREATE TEMP TABLE saved_views (id SERIAL PRIMARY KEY,
            name TEXT UNIQUE, filters JSONB, created_at TIMESTAMPTZ DEFAULT NOW())''')
    connection.commit()
    deps = MagicMock()
    deps.get_conn.return_value = connection
    deps.ttl_cache.side_effect = lambda **kwargs: lambda func: func
    monkeypatch.setitem(sys.modules, 'deps', deps)
    database = MagicMock()
    database.get_config.return_value = 'off'
    monkeypatch.setitem(sys.modules, 'db', database)
    identity = MagicMock()
    identity.annotate_ip.return_value = (None, None, None)
    monkeypatch.setitem(sys.modules, 'ip_identity', identity)
    app = FastAPI()
    for name in ('routes.logs', 'routes.rule_usage', 'routes.views', 'routes.security'):
        monkeypatch.delitem(sys.modules, name, raising=False)
        module = importlib.import_module(name)
        app.include_router(module.router)
    yield connection, TestClient(app)
    connection.close()


def visible_ids(connection, groups, base='TRUE', base_params=()):
    where, params = append_exclusions(base, base_params, groups)
    with connection.cursor() as cursor:
        cursor.execute('SELECT id FROM logs WHERE ' + where + ' ORDER BY id', params)
        return [row[0] for row in cursor.fetchall()]


def test_exact_scope_nulls_security_and_or_groups(pg_scope):
    connection, _ = pg_scope
    assert visible_ids(connection, PROFILE) == list(range(2, 11))
    second_group = {'conditions': [condition('hostname_exact', 'gateway-b')]}
    assert visible_ids(connection, PROFILE + [second_group]) == list(range(3, 11))
    # Deliberately broad profile still cannot hide known or historical threats.
    broad = [{'conditions': [condition('rule_name', operator='present')]}]
    assert visible_ids(connection, broad) == [5, 6, 7, 8, 9]
    # Ordinary explicit field filters are still under the user's control.
    rules, params = compile_filters([condition('event_source', 'unifi_ips', 'exclude')])
    assert 6 not in visible_ids(connection, [], ' AND '.join(rules), params)


@pytest.mark.parametrize('raw', [
    'CEF:0|Ubiquiti|UniFi Network|1|201|Threat Detected and Blocked|7|act=blocked',
    'CEF:0|Ubiquiti|UniFi Network|1|201|Threat Prevented|7|act=blocked',
    'CEF:0|Ubiquiti|UniFi Network|1|201|Example|7|UNIFIipsSignature=synthetic',
    'CEF:0|Ubiquiti|UniFi Network|1|201|Example|7|UNIFIipsSignatureId=1234',
    'CEF:0|Ubiquiti|UniFi Network|1|201|Example|7|UNIFIpolicyType=ids/ips',
])
def test_legacy_cef_names_and_ips_metadata_always_remain_visible(pg_scope, raw):
    connection, _ = pg_scope
    with connection.cursor() as cursor:
        cursor.execute('UPDATE logs SET raw_log = %s WHERE id = 1', [raw])
    assert 1 in visible_ids(connection, PROFILE)


@pytest.mark.parametrize('value,operator,expected', [
    ('ips', 'include', [6, 7, 9]),
    ('unparsed_cef', 'include', [8]),
    ('IPS, UNPARSED_CEF', 'include', [6, 7, 8, 9]),
    ('ips', 'exclude', [1, 2, 3, 4, 5, 8, 10]),
    ('ips,unparsed_cef', 'exclude', [1, 2, 3, 4, 5, 10]),
    (None, 'present', [6, 7, 8, 9]),
    (None, 'missing', [1, 2, 3, 4, 5, 10]),
])
def test_security_category_truth_table_and_nulls(pg_scope, value, operator, expected):
    connection, _ = pg_scope
    rules, params = compile_filters([condition('security_event', value, operator)])
    assert params == []  # No caller text becomes a SQL identifier or expression.
    assert visible_ids(connection, [], ' AND '.join(rules), params) == expected


def test_security_summary_matches_source_and_signature_classification(pg_scope):
    connection, client = pg_scope
    with connection.cursor() as cursor:
        # The fixture includes source-only, signature-only, alternate-source,
        # ordinary blocked, and unparsed CEF rows; assign separate IPS actions.
        cursor.execute("UPDATE logs SET rule_action = 'block' WHERE id = 7")
        cursor.execute('UPDATE logs SET rule_action = NULL WHERE id = 9')
    connection.commit()
    summary_response = client.get('/api/security/summary')
    assert summary_response.status_code == 200
    summary = summary_response.json()
    assert {key: summary[key] for key in ('ips_blocked', 'ips_allowed', 'ips_unknown',
                                        'firewall_blocks', 'unparsed_cef_threats')} == {
        'ips_blocked': 1, 'ips_allowed': 1, 'ips_unknown': 1,
        'firewall_blocks': 1, 'unparsed_cef_threats': 1,
    }
    filtered = client.get('/api/logs', params={
        'filter_rules': json.dumps([condition('security_event', 'ips')]),
        'exclude_groups': json.dumps(PROFILE),
    }).json()
    assert sorted(row['id'] for row in filtered['data']) == [6, 7, 9]
    assert sum(summary[key] for key in ('ips_blocked', 'ips_allowed', 'ips_unknown')) == filtered['total']
    assert sum(row['count'] for row in summary['top_signatures']) == filtered['total']
    assert next(row for row in summary['top_signatures'] if row['ips_signature_id'] == '2000001')['rule_action'] == 'block'


@pytest.mark.parametrize('category,expected', [('ips', [6, 7, 9]), ('unparsed_cef', [8])])
def test_security_presets_match_api_csv_preview_and_saved_view(pg_scope, category, expected):
    import csv
    _, client = pg_scope
    rules = [condition('security_event', category)]
    params = {'filter_rules': json.dumps(rules), 'exclude_groups': json.dumps(PROFILE)}
    response = client.get('/api/logs', params=params)
    assert response.status_code == 200
    body = response.json()
    assert sorted(row['id'] for row in body['data']) == expected
    assert body['view_counts'] == {'total': len(expected), 'visible': len(expected), 'hidden': 0}
    csv_response = client.get('/api/export', params=params)
    assert csv_response.status_code == 200
    assert len(list(csv.DictReader(csv_response.text.splitlines()))) == len(expected)
    preview = client.get('/api/logs/exclusion-preview', params=params).json()
    assert preview['view_counts'] == body['view_counts'] and preview['examples'] == []
    filters = {'view_type': 'logs', 'filter_rules': rules, 'time_range': '24h'}
    saved = client.post('/api/views', json={'name': 'Synthetic security view', 'filters': filters})
    assert saved.status_code == 200 and saved.json()['filters'] == filters


def test_preview_is_scoped_bounded_read_only_and_omits_raw_log(pg_scope):
    connection, client = pg_scope
    with connection.cursor() as cursor:
        cursor.execute('''INSERT INTO logs (id,hostname,rule_name,rule_action)
            SELECT n,'gateway-a','Allow, media','allow' FROM generate_series(11,18) n''')
    connection.commit()
    response = client.get('/api/logs/exclusion-preview', params={
        'exclude_groups': json.dumps(PROFILE), 'rule_action': 'allow', 'time_range': '24h'})
    assert response.status_code == 200
    body = response.json()
    assert body['view_counts'] == {'total': 16, 'visible': 7, 'hidden': 9}
    assert len(body['examples']) == 5
    assert all('raw_log' not in row and row['hostname'] == 'gateway-a' for row in body['examples'])
    with connection.cursor() as cursor:
        cursor.execute('SELECT COUNT(*) FROM logs')
        assert cursor.fetchone()[0] == 18
    empty = client.get('/api/logs/exclusion-preview').json()
    assert empty['view_counts'] == {'total': 18, 'visible': 18, 'hidden': 0}
    assert empty['examples'] == []
    assert client.get('/api/logs/exclusion-preview?exclude_groups=invalid').status_code == 400


def test_rule_usage_counts_before_limit_and_groups_by_observed_gateway(pg_scope):
    _, client = pg_scope
    body = client.get('/api/rules/usage', params={
        'exclude_groups': json.dumps(PROFILE), 'limit': 1}).json()
    assert body['view_counts'] == {'total': 10, 'visible': 9, 'hidden': 1}
    assert body['truncated'] is True
    assert body['data'][0]['hostname'] == 'gateway-a'
    assert body['data'][0]['log_hits'] == 4  # the protected security rows


def test_aggregate_and_counts_by_type_apply_profile(pg_scope):
    connection, client = pg_scope
    body = client.get('/api/logs/aggregate', params={
        'group_by': 'rule_name', 'exclude_groups': json.dumps(PROFILE)}).json()
    assert body['view_counts'] == {'total': 10, 'visible': 9, 'hidden': 1}
    assert sum(row['total'] for row in body['data']) == 9
    with connection.cursor() as cursor:
        cursor.execute("UPDATE logs SET log_type = 'system'")
    connection.commit()
    assert client.get('/api/logs/counts-by-type', params={
        'exclude_groups': json.dumps(PROFILE)}).json() == {'wifi': 0, 'system': 9}


def test_real_log_rows_and_csv_share_visible_scope_and_counts_before_pagination(pg_scope):
    import csv
    from collections import Counter
    _, client = pg_scope
    params = {'exclude_groups': json.dumps(PROFILE), 'time_range': '24h'}
    page = client.get('/api/logs', params={**params, 'per_page': 2}).json()
    assert page['view_counts'] == {'total': 10, 'visible': 9, 'hidden': 1}
    assert page['total'] == 9 and page['pages'] == 5 and len(page['data']) == 2
    rows = client.get('/api/logs', params={**params, 'per_page': 200}).json()['data']
    exported = client.get('/api/export', params=params)
    assert exported.status_code == 200
    csv_rows = list(csv.DictReader(exported.text.splitlines()))
    assert len(csv_rows) == len(rows) == 9
    keys = ('hostname', 'rule_name', 'rule_action', 'event_source', 'ips_signature_id')
    assert Counter(tuple(row[key] or '' for key in keys) for row in rows) == Counter(
        tuple(row[key] for key in keys) for row in csv_rows)


def test_named_profile_roundtrip_has_no_implicit_private_defaults(pg_scope):
    _, client = pg_scope
    filters = {'view_type': 'exclusions', 'exclude_groups': PROFILE}
    created = client.post('/api/views', json={'name': 'Everyday', 'filters': filters})
    assert created.status_code == 200
    assert client.get('/api/views').json()['views'][0]['filters'] == filters
    assert client.delete('/api/views/' + str(created.json()['id'])).status_code == 200
    assert client.get('/api/views').json()['views'] == []
    malformed = client.post('/api/views', json={'name': 'Invalid', 'filters': {
        'view_type': 'exclusions', 'exclude_groups': [{'conditions': []}]}})
    assert malformed.status_code == 400
    for value in (None, '[]', {}):
        assert client.post('/api/views', json={'name': 'Invalid', 'filters': {
            'view_type': 'exclusions', 'exclude_groups': value}}).status_code == 400
