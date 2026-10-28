"""Fast browsing API checks; optional SQL coverage uses disposable PG temp tables."""

import importlib
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from log_pagination import decode_cursor, encode_cursor, filter_fingerprint
from query_helpers import build_ip_condition


@pytest.fixture
def logs_api(monkeypatch):
    monkeypatch.delitem(sys.modules, 'routes.logs', raising=False)
    deps = MagicMock()
    monkeypatch.setitem(sys.modules, 'deps', deps)
    monkeypatch.setitem(sys.modules, 'db', MagicMock())
    monkeypatch.setitem(sys.modules, 'ip_identity', MagicMock())
    logs = importlib.import_module('routes.logs')
    monkeypatch.setattr(logs, '_annotate_logs', lambda rows: None)
    app = FastAPI()
    app.include_router(logs.router)
    return TestClient(app), logs, deps


def test_no_count_fast_path_is_one_bounded_page_query(logs_api):
    api, logs, deps = logs_api
    cur = deps.get_conn.return_value.cursor.return_value.__enter__.return_value
    stamp = datetime.now(timezone.utc)
    cur.fetchall.return_value = [{'id': i, 'timestamp': stamp} for i in (3, 2, 1)]
    result = api.get('/api/logs', params={'count_mode': 'none', 'per_page': 2}).json()
    assert result['total'] is result['pages'] is result['view_counts'] is None
    assert result['timings']['count_ms'] is None
    assert result['timings']['query_ms'] >= 0
    assert result['has_more'] is True
    assert [row['id'] for row in result['data']] == [3, 2]
    assert cur.execute.call_count == 1
    query, params = cur.execute.call_args.args
    assert 'COUNT(' not in query and params[-2:] == [3, 0]
    assert 'ORDER BY timestamp DESC, id DESC' in query


def test_legacy_default_still_counts(logs_api):
    api, _, deps = logs_api
    cur = deps.get_conn.return_value.cursor.return_value.__enter__.return_value
    cur.fetchone.return_value = {'total': 10}
    cur.fetchall.return_value = []
    result = api.get('/api/logs', params={'per_page': 2}).json()
    assert result['total'] == 10 and result['pages'] == 5
    assert result['view_counts'] == {'total': 10, 'visible': 10, 'hidden': 0}
    assert result['timings']['count_ms'] >= 0
    assert any('COUNT(*)' in call.args[0] for call in cur.execute.call_args_list)


@pytest.mark.parametrize('params', [
    {'count_mode': 'estimate'}, {'pagination': 'key'},
    {'cursor': 'bad'}, {'pagination': 'cursor', 'cursor': 'bad'},
    {'pagination': 'cursor', 'sort': 'src_ip'},
    {'pagination': 'cursor', 'order': 'random'},
    {'pagination': 'cursor', 'page': 2},
])
def test_invalid_cursor_options_rejected_before_database(logs_api, params):
    api, _, deps = logs_api
    assert api.get('/api/logs', params=params).status_code == 400
    deps.get_conn.assert_not_called()


def test_fingerprint_normalizes_json_but_covers_filters_sort_and_exclusions():
    rules = [{'field': 'src_ip', 'value': '192.0.2.1', 'operator': 'include'}]
    a = {'filter_rules': json.dumps(rules), 'order': 'desc'}
    b = {'order': 'desc', 'filter_rules': rules}
    assert filter_fingerprint(a) == filter_fingerprint(b)
    assert filter_fingerprint(a) != filter_fingerprint({**a, 'order': 'asc'})
    assert filter_fingerprint(a) != filter_fingerprint({**a, 'exclude_groups': []})


@pytest.mark.parametrize('token', ['?', 'A' * 3000, encode_cursor([]), encode_cursor({})])
def test_malformed_cursor_fails_closed(token):
    with pytest.raises(HTTPException):
        decode_cursor(token, 'synthetic')


@pytest.mark.parametrize('value,fragment,parameter', [
    ('192.0.2.1', '= %s::inet', '192.0.2.1'),
    ('2001:db8:0::1', '= %s::inet', '2001:db8::1'),
    ('192.0.2.99/24', '<<= %s::inet', '192.0.2.0/24'),
    ('2001:db8:abcd::1/32', '<<= %s::inet', '2001:db8::/32'),
    ('192.0.2.', 'LIKE %s', '%192.0.2.%'),
    ('contains:192.0.2.1', 'LIKE %s', '%192.0.2.1%'),
    ('2001:db8:', 'LIKE %s', '%2001:db8:%'),
    ('contains:%_', 'LIKE %s', r'%\%\_%'),
])
def test_basic_ip_mode_detection(value, fragment, parameter):
    predicate, params = build_ip_condition(value, ('src_ip', 'dst_ip'))
    assert fragment in predicate and params == [parameter, parameter]
    negative, negative_params = build_ip_condition('!' + value, ('src_ip', 'dst_ip'))
    assert 'IS NOT TRUE' in negative and negative_params == params


@pytest.mark.parametrize('value', ['192.0.2.0/999', 'fe80::1%eth0', 'contains:', '!'])
def test_bad_typed_ip_filters_are_not_silent_substring_matches(value):
    with pytest.raises(HTTPException):
        build_ip_condition(value, ('src_ip',))


@pytest.fixture
def pg_api(logs_api):
    dsn = os.environ.get('TEST_POSTGRES_DSN')
    if not dsn:
        pytest.skip('set TEST_POSTGRES_DSN to a disposable local PostgreSQL')
    import psycopg2
    from psycopg2.extensions import parse_dsn
    assert parse_dsn(dsn).get('host') in ('localhost', '127.0.0.1', '::1')
    api, logs, deps = logs_api
    conn = psycopg2.connect(dsn)
    with conn.cursor() as cur:
        cur.execute('''CREATE TEMP TABLE logs (
            id BIGSERIAL PRIMARY KEY, timestamp TIMESTAMPTZ NOT NULL,
            log_type TEXT, src_ip INET, dst_ip INET, mac_address TEXT,
            src_device_name TEXT, dst_device_name TEXT, rule_name TEXT,
            event_source TEXT, ips_signature_id TEXT, raw_log TEXT,
            protocol TEXT, rule_action TEXT);
            CREATE TEMP TABLE unifi_clients (
                ip INET, mac TEXT, device_name TEXT, hostname TEXT,
                oui TEXT, last_seen TIMESTAMPTZ);
            CREATE TEMP TABLE unifi_devices (
                ip INET, mac TEXT, device_name TEXT, model TEXT,
                updated_at TIMESTAMPTZ);''')
    conn.commit()
    deps.get_conn.return_value = conn
    yield api, logs, conn
    conn.close()


@pytest.mark.parametrize('order', ['asc', 'desc'])
def test_cursor_ties_frozen_window_new_inserts_counts_and_back(pg_api, order):
    api, logs, conn = pg_api
    now = datetime.now(timezone.utc)
    with conn.cursor() as cur:
        cur.executemany('INSERT INTO logs(timestamp,log_type,src_ip,raw_log) VALUES (%s,%s,%s,%s)', [
            (now - timedelta(minutes=15 + i // 3), 'firewall', '192.0.2.1', 'synthetic')
            for i in range(13)])
        cur.execute('SELECT id FROM logs ORDER BY timestamp ' + order + ', id ' + order)
        expected = [row[0] for row in cur.fetchall()]
    conn.commit()
    params = {'pagination': 'cursor', 'count_mode': 'none', 'time_range': '1h',
              'per_page': 4, 'order': order, 'src_ip': '192.0.2.1'}
    response = api.get('/api/logs', params=params)
    assert response.status_code == 200, response.text
    first = result = response.json()
    found = [row['id'] for row in result['data']]
    with conn.cursor() as cur:
        # A late-arriving old event and a new event must not enter this traversal.
        cur.executemany('INSERT INTO logs(timestamp,log_type,src_ip,raw_log) VALUES (%s,%s,%s,%s)', [
            (now - timedelta(minutes=16), 'firewall', '192.0.2.1', 'late arrival'),
            (now + timedelta(seconds=1), 'firewall', '192.0.2.1', 'new arrival'),
        ])
    conn.commit()
    while result['has_more']:
        result = api.get('/api/logs', params={**params, 'cursor': result['next_cursor']}).json()
        assert result['window'] == first['window']
        found.extend(row['id'] for row in result['data'])
    assert found == expected and len(set(found)) == 13
    assert result['next_cursor'] is None
    recount = api.get('/api/logs', params={**params, 'cursor': first['page_cursor'], 'count_mode': 'exact'}).json()
    assert recount['total'] == 13 and recount['pages'] == 4
    assert recount['data'] == first['data'] and recount['window'] == first['window']
    for change in ({'src_ip': '192.0.2.2'}, {'order': 'asc' if order == 'desc' else 'desc'},
                   {'time_range': '24h'}, {'exclude_groups': '[]'}):
        assert api.get('/api/logs', params={**params, 'cursor': first['page_cursor'], **change}).status_code == 400


@pytest.mark.parametrize('value,expected', [
    ('192.0.2.1', [1]), ('!192.0.2.1', [2, 3, 4, 5]),
    ('192.0.2.0/24', [1, 2]), ('!192.0.2.0/24', [3, 4, 5]),
    ('2001:db8::/32', [4]), ('!2001:db8::/32', [1, 2, 3, 5]),
    ('contains:192.0.2.1', [1, 2]), ('!contains:192.0.2.1', [3, 4, 5]),
])
def test_basic_ip_postgres_truth_table(pg_api, value, expected):
    api, _, conn = pg_api
    with conn.cursor() as cur:
        cur.executemany('INSERT INTO logs(timestamp,src_ip,dst_ip) VALUES (now(),%s,%s)', [
            ('192.0.2.1', None), (None, '192.0.2.10'),
            (None, '198.51.100.1'), ('2001:db8::1', None), (None, None),
        ])
    conn.commit()
    response = api.get('/api/logs', params={'ip': value, 'order': 'asc'})
    assert response.status_code == 200, response.text
    assert [row['id'] for row in response.json()['data']] == expected
