"""Dashboard and exports aggregate the same retained records under a profile."""

import csv
import importlib
import io
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest


GROUPS = [{
    'name': 'Example routine allows',
    'conditions': [
        {'field': 'rule_name_exact', 'operator': 'include', 'value': 'EXAMPLE-A-100'},
        {'field': 'hostname_exact', 'operator': 'include', 'value': 'example-gateway'},
        {'field': 'rule_action', 'operator': 'include', 'value': 'allow'},
    ],
}]
PATHS = ('/api/stats', '/api/stats/overview', '/api/stats/tables',
         '/api/stats/charts', '/api/stats/ip-pairs', '/api/stats/ip-pairs/csv')


def load_client(monkeypatch, connection):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    deps = MagicMock()
    deps.get_conn.return_value = connection
    monkeypatch.setitem(sys.modules, 'deps', deps)
    monkeypatch.delitem(sys.modules, 'routes.stats', raising=False)
    module = importlib.import_module('routes.stats')
    monkeypatch.setattr(module, 'get_config', lambda *args: None)
    monkeypatch.setattr(module, 'get_wan_ips_from_config', lambda *args: [])
    monkeypatch.setattr(module, 'load_identity_config', lambda *args: {})
    monkeypatch.setattr(module, 'annotate_ip', lambda cfg, ip, name: (name, None, None))
    monkeypatch.setattr(module, 'annotate_record', lambda *args: None)
    monkeypatch.setattr(module, 'parse_time_range', lambda value: datetime(2026, 1, 1, tzinfo=timezone.utc))
    app = FastAPI()
    app.include_router(module.router)
    return TestClient(app), deps


@pytest.mark.parametrize('path', PATHS)
def test_malformed_profile_rejected_before_database_access(monkeypatch, path):
    client, deps = load_client(monkeypatch, MagicMock())
    response = client.get(path, params={'exclude_groups': '{invalid'})
    assert response.status_code == 400
    deps.get_conn.assert_not_called()


@pytest.fixture
def pg_stats(monkeypatch):
    dsn = os.environ.get('TEST_POSTGRES_DSN')
    if not dsn:
        pytest.skip('set TEST_POSTGRES_DSN for disposable PostgreSQL integration tests')
    import psycopg2
    from psycopg2.extensions import parse_dsn

    assert parse_dsn(dsn).get('host') in ('127.0.0.1', 'localhost', '::1'), 'use a local disposable test database'
    connection = psycopg2.connect(dsn)
    schema = 'stats_test_' + uuid.uuid4().hex
    from psycopg2 import sql
    with connection.cursor() as cur:
        cur.execute(sql.SQL('CREATE SCHEMA {}').format(sql.Identifier(schema)))
        cur.execute('''CREATE TEMP TABLE logs (
            id INTEGER, timestamp TIMESTAMPTZ, log_type TEXT,
            src_ip INET, dst_ip INET, remote_ip INET, protocol TEXT, dst_port INTEGER,
            rule_name TEXT, rule_desc TEXT, rule_action TEXT, hostname TEXT,
            interface_in TEXT, interface_out TEXT, service_name TEXT,
            direction TEXT, asn_name TEXT, rdns TEXT,
            event_source TEXT, ips_signature_id TEXT, raw_log TEXT,
            geo_country TEXT, geo_city TEXT, threat_score INTEGER,
            threat_categories TEXT, dns_query TEXT)''')
        cur.execute('''CREATE TEMP TABLE unifi_clients (
            ip INET, device_name TEXT, hostname TEXT, oui TEXT, last_seen TIMESTAMPTZ)''')
        cur.execute('''CREATE TEMP TABLE unifi_devices (
            ip INET, device_name TEXT, model TEXT, updated_at TIMESTAMPTZ)''')
        cur.execute('CREATE TEMP TABLE ip_threats (ip INET, threat_categories TEXT)')
        cur.execute(sql.SQL('''CREATE FUNCTION {}.is_public_inet(INET) RETURNS BOOLEAN
            LANGUAGE SQL IMMUTABLE AS 'SELECT NOT ($1 <<= ''10.0.0.0/8''::inet)' ''').format(sql.Identifier(schema)))
        cur.execute(sql.SQL('SET search_path TO pg_temp, {}, public').format(sql.Identifier(schema)))
        rows = [
            (1, 'allow', 'example-gateway', None, None, '', 'firewall', 'EXAMPLE-A-100'),
            (2, 'block', 'example-gateway', None, None, '', 'firewall', 'EXAMPLE-A-100'),
            (3, 'allow', 'other-gateway', None, None, '', 'firewall', 'EXAMPLE-A-100'),
            (4, 'allow', 'example-gateway', 'unifi_ips', '1234567', '', 'firewall', 'EXAMPLE-A-100'),
            (5, 'allow', 'example-gateway', None, None,
             'CEF:0|Ubiquiti|UniFi Network|10.0.0|200|Threat Detected|7|act=allowed', 'system', 'EXAMPLE-A-100'),
            (6, 'allow', 'example-gateway', None, None, '', 'firewall', None),
        ]
        cur.executemany('''INSERT INTO logs
            (id,rule_action,hostname,event_source,ips_signature_id,raw_log,log_type,rule_name,
             timestamp,src_ip,dst_ip,remote_ip,protocol,dst_port,rule_desc,interface_in,
             interface_out,service_name,direction,geo_country,threat_score)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,'2026-01-02T12:00:00Z',
                    '192.0.2.10','198.51.100.20','198.51.100.20','tcp',443,
                    'Example event','br-example','eth-example','Example','outbound','ZZ',80)''', rows)
        cur.execute('''INSERT INTO logs (id,timestamp,log_type,rule_action)
            VALUES (7,'2020-01-01T00:00:00Z','firewall','allow')''')
    connection.commit()
    client, _ = load_client(monkeypatch, connection)
    try:
        yield client
    finally:
        connection.rollback()
        with connection.cursor() as cur:
            cur.execute(sql.SQL('DROP SCHEMA {} CASCADE').format(sql.Identifier(schema)))
        connection.commit()
        connection.close()


def test_legacy_and_overview_counts_match_without_deleting_logs(pg_stats):
    for path in ('/api/stats', '/api/stats/overview'):
        response = pg_stats.get(path, params={'exclude_groups': json.dumps(GROUPS)})
        assert response.status_code == 200, response.text
        data = response.json()
        assert data['view_counts'] == {'total': 6, 'visible': 5, 'hidden': 1}
        assert (data['total'], data['allowed'], data['blocked'], data['threats']) == (5, 3, 1, 5)
        assert data['by_type'] == {'firewall': 4, 'system': 1}
        assert data['by_direction'] == {'outbound': 5}
    unfiltered = pg_stats.get('/api/stats/overview').json()
    assert unfiltered['view_counts'] == {'total': 6, 'visible': 6, 'hidden': 0}


def test_charts_and_top_tables_match_profile_aggregates(pg_stats):
    params = {'exclude_groups': json.dumps(GROUPS)}
    charts = pg_stats.get('/api/stats/charts', params=params)
    tables = pg_stats.get('/api/stats/tables', params=params)
    assert charts.status_code == tables.status_code == 200
    assert sum(row['count'] for row in charts.json()['logs_over_time']) == 5
    assert sum(row['allow'] for row in charts.json()['traffic_by_action']) == 3
    data = tables.json()
    assert sum(row['count'] for row in data['top_allowed_destinations']) == 4
    assert sum(row['count'] for row in data['top_threat_ips']) == 5
    assert sum(row['count'] for row in data['top_blocked_services']) == 1


def test_ip_pairs_and_csv_share_profile_and_advanced_filter(pg_stats):
    params = {'time_from': '2026-01-01T00:00:00Z', 'exclude_groups': json.dumps(GROUPS),
              'filter_rules': json.dumps([{'field': 'hostname_exact', 'operator': 'include',
                                          'value': 'example-gateway'}])}
    pairs = pg_stats.get('/api/stats/ip-pairs', params=params)
    exported = pg_stats.get('/api/stats/ip-pairs/csv', params=params)
    assert pairs.status_code == exported.status_code == 200
    pair = pairs.json()['pairs'][0]
    assert (pair['total_count'], pair['allow_count'], pair['block_count']) == (3, 2, 1)
    csv_row = list(csv.DictReader(io.StringIO(exported.text)))[0]
    assert (csv_row['allow_count'], csv_row['block_count']) == ('2', '1')


def test_overlapping_exclusion_groups_count_each_hidden_event_once(pg_stats):
    response = pg_stats.get('/api/stats/overview', params={'exclude_groups': json.dumps(GROUPS * 2)})
    assert response.status_code == 200
    assert response.json()['view_counts'] == {'total': 6, 'visible': 5, 'hidden': 1}
