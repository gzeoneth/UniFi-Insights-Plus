"""Address-based names for routed logs, historical names, and threat grouping."""

import importlib
import sys
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest


@pytest.fixture
def identity_routes(monkeypatch):
    for name in ('routes.logs', 'routes.stats'):
        monkeypatch.delitem(sys.modules, name, raising=False)
    deps = MagicMock()
    monkeypatch.setitem(sys.modules, 'deps', deps)
    db = MagicMock()
    db.get_config.return_value = None
    db.get_wan_ips_from_config.return_value = []
    monkeypatch.setitem(sys.modules, 'db', db)
    identity = MagicMock()
    identity.annotate_ip.return_value = (None, None, None)
    monkeypatch.setitem(sys.modules, 'ip_identity', identity)
    logs = importlib.import_module('routes.logs')
    stats = importlib.import_module('routes.stats')
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    app = FastAPI()
    app.include_router(logs.router)
    return TestClient(app), logs, stats, deps


def test_log_page_names_use_bounded_ip_joins(identity_routes):
    api, _, _, deps = identity_routes
    cur = deps.get_conn.return_value.cursor.return_value.__enter__.return_value
    cur.fetchone.return_value = {'total': 0}
    cur.fetchall.return_value = []
    response = api.get('/api/logs?time_range=1h')
    assert response.status_code == 200
    sql = cur.execute.call_args.args[0]
    assert 'WHERE ip = page.src_ip' in sql
    assert 'WHERE ip = page.dst_ip' in sql
    assert 'c1.mac = page.mac_address' not in sql
    assert 'd1.mac = page.mac_address' not in sql
    assert sql.count('LIMIT 1') == 4
    assert 'bad_device.ip != page.src_ip' in sql
    assert 'bad_client.ip != page.src_ip' in sql


def test_detail_names_use_same_safe_source_resolution(identity_routes):
    _, logs, _, _ = identity_routes
    sql = logs._LOG_DETAIL_SQL
    assert 'WHERE ip = l.src_ip' in sql
    assert 'WHERE ip = l.dst_ip' in sql
    assert 'c1.mac = l.mac_address' not in sql
    assert 'd1.mac = l.mac_address' not in sql
    assert 'THEN NULL ELSE l.src_device_name END' in sql


def test_historical_name_is_fallback_after_ip_name(identity_routes):
    _, logs, _, _ = identity_routes
    sql = logs._source_device_name_select('page')
    assert sql.index('c1.device_name') < sql.index('page.src_device_name')
    assert 'bad_device.ip IS NOT NULL' in sql
    assert 'page.src_device_name IN (bad_device.device_name, bad_device.model)' in sql
    assert 'ELSE page.src_device_name END' in sql


def test_csv_names_use_ip_lookup_without_changing_export_limits(identity_routes):
    api, _, _, deps = identity_routes
    cur = deps.get_conn.return_value.cursor.return_value.__enter__.return_value
    cur.fetchall.return_value = []
    response = api.get('/api/export?time_range=1h&limit=20')
    assert response.status_code == 200
    sql, params = cur.execute.call_args.args
    assert 'WHERE ip = f.src_ip' in sql
    assert 'bad_device.ip != f.src_ip' in sql
    assert params[-1] == 20
    assert api.get('/api/export?limit=100001').status_code == 422


def test_threats_join_and_group_the_scored_remote_endpoint(identity_routes):
    _, _, stats, _ = identity_routes
    cur = MagicMock()
    stamp = datetime(2026, 10, 28, tzinfo=timezone.utc)
    cur.fetchall.return_value = [{'ip': '203.0.113.50', 'count': 3, 'last_seen': stamp}]
    rows = stats._query_top_threat_ips(cur, stamp, ['0.0.0.0'])
    sql, params = cur.execute.call_args.args
    assert 'host(l.remote_ip) as ip' in sql
    assert 'LEFT JOIN ip_threats t ON l.remote_ip = t.ip' in sql
    assert 'GROUP BY l.remote_ip' in sql
    assert 'host(l.remote_ip) != ALL(%s)' in sql
    assert 'LIMIT 10' in sql
    assert 'l.src_ip' not in sql
    assert params == [stamp, ['0.0.0.0']]
    assert rows[0]['last_seen'] == stamp.isoformat()


def test_api_exposes_cef_context_without_creating_endpoint_identity(identity_routes):
    _, logs, _, _ = identity_routes
    record = {'event_source': 'unifi_ips', 'src_ip': None, 'dst_ip': None,
              'raw_log': '<14>Jan 01 00:00:00 gateway CEF:0|Ubiquiti|UniFi Network|1|201|Threat|7|'
                         'UNIFIsrcClientAlias=Player UNIFIdstClientAlias=Player app=Media'}
    logs._annotate_logs([record])
    assert record['src_reported_name'] == 'Player'
    assert record['dst_reported_name'] == 'Player'
    assert record['reported_application'] == 'Media'
    assert record['src_ip'] is None and record['dst_ip'] is None
    assert 'src_device_name' not in record and 'dst_device_name' not in record
