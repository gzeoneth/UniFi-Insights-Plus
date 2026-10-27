"""Local ingestion health remains readable through database/provider outages."""
import importlib
import json
import sys
import time
from unittest.mock import MagicMock

import pytest


@pytest.fixture
def route(monkeypatch, tmp_path):
    deps = MagicMock()
    deps.get_conn.side_effect = AssertionError('Snapshot endpoint must not query DB')
    monkeypatch.setitem(sys.modules, 'deps', deps)
    monkeypatch.delitem(sys.modules, 'routes.health', raising=False)
    module = importlib.import_module('routes.health')
    path = tmp_path / 'health.json'
    monkeypatch.setenv('INGEST_STATUS_PATH', str(path))
    return module, path, deps


def snapshot(**overrides):
    now = time.time()
    return dict({
        'schema_version': 1, 'updated_at': now, 'running': True, 'worker_alive': True,
        'last_progress_at': now, 'last_receive_at': now - 3,
        'queue': {'depth': 0, 'capacity': 4096, 'oldest_age_seconds': 0},
        'spool': {'rows': 0, 'bytes': 0, 'max_rows': 100000, 'max_bytes': 67108864, 'failed': False},
        'stats': {'received': 100, 'inserted': 99, 'dropped': 1},
        'providers': {'geoip': {'status': 'missing'}, 'abuseipdb': {'status': 'not_configured'}},
    }, **overrides)


def test_missing_file_is_unavailable_not_healthy(route):
    module, _, deps = route
    result = module.read_ingest_health()
    assert result['status'] == 'unavailable'
    assert result['state'] == 'unknown'
    deps.get_conn.assert_not_called()


def test_fresh_snapshot_is_allowlisted_and_exposes_counts(route):
    module, path, deps = route
    data = snapshot(secret='no', raw_log='no')
    data['stats']['password'] = 'no'
    data['providers']['abuseipdb']['api_key'] = 'no'
    path.write_text(json.dumps(data))
    result = module.read_ingest_health()
    assert result['status'] == 'fresh' and result['state'] == 'ready'
    assert result['stats']['received'] == 100
    assert result['providers']['geoip']['status'] == 'missing'
    assert result['providers']['abuseipdb']['status'] == 'not_configured'
    assert not any(key in json.dumps(result) for key in ('secret', 'password', 'raw_log', 'api_key'))
    deps.get_conn.assert_not_called()


def test_stale_snapshot_does_not_claim_provider_readiness(route):
    module, path, _ = route
    path.write_text(json.dumps(snapshot(updated_at=time.time() - 30,
        providers={'rdns': {'status': 'ready'}})))
    result = module.read_ingest_health()
    assert result['status'] == 'stale' and result['state'] == 'unknown'
    assert result['providers']['rdns']['status'] == 'pending'


def test_legacy_retry_total_is_exposed_as_deliveries_not_actual_retries(route):
    module, path, _ = route
    path.write_text(json.dumps(snapshot(stats={'retry_attempts': 7, 'flush_errors': 0})))
    result = module.read_ingest_health()
    assert result['stats']['delivery_attempts'] == 7
    assert result['stats']['retry_attempts'] is None
    assert result['state'] == 'ready'


def test_new_delivery_and_retry_counters_keep_their_distinct_meanings(route):
    module, path, _ = route
    path.write_text(json.dumps(snapshot(stats={'delivery_attempts': 9, 'retry_attempts': 2})))
    result = module.read_ingest_health()
    assert result['stats']['delivery_attempts'] == 9
    assert result['stats']['retry_attempts'] == 2


def test_fresh_publisher_does_not_hide_stalled_ingestion_worker(route):
    module, path, _ = route
    path.write_text(json.dumps(snapshot(last_progress_at=time.time() - 60,
                                      spool={'rows': 50, 'bytes': 4000})))
    result = module.read_ingest_health()
    assert result['status'] == 'fresh' and result['state'] == 'stalled'


@pytest.mark.parametrize('payload', ['{broken', 'x' * 65537,
    json.dumps(snapshot(updated_at=float('nan'))), json.dumps(snapshot(updated_at=time.time() + 3600))])
def test_invalid_snapshots_fail_closed(route, payload):
    module, path, _ = route
    path.write_text(payload)
    assert module.read_ingest_health()['status'] == 'unavailable'


def test_snapshot_route_works_without_database(route):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    module, path, deps = route
    path.write_text(json.dumps(snapshot()))
    app = FastAPI()
    app.include_router(module.router)
    response = TestClient(app).get('/api/health/ingest')
    assert response.status_code == 200
    assert response.json()['stats']['inserted'] == 99
    deps.get_conn.assert_not_called()
