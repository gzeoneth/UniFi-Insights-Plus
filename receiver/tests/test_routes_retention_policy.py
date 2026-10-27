"""Retention policy API validation, persistence, and bounded summary reads."""

import importlib
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest


@pytest.fixture
def client(monkeypatch):
    # Only this route is reloaded; never initialize production deps/pools.
    monkeypatch.delitem(sys.modules, 'routes.retention', raising=False)
    deps = MagicMock()
    deps.enricher_db.get_config.return_value = None
    monkeypatch.setitem(sys.modules, 'deps', deps)
    db = MagicMock()
    db.Database.resolve_retention_days.return_value = SimpleNamespace(general=60, dns=10)
    monkeypatch.setitem(sys.modules, 'db', db)
    route = importlib.import_module('routes.retention')
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    app = FastAPI()
    app.include_router(route.router)
    return TestClient(app), deps.enricher_db


def test_defaults_do_not_activate_cleanup_policy(client):
    api, db = client
    response = api.get('/api/config/retention/policy')
    assert response.status_code == 200
    body = response.json()
    assert body['policy']['enabled'] is False
    assert body['inherited_general_days'] == 60
    assert body['inherited_dns_days'] == 10
    assert body['archive_deletion_enabled'] is False
    db.set_config.assert_not_called()


def test_policy_saved_as_one_validated_entry(client):
    api, db = client
    response = api.put('/api/config/retention/policy', json={
        'enabled': True, 'security_days': 180, 'firewall_allow_days': 60,
        'summaries_enabled': True})
    assert response.status_code == 200
    db.set_config.assert_called_once()
    key, saved = db.set_config.call_args.args
    assert key == 'retention_policy_v1'
    assert saved['security_days'] == 180
    assert saved['archives_enabled'] is False


def test_invalid_policy_has_no_partial_writes(client):
    api, db = client
    response = api.post('/api/config/retention/policy', json={
        'enabled': True, 'security_days': 30, 'firewall_allow_days': 60})
    assert response.status_code == 400
    db.set_config.assert_not_called()


def test_corrupt_policy_is_visible_and_can_be_replaced(client):
    api, db = client
    db.get_config.return_value = {'batch_size': -1}
    assert api.get('/api/config/retention/policy').status_code == 409
    assert api.put('/api/config/retention/policy', json={'enabled': False}).status_code == 200


def test_summary_dates_and_limits_are_bounded(client):
    api, db = client
    assert api.get('/api/retention/summaries?start=2020-01-01&end=2026-01-01').status_code == 400
    assert api.get('/api/retention/summaries?start=2026-01-02&end=2026-01-01').status_code == 400
    assert api.get('/api/retention/summaries?limit=5001').status_code == 422
    db.get_conn.assert_not_called()


def test_summary_response_is_explicit_about_scope_and_truncation(client):
    api, db = client
    cur = db.get_conn.return_value.__enter__.return_value.cursor.return_value.__enter__.return_value
    cur.fetchall.return_value = [{'log_type': 'dns', 'event_count': 5}, {'log_type': 'firewall', 'event_count': 9}]
    response = api.get('/api/retention/summaries?start=2026-01-01&end=2026-01-10&source=pihole&limit=1')
    assert response.status_code == 200
    body = response.json()
    assert body['timezone'] == 'UTC'
    assert body['truncated'] is True
    assert body['summaries'] == [{'log_type': 'dns', 'event_count': 5}]
    assert 'expired events' in body['scope']
    sql, args = cur.execute.call_args.args
    assert 'source = %s' in sql
    assert 'LIMIT %s' in sql
    assert args[-2:] == ['pihole', 2]
