"""The sanitized public snapshot works without PostgreSQL; logs stay private."""

import importlib
import json
import sys
import time
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException
from starlette.requests import Request


@pytest.fixture
def auth_health(monkeypatch, tmp_path):
    monkeypatch.setitem(sys.modules, 'deps', MagicMock())
    for name in ('routes.auth', 'routes.health'):
        monkeypatch.delitem(sys.modules, name, raising=False)
    auth = importlib.import_module('routes.auth')
    health = importlib.import_module('routes.health')
    monkeypatch.setattr(auth, 'AUTH_ENABLED', True)
    get_config = MagicMock(side_effect=RuntimeError('synthetic database outage'))
    monkeypatch.setattr(auth, 'get_config', get_config)
    status = tmp_path / 'synthetic-status.json'
    status.write_text(json.dumps({'schema_version': 1, 'updated_at': time.time(),
        'running': True, 'worker_alive': True, 'last_progress_at': time.time(),
        'stats': {'received': 3}, 'event_ip': '203.0.113.1', 'raw_log': 'Synthetic private message',
        'providers': {'rdns': {'status': 'ready', 'hostname': 'private.example'}}}))
    monkeypatch.setenv('INGEST_STATUS_PATH', str(status))
    return auth, health, get_config


def request(path, *, cookie=None):
    headers = [(b'cookie', ('uli_session=' + cookie).encode())] if cookie else []
    return Request({'type': 'http', 'method': 'GET', 'path': path, 'headers': headers})


def test_public_ingest_snapshot_skips_database_auth_and_filters_unknown_fields(auth_health):
    auth, health, get_config = auth_health
    assert auth.require_auth(request('/api/health/ingest')) is None
    snapshot = health.ingest_health()
    assert snapshot['stats']['received'] == 3
    assert snapshot['status'] == 'fresh'
    encoded = json.dumps(snapshot)
    assert '203.0.113.1' not in encoded
    assert 'Synthetic private message' not in encoded
    assert 'private.example' not in encoded
    get_config.assert_not_called()


def test_protected_route_still_checks_auth_configuration(auth_health):
    auth, _, get_config = auth_health
    with pytest.raises(RuntimeError, match='synthetic database outage'):
        auth.require_auth(request('/api/logs'))
    get_config.assert_called_once()


def test_protected_routes_and_health_lookalikes_still_require_credentials(auth_health, monkeypatch):
    auth, _, _ = auth_health
    monkeypatch.setattr(auth, '_auth_enabled', lambda: True)
    for path in ('/api/logs', '/api/config', '/api/health/ingest/private'):
        with pytest.raises(HTTPException) as error:
            auth.require_auth(request(path))
        assert error.value.status_code == 401
    session = MagicMock(return_value={'username': 'synthetic-reader'})
    monkeypatch.setattr(auth, '_validate_session', session)
    assert auth.require_auth(request('/api/logs', cookie='synthetic-session')) == {'username': 'synthetic-reader'}
    session.assert_called_once_with('synthetic-session')
