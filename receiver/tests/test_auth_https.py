"""Exercise real auth handlers with direct TLS and authenticated proxy headers."""

import importlib
import sys
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from starlette.requests import Request


@pytest.fixture
def auth(monkeypatch):
    monkeypatch.setenv('SECRET_KEY', 'synthetic-test-secret')
    monkeypatch.setitem(sys.modules, 'deps', MagicMock())
    monkeypatch.setitem(sys.modules, 'routes.setup', MagicMock())
    monkeypatch.delitem(sys.modules, 'routes.auth', raising=False)
    module = importlib.import_module('routes.auth')
    monkeypatch.setattr(module, 'get_config', lambda db, key, default=None: default)
    monkeypatch.setattr(module, '_auth_enabled', lambda: True)
    monkeypatch.setattr(module, '_has_users', lambda: True)
    monkeypatch.setattr(module, '_has_admin', lambda: True)
    return module


def request(scheme='https', headers=None):
    return Request({
        'type': 'http', 'method': 'GET', 'path': '/api/auth/status',
        'scheme': scheme, 'server': ('insights.example', 8000),
        'client': ('203.0.113.5', 12345),
        'headers': [(key.encode(), value.encode()) for key, value in (headers or {}).items()],
    })


def test_native_https_status_does_not_require_a_proxy_header(auth):
    status = auth.auth_status(request())
    assert status['is_https'] is True
    assert status['proxy_trusted'] is False
    auth._require_https(request())
    assert auth.get_real_client_ip(request()) == '203.0.113.5'


@pytest.mark.parametrize('token', [None, 'wrong-proxy-token'])
def test_http_cannot_claim_https_or_another_client_without_proxy_secret(auth, token):
    headers = {'x-forwarded-proto': 'https', 'x-forwarded-for': '198.51.100.5'}
    if token:
        headers['x-uli-proxy-auth'] = token
    req = request('http', headers)
    assert auth.get_forwarded_proto(req) == 'http'
    assert auth.get_real_client_ip(req) == '203.0.113.5'
    with pytest.raises(HTTPException) as error:
        auth._require_https(req)
    assert error.value.status_code == 403


def test_authenticated_https_proxy_keeps_working_over_http(auth):
    req = request('http', {
        'x-forwarded-proto': 'https', 'x-forwarded-for': '198.51.100.5',
        'x-uli-proxy-auth': auth.PROXY_AUTH_TOKEN,
    })
    auth._require_https(req)
    assert auth.get_real_client_ip(req) == '198.51.100.5'
    status = auth.auth_status(req)
    assert status['is_https'] is True
    assert status['proxy_trusted'] is True


def test_native_https_ignores_untrusted_forwarded_http(auth):
    req = request('https', {'x-forwarded-proto': 'http'})
    assert auth.get_forwarded_proto(req) == 'https'
    auth._require_https(req)


def test_direct_https_login_sets_secure_session_cookie(auth, monkeypatch):
    cursor = auth.get_conn.return_value.cursor.return_value.__enter__.return_value
    cursor.fetchone.return_value = {
        'id': 1, 'username': 'test-admin', 'password_hash': 'synthetic-hash', 'is_active': True,
    }
    for name in ('_check_rate_limit', '_clear_attempts', '_write_audit'):
        monkeypatch.setattr(auth, name, MagicMock())
    monkeypatch.setattr(auth.bcrypt, 'checkpw', lambda *args: True)
    monkeypatch.setattr(auth, '_create_session', lambda *args: 'synthetic-session')
    app = FastAPI()
    app.include_router(auth.router)
    with TestClient(app, base_url='https://insights.example:8000') as client:
        response = client.post('/api/auth/login', json={'username': 'test-admin', 'password': 'test-password'})
    assert response.status_code == 200
    cookie = response.headers['set-cookie']
    assert 'uli_session=synthetic-session' in cookie
    assert 'HttpOnly' in cookie
    assert 'Secure' in cookie
    assert 'SameSite=lax' in cookie
    assert 'Path=/' in cookie


def test_http_login_is_rejected_before_checking_credentials(auth):
    app = FastAPI()
    app.include_router(auth.router)
    with TestClient(app, base_url='http://insights.example:8000') as client:
        response = client.post('/api/auth/login', json={'username': 'test-admin', 'password': 'test-password'})
    assert response.status_code == 403
    auth.get_conn.assert_not_called()
