"""Request-local auth reuse preserves credential and permission checks."""

import asyncio
import importlib
import os
import sys
from types import ModuleType
from unittest.mock import MagicMock

import pytest
from fastapi import APIRouter
from fastapi.testclient import TestClient
from starlette.requests import Request

from request_auth import (clear_bearer_context, remember_bearer_context,
                          validated_bearer_context)


TOKEN = 'synthetic-api-token'


def request(token=TOKEN, state=None):
    return Request({'type': 'http', 'method': 'POST', 'path': '/api/mcp',
                    'scheme': 'https', 'server': ('insights.example', 443),
                    'headers': [(b'authorization', ('Bearer ' + token).encode())],
                    'state': state or {}})


def test_bearer_context_is_tied_to_one_request_and_credential():
    info = {'token_id': 1, 'effective_scopes': set()}
    req = request()
    remember_bearer_context(req, TOKEN, info)
    assert validated_bearer_context(req, TOKEN) is info
    assert validated_bearer_context(req, 'different-token') is None
    assert validated_bearer_context(request(), TOKEN) is None
    assert validated_bearer_context(req, None) is None
    clear_bearer_context(req)
    assert validated_bearer_context(req, TOKEN) is None


@pytest.mark.parametrize('value', [
    {'token_id': 1, 'effective_scopes': {'system.read'}},
    ('synthetic-api-token', {'token_id': 1}),
    'synthetic-api-token',
])
def test_arbitrary_state_cannot_claim_validated_credentials(value):
    req = request(state={'_uli_bearer_context': value})
    assert validated_bearer_context(req, TOKEN) is None


def test_session_context_cannot_stand_in_for_a_bearer():
    req = request()
    remember_bearer_context(req, TOKEN, {'user_id': 1, 'role_name': 'admin'})
    assert validated_bearer_context(req, TOKEN) is None


@pytest.fixture
def auth_stack(monkeypatch):
    """Real middleware, token policy and MCP routes with synthetic services."""
    for name in list(sys.modules):
        if name == 'api' or name == 'routes' or name.startswith('routes.'):
            monkeypatch.delitem(sys.modules, name, raising=False)
    dependencies = MagicMock()
    dependencies.APP_VERSION = 'synthetic-test'
    monkeypatch.setitem(sys.modules, 'deps', dependencies)
    monkeypatch.setitem(sys.modules, 'db', MagicMock())
    monkeypatch.setenv('SECRET_KEY', 'synthetic-auth-secret')
    for name in ('logs', 'security', 'retention', 'rule_usage', 'stats', 'setup',
                 'unifi', 'abuseipdb', 'health', 'threats', 'flows', 'views',
                 'migration', 'pihole', 'tokens'):
        module = ModuleType('routes.' + name)
        module.router = APIRouter()
        monkeypatch.setitem(sys.modules, module.__name__, module)
    auth = importlib.import_module('routes.auth')
    mcp = importlib.import_module('routes.mcp')
    monkeypatch.setattr(auth, '_auth_enabled', lambda: True)
    monkeypatch.setattr(auth, 'log_proxy_token', lambda: None)
    monkeypatch.setattr(mcp, '_require_mcp_enabled', lambda: None)
    monkeypatch.setattr(mcp, '_validate_origin', lambda req: None)
    monkeypatch.setattr(mcp, '_handle_tool_call', lambda name, args: {'ok': True})
    audit = MagicMock()
    monkeypatch.setattr(mcp, '_write_audit', audit)
    calls = []
    state = {'enabled': True, 'permissions': ['system.read']}

    def validate(token):
        calls.append(token)
        if not state['enabled'] or token != TOKEN:
            return None
        return {'token_id': 1, 'owner_user_id': 2, 'role_name': 'operator',
                'scopes': ['system.read', 'logs.read'],
                'user_permissions': list(state['permissions'])}

    validate.production_validator = auth._validate_api_token
    monkeypatch.setattr(auth, '_validate_api_token', validate)
    api = importlib.import_module('api')
    return api, auth, mcp, calls, state, audit


def tool_body():
    return {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
            'params': {'name': 'get_health', 'arguments': {}}}


def test_mcp_has_one_validation_per_request_and_keeps_auditing(auth_stack):
    api, auth, mcp, calls, state, audit = auth_stack
    with TestClient(api.app, base_url='https://insights.example') as client:
        for _ in range(100):
            response = client.post('/api/mcp', headers={'authorization': 'Bearer ' + TOKEN},
                                   json=tool_body())
            assert response.status_code == 200
            assert response.json()['result'].get('isError') is not True
    assert calls == [TOKEN] * 100
    assert audit.call_count == 100


def test_new_requests_observe_revocation_and_owner_permission_changes(auth_stack):
    api, auth, mcp, calls, state, audit = auth_stack
    with TestClient(api.app, base_url='https://insights.example') as client:
        def call():
            return client.post('/api/mcp', headers={'authorization': 'Bearer ' + TOKEN},
                               json=tool_body())
        assert call().json()['result'].get('isError') is not True
        state['permissions'] = []
        denied = call()
        assert denied.status_code == 200
        assert denied.json()['result']['isError'] is True
        assert denied.json()['result']['content'][0]['text'] == 'Permission denied'
        state['enabled'] = False
        assert call().status_code == 401
    assert len(calls) == 3


def test_empty_effective_scopes_are_not_replaced_by_raw_token_scopes(auth_stack):
    api, auth, mcp, calls, state, audit = auth_stack
    state['permissions'] = []
    @api.app.get('/api/logs/auth-scope-check')
    def protected():
        return {'ok': True}
    with TestClient(api.app, base_url='https://insights.example') as client:
        response = client.get('/api/logs/auth-scope-check',
                              headers={'authorization': 'Bearer ' + TOKEN})
    assert response.status_code == 403


def test_mcp_still_validates_bearer_when_global_auth_is_disabled(auth_stack, monkeypatch):
    api, auth, mcp, calls, state, audit = auth_stack
    monkeypatch.setattr(auth, '_auth_enabled', lambda: False)
    with TestClient(api.app, base_url='https://insights.example') as client:
        good = client.post('/api/mcp', headers={'authorization': 'Bearer ' + TOKEN}, json=tool_body())
        bad = client.post('/api/mcp', headers={'authorization': 'Bearer invalid'}, json=tool_body())
    assert good.status_code == 200
    assert bad.status_code == 401
    assert calls == [TOKEN, 'invalid']


def test_session_login_is_not_sufficient_for_mcp(auth_stack, monkeypatch):
    api, auth, mcp, calls, state, audit = auth_stack
    monkeypatch.setattr(auth, '_validate_session', lambda token: {
        'user_id': 2, 'role_name': 'admin'})
    with TestClient(api.app, base_url='https://insights.example') as client:
        client.cookies.set('uli_session', 'synthetic-session')
        response = client.post('/api/mcp', json=tool_body())
    assert response.status_code == 401
    assert calls == []


def test_changed_bearer_does_not_reuse_request_context(auth_stack):
    api, auth, mcp, calls, state, audit = auth_stack
    req = request('invalid')
    remember_bearer_context(req, TOKEN, {'token_id': 1, 'effective_scopes': {'system.read'}})
    assert mcp._request_token(req, 'invalid') is None
    assert calls == ['invalid']


def test_get_stream_reuses_validation_without_a_second_lookup(auth_stack, monkeypatch):
    api, auth, mcp, calls, state, audit = auth_stack
    req = request()
    info = auth.require_auth(req)
    response = asyncio.run(mcp.mcp_get(req))
    assert response.media_type == 'text/event-stream'
    assert info['effective_scopes'] == {'system.read'}
    assert calls == [TOKEN]


def test_last_used_coalesces_actual_updates_but_reads_auth_every_time(auth_stack, monkeypatch):
    """Run production token SQL against a disposable PostgreSQL schema."""
    dsn = os.environ.get('TEST_POSTGRES_DSN')
    if not dsn:
        pytest.skip('set TEST_POSTGRES_DSN for disposable PostgreSQL checks')
    import hashlib
    import hmac
    import uuid
    import psycopg2
    from concurrent.futures import ThreadPoolExecutor
    from psycopg2 import sql

    api, auth, mcp, calls, state, audit = auth_stack
    connection = psycopg2.connect(dsn)
    schema = 'auth_touch_' + uuid.uuid4().hex

    class CountingCursor:
        def __init__(self, cursor):
            self.cursor = cursor

        def __enter__(self):
            self.cursor.__enter__()
            return self

        def __exit__(self, *args):
            return self.cursor.__exit__(*args)

        def execute(self, query, params=None):
            counted.queries.append(query.strip().split()[0])
            return self.cursor.execute(query, params)

        def __getattr__(self, name):
            return getattr(self.cursor, name)

    class CountingConnection:
        queries = []
        commits = 0

        def cursor(self, *args, **kwargs):
            return CountingCursor(connection.cursor(*args, **kwargs))

        def commit(self):
            self.commits += 1
            return connection.commit()

        def rollback(self):
            return connection.rollback()

    counted = CountingConnection()
    try:
        with connection.cursor() as cursor:
            cursor.execute(sql.SQL('CREATE SCHEMA {}').format(sql.Identifier(schema)))
            cursor.execute(sql.SQL('SET search_path TO {}').format(sql.Identifier(schema)))
            cursor.execute('CREATE TABLE roles(id integer,name text,permissions text[])')
            cursor.execute('CREATE TABLE users(id integer,username text,role_id integer,is_active boolean)')
            cursor.execute('''CREATE TABLE api_tokens(id integer,token_hash text,token_salt text,
                scopes text[],client_type text,owner_user_id integer,token_prefix text,
                disabled boolean,last_used_at timestamptz)''')
            cursor.execute('CREATE TABLE touches(id integer)')
            cursor.execute('''CREATE FUNCTION record_touch() RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN INSERT INTO touches VALUES(NEW.id); RETURN NEW; END $$''')
            cursor.execute('CREATE TRIGGER touch_count AFTER UPDATE ON api_tokens '
                           'FOR EACH ROW EXECUTE FUNCTION record_touch()')
            salt = 'synthetic-salt'
            digest = hmac.new(salt.encode(), TOKEN.encode(), hashlib.sha256).hexdigest()
            cursor.execute("INSERT INTO roles VALUES(1,'operator',ARRAY['system.read'])")
            cursor.execute("INSERT INTO users VALUES(2,'synthetic-user',1,true)")
            cursor.execute("INSERT INTO api_tokens VALUES(1,%s,%s,ARRAY['system.read'],"
                           "'mcp',2,%s,false,NULL)", [digest, salt, TOKEN[:8]])
        connection.commit()
        monkeypatch.setattr(auth, 'get_conn', lambda: counted)
        monkeypatch.setattr(auth, 'put_conn', lambda conn: None)
        validator = auth._validate_api_token.production_validator
        monkeypatch.setattr(auth, '_validate_api_token', validator)
        with TestClient(api.app, base_url='https://insights.example') as client:
            def call():
                return client.post('/api/mcp', headers={'authorization': 'Bearer ' + TOKEN},
                                   json=tool_body())
            for _ in range(100):
                response = call()
                assert response.status_code == 200
                assert response.json()['result'].get('isError') is not True
            assert counted.queries.count('SELECT') == 100
            assert counted.queries.count('UPDATE') == 100
            assert counted.commits == 100
            assert audit.call_count == 100
            with connection.cursor() as cursor:
                cursor.execute('SELECT count(*) FROM touches')
                assert cursor.fetchone() == (1,)
                cursor.execute("UPDATE api_tokens SET last_used_at=NOW()-INTERVAL '61 seconds'")
                cursor.execute('TRUNCATE touches')
            connection.commit()

            def fresh_connection():
                fresh = psycopg2.connect(dsn)
                with fresh.cursor() as cursor:
                    cursor.execute(sql.SQL('SET search_path TO {}').format(sql.Identifier(schema)))
                fresh.commit()
                return fresh

            monkeypatch.setattr(auth, 'get_conn', fresh_connection)
            monkeypatch.setattr(auth, 'put_conn', lambda conn: conn.close())
            # Separate worker connections race on an expired metadata window.
            # Conditional UPDATE must recheck its predicate after row locking.
            with ThreadPoolExecutor(max_workers=8) as workers:
                refreshed = list(workers.map(validator, [TOKEN] * 32))
            assert all(info['token_id'] == 1 for info in refreshed)
            with connection.cursor() as cursor:
                cursor.execute('SELECT count(*) FROM touches')
                assert cursor.fetchone() == (1,)
                cursor.execute('SELECT last_used_at>NOW()-INTERVAL \'60 seconds\' FROM api_tokens')
                assert cursor.fetchone() == (True,)
                cursor.execute("UPDATE roles SET permissions=ARRAY[]::text[]")
            connection.commit()
            assert call().json()['result']['isError'] is True
            with connection.cursor() as cursor:
                cursor.execute('UPDATE api_tokens SET disabled=true')
            connection.commit()
            assert call().status_code == 401
    finally:
        connection.rollback()
        with connection.cursor() as cursor:
            cursor.execute('SET search_path TO public')
            cursor.execute(sql.SQL('DROP SCHEMA IF EXISTS {} CASCADE').format(sql.Identifier(schema)))
        connection.commit()
        connection.close()
