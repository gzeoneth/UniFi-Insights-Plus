"""Admission, request cancellation, and connection ownership regressions."""

import asyncio
import importlib.util
import os
from pathlib import Path
import re
import sys
import threading
import time
from unittest.mock import MagicMock

import httpx
import psycopg2
from psycopg2 import extensions
import pytest
from starlette.requests import Request

from read_cache import ReadCache
import request_work as rw
from tests.test_request_auth import auth_stack, TOKEN


@pytest.fixture
def real_deps(monkeypatch):
    """Load production pool functions without starting integration clients."""
    with monkeypatch.context() as patches:
        for name in ('db', 'enrichment', 'unifi_api', 'pihole_api'):
            patches.setitem(sys.modules, name, MagicMock())
        patches.setattr(psycopg2.pool, 'ThreadedConnectionPool', MagicMock())
        spec = importlib.util.spec_from_file_location(
            '_request_work_test_deps', Path(__file__).parents[1] / 'deps.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    return module


def connection():
    conn = MagicMock()
    conn.closed = False
    conn.info.transaction_status = extensions.TRANSACTION_STATUS_IDLE
    return conn


def test_gate_bounds_queue_wait_and_releases_fifo():
    async def run():
        gate = rw.HeavyGate(limit=1, waiting=1, seconds=0.2)
        first, second, third = [rw.RequestWork(gate) for _ in range(3)]
        await first.admit()
        queued = asyncio.create_task(second.admit())
        await asyncio.sleep(0.03)
        with pytest.raises(rw.AdmissionBusy):
            await third.admit()
        first.finish()
        await asyncio.wait_for(queued, 0.2)
        assert second.admitted and gate._active == 1
        second.finish()
        assert gate._active == 0 and not gate._queue
        await first.admit()
        with pytest.raises(rw.AdmissionBusy):
            await third.admit()
        first.finish()
        assert not gate._queue
    asyncio.run(run())


def test_cancelled_waiter_does_not_leak_gate_capacity():
    async def run():
        gate = rw.HeavyGate(limit=1)
        active, waiting = rw.RequestWork(gate), rw.RequestWork(gate)
        await active.admit()
        task = asyncio.create_task(waiting.admit())
        await asyncio.sleep(0.03)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert not gate._queue
        active.finish()
        assert gate._active == 0
    asyncio.run(run())


def test_gate_keeps_slot_until_abandoned_connection_is_returned(real_deps):
    async def run():
        work = rw.RequestWork(rw.HeavyGate(limit=1), cancel_reads=True)
        await work.admit()
        token = rw._current.set(work)
        conn = connection()
        try:
            rw.track_connection(conn)
            lease = next(iter(work._connections))
            work.disconnect()
            work.finish()
            assert work.gate._active == 1
            real_deps.put_conn(conn)
            real_deps.db_pool.putconn.assert_called_once_with(conn, close=True)
            assert work.gate._active == 0
            cancels = conn.cancel.call_count
            lease.cancel()  # A delayed cancellation cannot target a new borrower.
            assert conn.cancel.call_count == cancels
        finally:
            rw._current.reset(token)
    asyncio.run(run())


@pytest.mark.parametrize('phase_name', ['auth', 'token', 'session', 'audit'])
def test_auth_and_audit_connections_are_never_cancelled(real_deps, phase_name):
    work = rw.RequestWork(rw.HeavyGate(), cancel_reads=True)
    token = rw._current.set(work)
    conn = connection()
    try:
        with rw.phase(phase_name), rw.phase('query'):
            rw.track_connection(conn)
        lease = next(iter(work._connections))
        assert not lease.cancellable
        work.disconnect()
        lease.cancel()
        conn.cancel.assert_not_called()
        real_deps.put_conn(conn)
        real_deps.db_pool.putconn.assert_called_once_with(conn, close=True)
    finally:
        rw._current.reset(token)


def test_query_timing_does_not_hide_a_cancellable_read(real_deps):
    work = rw.RequestWork(rw.HeavyGate(), cancel_reads=True)
    token = rw._current.set(work)
    conn = connection()
    try:
        with rw.phase('query'):
            rw.track_connection(conn)
        lease = next(iter(work._connections))
        assert lease.cancellable
        lease.cancel()
        conn.cancel.assert_called_once()
        real_deps.put_conn(conn)
        real_deps.db_pool.putconn.assert_called_once_with(conn, close=True)
    finally:
        rw._current.reset(token)


@pytest.mark.parametrize('phase_name', ['auth', 'token', 'session', 'audit', 'commit'])
def test_existing_read_lease_is_protected_during_critical_phase(real_deps, phase_name):
    work = rw.RequestWork(rw.HeavyGate(), cancel_reads=True)
    token = rw._current.set(work)
    conn = connection()
    try:
        rw.track_connection(conn)
        lease = next(iter(work._connections))
        assert lease.cancellable
        with rw.phase(phase_name):
            work.disconnected.set()
            lease.cancel()
            conn.cancel.assert_not_called()
            conn.commit()
        conn.commit.assert_called_once()
        real_deps.put_conn(conn)
        real_deps.db_pool.putconn.assert_called_once_with(conn, close=True)
    finally:
        rw._current.reset(token)


def test_cancellation_before_commit_refuses_the_existing_read_commit(real_deps):
    work = rw.RequestWork(rw.HeavyGate(), cancel_reads=True)
    token = rw._current.set(work)
    conn = connection()
    try:
        rw.track_connection(conn)
        lease = next(iter(work._connections))
        lease.cancel()
        with pytest.raises(rw.RequestGone):
            with rw.phase('commit'):
                conn.commit()
        conn.commit.assert_not_called()
        real_deps.put_conn(conn)
        real_deps.db_pool.putconn.assert_called_once_with(conn, close=True)
    finally:
        rw._current.reset(token)


def test_nested_critical_phase_inherits_protection_that_won_before_disconnect(real_deps):
    work = rw.RequestWork(rw.HeavyGate(), cancel_reads=True)
    token = rw._current.set(work)
    conn = connection()
    try:
        rw.track_connection(conn)
        lease = next(iter(work._connections))
        with rw.phase('audit'):
            work.disconnected.set()
            with rw.phase('commit'):
                lease.cancel()
                conn.commit()
            assert lease._protected == 1
            lease.cancel()
            conn.cancel.assert_not_called()
        assert lease._protected == 0
        conn.commit.assert_called_once()
        real_deps.put_conn(conn)
        real_deps.db_pool.putconn.assert_called_once_with(conn, close=True)
    finally:
        rw._current.reset(token)


def test_commit_transition_waits_for_inflight_cancel_then_refuses(real_deps):
    work = rw.RequestWork(rw.HeavyGate(), cancel_reads=True)
    token = rw._current.set(work)
    conn = connection()
    began, release = threading.Event(), threading.Event()
    outcome = []
    def cancel_call():
        began.set()
        assert release.wait(2)
    conn.cancel.side_effect = cancel_call
    def commit():
        context = rw._current.set(work)
        try:
            with rw.phase('commit'):
                conn.commit()
        except rw.RequestGone:
            outcome.append('refused')
        finally:
            rw._current.reset(context)
    try:
        rw.track_connection(conn)
        lease = next(iter(work._connections))
        cancelling = threading.Thread(target=lease.cancel)
        cancelling.start()
        assert began.wait(1)
        committing = threading.Thread(target=commit)
        committing.start()
        assert not outcome
        release.set()
        cancelling.join(1)
        committing.join(1)
        assert outcome == ['refused']
        conn.commit.assert_not_called()
        real_deps.put_conn(conn)
        real_deps.db_pool.putconn.assert_called_once_with(conn, close=True)
    finally:
        release.set()
        rw._current.reset(token)


def test_abandoned_context_cannot_checkout_another_connection(real_deps):
    work = rw.RequestWork(rw.HeavyGate(), cancel_reads=True)
    token = rw._current.set(work)
    try:
        work.disconnect()
        with pytest.raises(rw.RequestGone):
            real_deps.get_conn()
        real_deps.db_pool.getconn.assert_not_called()
    finally:
        rw._current.reset(token)


def test_disconnect_during_checkout_discards_before_setup(real_deps):
    work = rw.RequestWork(rw.HeavyGate(), cancel_reads=True)
    token = rw._current.set(work)
    conn = connection()
    def checkout():
        work.disconnect()
        return conn
    real_deps.db_pool.getconn.side_effect = checkout
    try:
        with pytest.raises(rw.RequestGone):
            real_deps.get_conn()
        conn.cursor.assert_not_called()
        real_deps.db_pool.putconn.assert_called_once_with(conn, close=True)
    finally:
        rw._current.reset(token)


def test_cancelled_metadata_waiter_does_not_cancel_other_loader():
    cache = ReadCache()
    started, release = threading.Event(), threading.Event()
    def load():
        started.set()
        assert release.wait(2)
        return {'value': 1}
    loader = threading.Thread(target=lambda: cache.get_or_load('key', load))
    loader.start()
    assert started.wait(1)
    work = rw.RequestWork(rw.HeavyGate(), cancel_reads=True)
    result = []
    def wait():
        token = rw._current.set(work)
        try:
            cache.get_or_load('key', lambda: pytest.fail('duplicate loader'))
        except rw.RequestGone:
            result.append('cancelled')
        finally:
            rw._current.reset(token)
    waiter = threading.Thread(target=wait)
    waiter.start()
    work.disconnect()
    waiter.join(1)
    assert result == ['cancelled'] and loader.is_alive()
    release.set()
    loader.join(1)
    assert cache.get_or_load('key', lambda: pytest.fail('lost result')) == {'value': 1}


@pytest.mark.parametrize('path,query,heavy', [
    ('/api/logs', 'count_mode=none&pagination=cursor', False),
    ('/api/logs', 'count_mode=none&pagination=cursor&sort=timestamp&per_page=100&page=1&time_range=24h', False),
    ('/api/logs/123', '', False),
    ('/api/logs/123/other', '', True),
    ('/api/logs/aggregate', '', True),
    ('/api/logs', 'count_mode=exact&pagination=cursor', True),
    ('/api/logs', 'count_mode=none&pagination=offset', True),
    ('/api/logs', 'count_mode=none&pagination=cursor&per_page=1000', True),
    ('/api/logs', 'count_mode=none&pagination=cursor&search=rare', True),
    ('/api/logs', 'count_mode=none&pagination=cursor&src_ip=192.0.2.1', True),
    ('/api/logs', 'count_mode=none&pagination=cursor&cursor=untrusted-boundary', True),
    ('/api/logs', 'count_mode=none&pagination=cursor&page=2', True),
    ('/api/logs', 'count_mode=none&pagination=cursor&sort=rule_name', True),
    ('/api/logs', 'count_mode=none&pagination=cursor&count_mode=exact', True),
    ('/api/logs', 'count_mode=none&pagination=cursor&per_page=invalid', True),
])
def test_only_bounded_log_reads_bypass_heavy_admission(path, query, heavy):
    request = Request({'type': 'http', 'method': 'GET', 'path': path,
                       'query_string': query.encode(), 'headers': []})
    assert asyncio.run(rw.expensive_request(request)) is heavy


def test_overload_preserves_auth_health_and_light_mcp(auth_stack, monkeypatch):
    api, auth, mcp, calls, state, audit = auth_stack
    monkeypatch.setenv('API_HEAVY_REQUEST_LIMIT', '1')
    monkeypatch.setenv('API_HEAVY_WAITING_LIMIT', '0')
    monkeypatch.setenv('API_HEAVY_WAIT_SECONDS', '0')
    state['permissions'] = ['system.read', 'logs.read']
    started, release = threading.Event(), threading.Event()
    @api.app.get('/api/logs/admission-test')
    def heavy():
        started.set()
        assert release.wait(3)
        return {'ok': True}
    @api.app.get('/api/logs')
    def quick_page():
        return {'data': []}
    @api.app.get('/api/health/ingest')
    def health():
        return {'ok': True}
    @api.app.get('/api/system/timing-test')
    def light():
        return {'ok': True}
    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=api.app),
                                    base_url='https://insights.example') as client:
            headers = {'authorization': 'Bearer ' + TOKEN}
            active = asyncio.create_task(client.get('/api/logs/admission-test', headers=headers))
            assert await asyncio.to_thread(started.wait, 1)
            try:
                overloaded = await client.get('/api/logs/admission-test', headers=headers)
                assert overloaded.status_code == 503
                assert overloaded.headers['retry-after'] == '1'
                denied = await client.get('/api/logs/admission-test',
                                          headers={'authorization': 'Bearer invalid'})
                assert denied.status_code == 401 and 'server-timing' not in denied.headers
                health = await client.get('/api/health/ingest')
                assert health.status_code == 200 and 'server-timing' not in health.headers
                light = await client.get('/api/system/timing-test', headers=headers)
                assert light.status_code == 200
                timing = light.headers['server-timing']
                assert re.fullmatch(r'[a-z_]+;dur=\d+\.\d{3}(,[a-z_]+;dur=\d+\.\d{3})*', timing)
                assert TOKEN not in timing and 'insights' not in timing
                quick = await client.get('/api/logs?count_mode=none&pagination=cursor', headers=headers)
                assert quick.status_code == 200
                counted = await client.get('/api/logs?count_mode=exact&pagination=cursor', headers=headers)
                assert counted.status_code == 503
                body = {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
                        'params': {'name': 'aggregate_logs', 'arguments': {}}}
                heavy_mcp = await client.post('/api/mcp', headers=headers, json=body)
                assert heavy_mcp.status_code == 503
                body['params']['name'] = 'get_health'
                light_mcp = await client.post('/api/mcp', headers=headers, json=body)
                assert light_mcp.status_code == 200 and light_mcp.json()['result']
                assert audit.call_count == 1
            finally:
                release.set()
                assert (await active).status_code == 200
            assert (await client.get('/api/logs/admission-test', headers=headers)).status_code == 200
        assert calls.count(TOKEN) == 8  # Every protected request revalidates.
    asyncio.run(run())


def test_asgi_disconnect_is_observed_and_context_is_cleared():
    async def run():
        incoming = asyncio.Queue()
        incoming.put_nowait({'type': 'http.request', 'body': b'', 'more_body': False})
        seen, sent = [], []
        async def app(scope, receive, send):
            work = rw.current_work()
            seen.append(work)
            work.authenticated = True
            await receive()
            incoming.put_nowait({'type': 'http.disconnect'})
            for _ in range(100):
                if work.disconnected.is_set():
                    break
                await asyncio.sleep(0.001)
            assert work.disconnected.is_set()
            await send({'type': 'http.response.start', 'status': 200, 'headers': []})
            await send({'type': 'http.response.body', 'body': b'{}'})
        async def send(message):
            sent.append(message)
        await rw.APIWorkMiddleware(app)(
            {'type': 'http', 'method': 'GET', 'path': '/api/stats/test'},
            incoming.get, send)
        assert seen[0].finished and rw.current_work() is None
        assert b'server-timing' in dict(sent[0]['headers'])
    asyncio.run(run())


def test_full_middleware_disconnect_cancels_only_owned_read(auth_stack, real_deps):
    api, auth, mcp, calls, state, audit = auth_stack
    state['permissions'] = ['system.read', 'logs.read']
    conn = connection()
    real_deps.db_pool.getconn.return_value = conn
    started, cancelled = threading.Event(), threading.Event()
    conn.cancel.side_effect = cancelled.set
    seen = []
    @api.app.get('/api/logs/disconnect-test')
    def heavy():
        owned = real_deps.get_conn()
        seen.append(rw.current_work())
        started.set()
        try:
            assert cancelled.wait(2)
        finally:
            real_deps.put_conn(owned)
        return {'ok': True}
    async def run():
        incoming = asyncio.Queue()
        incoming.put_nowait({'type': 'http.request', 'body': b'', 'more_body': False})
        async def send(message):
            pass
        scope = {'type': 'http', 'http_version': '1.1', 'method': 'GET',
                 'path': '/api/logs/disconnect-test', 'raw_path': b'/api/logs/disconnect-test',
                 'query_string': b'', 'scheme': 'https',
                 'server': ('insights.example', 443), 'client': ('192.0.2.1', 12345),
                 'headers': [(b'host', b'insights.example'),
                             (b'authorization', ('Bearer ' + TOKEN).encode())]}
        task = asyncio.create_task(api.app(scope, incoming.get, send))
        assert await asyncio.to_thread(started.wait, 1)
        incoming.put_nowait({'type': 'http.disconnect'})
        await asyncio.wait_for(task, 3)
        assert rw.current_work() is None
    asyncio.run(run())
    assert conn.cancel.call_count >= 1
    real_deps.db_pool.putconn.assert_called_once_with(conn, close=True)
    assert seen[0].finished and not seen[0]._connections
    assert seen[0].gate._active == 0


def test_postgres_cancel_discards_backend_before_next_borrower(real_deps):
    dsn = os.environ.get('TEST_POSTGRES_DSN')
    if not dsn:
        pytest.skip('TEST_POSTGRES_DSN not configured')
    assert 'test' in psycopg2.extensions.parse_dsn(dsn).get('dbname', '').lower()
    pool = psycopg2.pool.ThreadedConnectionPool(1, 1, dsn)
    real_deps.db_pool = pool
    work = rw.RequestWork(rw.HeavyGate(), cancel_reads=True)
    started = threading.Event()
    result = {}
    def query():
        token = rw._current.set(work)
        conn = None
        try:
            conn = real_deps.get_conn()
            result['old'] = conn
            result['pid'] = conn.get_backend_pid()
            started.set()
            with conn.cursor() as cur:
                cur.execute('SELECT pg_sleep(10)')
        except psycopg2.errors.QueryCanceled:
            result['cancelled'] = True
        finally:
            if conn is not None:
                real_deps.put_conn(conn)
            rw._current.reset(token)
    worker = threading.Thread(target=query)
    try:
        worker.start()
        assert started.wait(2)
        began = time.monotonic()
        work.disconnect()
        worker.join(3)
        assert not worker.is_alive() and result.get('cancelled')
        assert time.monotonic() - began < 3
        assert result['old'].closed
        later = pool.getconn()
        try:
            assert later.get_backend_pid() != result['pid']
            with later.cursor() as cur:
                cur.execute('SELECT pg_sleep(0.25), 1')
                assert cur.fetchone()[1] == 1
        finally:
            pool.putconn(later)
        assert not work._connections
    finally:
        worker.join(11)
        pool.closeall()
