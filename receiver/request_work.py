"""Bound expensive API work and track numeric request/connection timings."""

import asyncio
from collections import deque
from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps
import os
import re
import threading
import time


_current = ContextVar('api_request_work', default=None)
_phases = ContextVar('api_request_phases', default=('handler',))
_leases = {}
_leases_lock = threading.Lock()
_HEAVY_PREFIXES = ('/api/logs', '/api/export', '/api/stats', '/api/dashboard',
                   '/api/flows', '/api/security/', '/api/threats', '/api/rules/',
                   '/api/services', '/api/protocols')
_LIGHT_MCP_TOOLS = frozenset(('get_health', 'get_log', 'get_unifi_status',
                              'list_interfaces', 'export_logs_csv_url'))
_TIMING_NAMES = ('auth', 'token', 'session', 'audit', 'admission', 'pool_wait',
                 'db_setup', 'query', 'commit', 'db_hold', 'handler')
_PROTECTED_PHASES = frozenset(('auth', 'token', 'session', 'audit', 'commit'))


def _setting(name, default, minimum, maximum, kind=int):
    try:
        return max(minimum, min(maximum, kind(os.environ.get(name, str(default)))))
    except (TypeError, ValueError):
        return default


class AdmissionBusy(Exception):
    pass


class RequestGone(Exception):
    pass


class HeavyGate:
    """A bounded FIFO queue that never blocks an event-loop thread."""

    def __init__(self, limit=2, waiting=8, seconds=2):
        self.limit, self.waiting, self.seconds = limit, waiting, seconds
        self._active = 0
        self._queue = deque()
        self._lock = threading.Lock()

    @classmethod
    def from_env(cls):
        return cls(_setting('API_HEAVY_REQUEST_LIMIT', 2, 1, 6),
                   _setting('API_HEAVY_WAITING_LIMIT', 8, 0, 32),
                   _setting('API_HEAVY_WAIT_SECONDS', 2, 0, 5, float))

    async def acquire(self, work):
        ticket = object()
        acquired = False
        start = time.monotonic()
        if work.disconnected.is_set():
            raise RequestGone()
        with self._lock:
            if self._active < self.limit and not self._queue:
                self._active += 1
                return
            if len(self._queue) >= self.waiting:
                raise AdmissionBusy()
            self._queue.append(ticket)
        try:
            while True:
                if work.disconnected.is_set():
                    raise RequestGone()
                with self._lock:
                    if self._queue[0] is ticket and self._active < self.limit:
                        self._queue.popleft()
                        self._active += 1
                        acquired = True
                        return
                remaining = self.seconds - (time.monotonic() - start)
                if remaining <= 0:
                    raise AdmissionBusy()
                await asyncio.sleep(min(0.02, remaining))
        finally:
            if not acquired:
                with self._lock:
                    self._queue.remove(ticket)

    def release(self):
        with self._lock:
            self._active -= 1


def current_work():
    return _current.get()


def observe(name, seconds):
    work = current_work()
    if work is not None and name in _TIMING_NAMES:
        work.observe(name, seconds)


@contextmanager
def phase(name):
    work = current_work()
    protected = work.protect_connections() if work is not None and name in _PROTECTED_PHASES else []
    try:
        token = _phases.set(_phases.get() + (name,))
        started = time.monotonic()
        try:
            yield
        finally:
            observe(name, time.monotonic() - started)
            _phases.reset(token)
    finally:
        for lease in protected:
            lease.unprotect()


def timed_phase(name):
    def decorate(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            with phase(name):
                return fn(*args, **kwargs)
        return wrapped
    return decorate


class ConnectionLease:
    def __init__(self, connection, owner, cancellable):
        self.connection, self.owner, self.cancellable = connection, owner, cancellable
        self.started = time.monotonic()
        self.active = True
        self.cancel_attempted = False
        self._protected = 0
        self._lock = threading.Lock()

    def cancel(self):
        with self._lock:
            if not self.active or not self.cancellable or self._protected:
                return
            self.cancel_attempted = True
            try:
                self.connection.cancel()
            except Exception:
                pass  # The owner discards every connection cancellation touched.

    def protect(self):
        """Serialize an existing read lease's transition into a critical phase.

        If cancellation already won, starting a commit would risk a delayed
        cancellation reaching that commit. Unwind the abandoned read instead.
        """
        with self._lock:
            if not self.active or not self.cancellable:
                return False
            if self._protected:
                self._protected += 1
                return True
            if self.cancel_attempted or self.owner.disconnected.is_set():
                raise RequestGone()
            self._protected += 1
            return True

    def unprotect(self):
        with self._lock:
            self._protected -= 1

    def deactivate(self):
        with self._lock:
            self.active = False
            return self.cancel_attempted or self.owner.disconnected.is_set()


def track_connection(connection):
    work = current_work()
    if work is None:
        return
    # Query timing may encompass checkout, but nested auth/audit/commit phases
    # must never turn their connection into a cancellable handler read.
    cancellable = work.cancel_reads and all(
        name in ('handler', 'query') for name in _phases.get())
    lease = ConnectionLease(connection, work, cancellable)
    with work._lock:
        if work.disconnected.is_set():
            raise RequestGone()
        with _leases_lock:
            if id(connection) in _leases:
                raise RuntimeError('API connection is already leased')
            _leases[id(connection)] = lease
        work._connections.add(lease)


def detach_connection(connection):
    """Deactivate before pool return, even when returned on another thread."""
    with _leases_lock:
        lease = _leases.pop(id(connection), None)
    discard = lease.deactivate() if lease is not None else False
    return lease, discard


def returned_connection(lease):
    if lease is not None:
        lease.owner.observe('db_hold', time.monotonic() - lease.started)
        with lease.owner._lock:
            lease.owner._connections.discard(lease)
            lease.owner._release_if_done()


class RequestWork:
    def __init__(self, gate, cancel_reads=False):
        self.gate, self.cancel_reads = gate, cancel_reads
        self.started = time.monotonic()
        self.disconnected = threading.Event()
        self.authenticated = False
        self.admitted = False
        self.finished = False
        self.timings = {}
        self._connections = set()
        self._lock = threading.Lock()

    def observe(self, name, seconds):
        with self._lock:
            self.timings[name] = self.timings.get(name, 0) + seconds * 1000

    def protect_connections(self):
        with self._lock:
            leases = list(self._connections)
        protected = []
        try:
            for lease in leases:
                if lease.protect():
                    protected.append(lease)
            return protected
        except BaseException:
            for lease in protected:
                lease.unprotect()
            raise

    async def admit(self):
        start = time.monotonic()
        try:
            await self.gate.acquire(self)
            self.admitted = True
        finally:
            self.observe('admission', time.monotonic() - start)

    def _release_if_done(self):
        if self.finished and self.admitted and not self._connections:
            self.admitted = False
            self.gate.release()

    def finish(self):
        with self._lock:
            self.finished = True
            self._release_if_done()

    def disconnect(self):
        with self._lock:
            if self.disconnected.is_set():
                return
            self.disconnected.set()
            active = any(lease.cancellable for lease in self._connections)
        if active:
            threading.Thread(target=self._cancel_reads, daemon=True,
                             name='api-read-cancel').start()

    def _cancel_reads(self):
        # Repeat to catch an abort arriving between statements on one lease.
        # Never cancel a returned connection; cancelled leases are discarded.
        until = time.monotonic() + 60
        while time.monotonic() < until:
            with self._lock:
                leases = [lease for lease in self._connections if lease.cancellable]
            if not leases:
                return
            for lease in leases:
                lease.cancel()
            time.sleep(0.1)

    def server_timing(self):
        with self._lock:
            values = [(name, self.timings[name]) for name in _TIMING_NAMES
                      if name in self.timings]
        values.append(('headers', (time.monotonic() - self.started) * 1000))
        return ','.join(f'{name};dur={duration:.3f}' for name, duration in values)


def _bounded_log_read(request):
    path = request.url.path
    if re.fullmatch(r'/api/logs/[0-9]{1,19}', path):
        return True
    if path != '/api/logs':
        return False
    params = request.query_params
    allowed = {'count_mode', 'pagination', 'sort', 'order', 'per_page', 'page',
               'time_range', 'time_from', 'time_to'}
    # Only the unfiltered first cursor page is independent of matching-event
    # counts. Arbitrary cursor boundaries or filters can still scan many rows.
    if (set(params) - allowed or len(params.multi_items()) != len(params)
            or params.get('count_mode') != 'none'
            or params.get('pagination') != 'cursor'
            or params.get('sort', 'timestamp') != 'timestamp'
            or params.get('order', 'desc').lower() not in ('asc', 'desc')
            or params.get('page', '1') != '1'):
        return False
    try:
        return 1 <= int(params.get('per_page', '50')) <= 100
    except ValueError:
        return False


async def expensive_request(request):
    path, method = request.url.path, request.method
    if method == 'GET':
        if _bounded_log_read(request):
            return False
        return path.startswith(_HEAVY_PREFIXES)
    if method != 'POST' or path != '/api/mcp':
        return False
    # Small ordinary JSON requests can identify health/metadata calls. Unknown
    # or large bodies share the heavy budget without an extra unbounded read.
    try:
        length = int(request.headers.get('content-length', '-1'))
        if not 0 <= length <= 65536:
            return True
        body = await request.json()
        if not isinstance(body, dict):
            return True
        if body.get('method') in ('initialize', 'ping', 'tools/list'):
            return False
        return not (body.get('method') == 'tools/call'
                    and (body.get('params') or {}).get('name') in _LIGHT_MCP_TOOLS)
    except (ValueError, TypeError, AttributeError):
        return True


class APIWorkMiddleware:
    """Own the request context and cancellation through response completion."""

    def __init__(self, app):
        self.app, self.gate = app, HeavyGate.from_env()

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http' or not scope.get('path', '').startswith('/api/'):
            return await self.app(scope, receive, send)
        cancel_reads = scope['method'] == 'GET' and scope['path'].startswith(_HEAVY_PREFIXES)
        work = RequestWork(self.gate, cancel_reads)
        token = _current.set(work)
        pending = asyncio.Queue(maxsize=1)
        pump = None

        async def pump_receive():
            try:
                while True:
                    message = await receive()
                    if message['type'] == 'http.disconnect':
                        work.disconnect()
                    await pending.put(message)
                    if message['type'] == 'http.disconnect':
                        return
            except Exception:
                work.disconnect()
                await pending.put({'type': 'http.disconnect'})

        async def forwarded_receive():
            if work.disconnected.is_set() and pending.empty():
                return {'type': 'http.disconnect'}
            return await pending.get()

        async def timed_send(message):
            if message['type'] == 'http.response.start' and work.authenticated:
                message = dict(message)
                headers = [(k, v) for k, v in message.get('headers', [])
                           if k.lower() != b'server-timing']
                headers.append((b'server-timing', work.server_timing().encode('ascii')))
                message['headers'] = headers
            await send(message)

        try:
            if cancel_reads:
                pump = asyncio.create_task(pump_receive())
            await self.app(scope, forwarded_receive if pump else receive, timed_send)
        finally:
            work.finish()
            try:
                if pump is not None:
                    pump.cancel()
                    try:
                        await pump
                    except asyncio.CancelledError:
                        pass
            finally:
                _current.reset(token)
