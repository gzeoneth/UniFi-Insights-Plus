"""Bounded, crash-safe staging for parsed syslog batches.

One receiver owns a spool. Its workers share one locked SQLite connection;
network operations never hold that lock. FULL-synchronous WAL commits precede
delivery. Rows remain until PostgreSQL acknowledges them; ingest_id makes an
uncertain PostgreSQL commit safe to replay. UDP/health threads do no spool IO.
"""

import datetime
import json
import os
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager


def positive_env(name, default, maximum):
    """Bound memory/disk settings even when environment input is mistaken."""
    try:
        value = int(os.environ.get(name, default))
        return min(value, maximum) if value > 0 else default
    except (TypeError, ValueError):
        return default


def _json_value(value):
    if isinstance(value, (datetime.datetime, datetime.date)):
        return value.isoformat()
    if isinstance(value, uuid.UUID):
        return str(value)
    raise TypeError(f'Unsupported ingest value: {type(value).__name__}')


def _chunks(values, size=200):
    # Below SQLite's older 999-variable limit, including four INSERT fields.
    for start in range(0, len(values), size):
        yield values[start:start + size]


class RetrySpool:
    """Bounded durable FIFO with explicit rejection of newest overflow rows.

    WAL avoids creating/removing a rollback journal for every stage and ack.
    FULL sync is retained; extra RAM caches contain copies of committed rows.
    Checkpoints normally recycle the WAL near 4 MiB. An external reader can pin
    it; writes stop at 16 MiB until checkpoint succeeds (one preceding transaction
    may exceed that threshold). Database pages and logical rows/bytes are bounded
    separately. Only one receiver may own a spool. Use local persistent storage,
    not tmpfs/NFS. Live backups need SQLite backup, not a copy of the main file.
    """

    def __init__(self, path, max_rows=100000, max_bytes=64 * 1024 * 1024):
        path = os.fspath(path)
        self.path, self.max_rows, self.max_bytes = path, max_rows, max_bytes
        self._lock = threading.RLock()
        self._metrics_lock = threading.Lock()
        self._operations = {}
        self._cache_kib = positive_env('INGEST_SPOOL_CACHE_KIB', 16384, 65536)
        self._head_max_bytes = positive_env('INGEST_SPOOL_HEAD_CACHE_BYTES', 1024 * 1024, 8 * 1024 * 1024)
        self._head_max_rows = 512
        self._head, self._head_bytes = (), 0
        self._head_complete, self._head_changes = False, -1
        self._wal_checkpoint_bytes, self._wal_max_bytes = 4 * 1024 * 1024, 16 * 1024 * 1024
        self._wal_bytes = self._checkpoint_busy = self._checkpoint_errors = 0
        if path != ':memory:':
            os.makedirs(os.path.dirname(os.path.abspath(path)), mode=0o700, exist_ok=True)
        self.conn = sqlite3.connect(path, timeout=1, check_same_thread=False)
        if path != ':memory:':
            os.chmod(path, 0o600)
        self._journal_mode = self.conn.execute('PRAGMA journal_mode=WAL').fetchone()[0].lower()
        if self._journal_mode != ('memory' if path == ':memory:' else 'wal'):
            self.conn.close()
            raise sqlite3.OperationalError('Durable ingest spool requires SQLite WAL support')
        self.conn.execute('PRAGMA synchronous=FULL')
        self.conn.execute(f'PRAGMA cache_size=-{self._cache_kib}')
        # Same connection performs checkpoints; measure them apart from commits.
        self.conn.execute('PRAGMA wal_autocheckpoint=0')
        self.conn.execute(f'PRAGMA journal_size_limit={self._wal_checkpoint_bytes}')
        page_size = self.conn.execute('PRAGMA page_size').fetchone()[0]
        self.conn.execute(f'PRAGMA max_page_count={max(64, (max_bytes * 2) // page_size)}')
        self.conn.execute('''CREATE TABLE IF NOT EXISTS pending (
            ingest_id TEXT PRIMARY KEY, payload TEXT NOT NULL,
            payload_bytes INTEGER NOT NULL, created_at REAL NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0, next_retry_at REAL NOT NULL DEFAULT 0
        )''')
        # FIFO uses rowid. The former retry-time index served no query and added
        # a write for every insert/delete/retry, including during an outage.
        self.conn.execute('DROP INDEX IF EXISTS pending_due')
        self.conn.commit()
        self._refresh_size()
        self._publish_state()

    def _refresh_size(self):
        self.rows, self.bytes = self.conn.execute(
            'SELECT COUNT(*), COALESCE(SUM(payload_bytes), 0) FROM pending').fetchone()
        oldest = self.conn.execute('SELECT created_at FROM pending ORDER BY rowid LIMIT 1').fetchone()
        self._oldest_at = oldest[0] if oldest else None

    def _publish_state(self):
        self._state = {'rows': self.rows, 'bytes': self.bytes,
                       'max_rows': self.max_rows, 'max_bytes': self.max_bytes,
                       'oldest_at': self._oldest_at,
                       'storage': {
                           'journal_mode': self._journal_mode, 'synchronous': 'FULL',
                           'cache_kib': self._cache_kib,
                           'head_cache_rows': len(self._head), 'head_cache_bytes': self._head_bytes,
                           'head_cache_max_bytes': self._head_max_bytes,
                           'wal_bytes': self._wal_bytes,
                           'wal_checkpoint_bytes': self._wal_checkpoint_bytes,
                           'wal_max_bytes': self._wal_max_bytes,
                           'checkpoint_busy': self._checkpoint_busy,
                           'checkpoint_errors': self._checkpoint_errors,
                       }}

    def _phase(self, name, phase):
        with self._metrics_lock:
            self._operations[name] = {**self._operations.get(name, {}), 'phase': phase,
                                      'phase_started_at': time.time(), '_phase_started': time.monotonic()}

    def _timing(self, name, phase, started):
        elapsed = max(0, time.monotonic() - started)
        with self._metrics_lock:
            previous = self._operations.get(name, {})
            metric = previous.get(phase, {})
            self._operations[name] = {**previous, phase: {
                'last_seconds': elapsed, 'max_seconds': max(elapsed, metric.get('max_seconds', 0)),
                'total_seconds': metric.get('total_seconds', 0) + elapsed,
                'count': metric.get('count', 0) + 1,
            }}

    @contextmanager
    def _operation(self, name):
        self._phase(name, 'waiting_lock')
        started = time.monotonic()
        self._lock.acquire()
        self._timing(name, 'lock_wait', started)
        self._phase(name, 'sql')
        try:
            yield
        except Exception:
            with self._metrics_lock:
                previous = self._operations[name]
                self._operations[name] = {**previous, 'errors': previous.get('errors', 0) + 1}
            raise
        finally:
            self._phase(name, 'idle')
            self._lock.release()

    def _read_wal_size(self):
        if self._journal_mode != 'wal':
            return 0
        try:
            return os.stat(self.path + '-wal').st_size
        except FileNotFoundError:
            return 0

    def _checkpoint(self, name):
        self._phase(name, 'checkpoint')
        started = time.monotonic()
        try:
            # Do not wait for an external reader to finish. Normal checkpoints
            # have no competing reader: all worker reads share this lock.
            self.conn.execute('PRAGMA busy_timeout=0')
            busy, _, _ = self.conn.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()
            if busy:
                self._checkpoint_busy += 1
        except sqlite3.Error:
            # Maintenance after FULL commit cannot change admission success.
            self._checkpoint_errors += 1
        finally:
            self.conn.execute('PRAGMA busy_timeout=1000')
            self._timing(name, 'checkpoint', started)
            self._phase(name, 'sql')

    def _prepare_write(self, name):
        self._wal_bytes = self._read_wal_size()
        if self._wal_bytes >= self._wal_max_bytes:
            self._checkpoint(name)
            self._wal_bytes = self._read_wal_size()
            self._publish_state()
            if self._wal_bytes >= self._wal_max_bytes:
                raise sqlite3.OperationalError('Ingest spool WAL is pinned; release external readers')

    def _committed(self, name):
        self._phase(name, 'commit')
        started = time.monotonic()
        try:
            self.conn.commit()
        finally:
            self._timing(name, 'commit', started)
        self._invalidate_head()

    def _maintenance(self, name):
        # Errors after commit must not report already-admitted rows as lost.
        try:
            self._wal_bytes = self._read_wal_size()
            if self._wal_bytes >= self._wal_checkpoint_bytes:
                self._checkpoint(name)
                self._wal_bytes = self._read_wal_size()
        except (OSError, sqlite3.Error):
            self._checkpoint_errors += 1
        self._publish_state()

    def _rollback(self):
        self.conn.rollback()
        self._invalidate_head()
        self._publish_state()

    def _invalidate_head(self):
        self._head, self._head_bytes = (), 0
        self._head_complete, self._head_changes = False, -1

    def stage(self, rows):
        """Return (admitted rows, rejected count), committing before returning."""
        with self._operation('stage'):
            self._prepare_write('stage')
            accepted, rejected = [], 0
            size, count, oldest_at = self.bytes, self.rows, self._oldest_at
            started = time.monotonic()
            for row in rows:
                if 'ingest_id' not in row:
                    row['ingest_id'] = str(uuid.uuid4())
            ids = list(dict.fromkeys(row['ingest_id'] for row in rows))
            existing = set()
            for chunk in _chunks(ids):
                placeholders = ','.join('?' for _ in chunk)
                existing.update(row[0] for row in self.conn.execute(
                    f'SELECT ingest_id FROM pending WHERE ingest_id IN ({placeholders})', chunk))
            try:
                self.conn.execute('BEGIN')
                inserts = []
                for row in rows:
                    try:
                        payload = json.dumps(row, default=_json_value, separators=(',', ':'))
                    except (ValueError, TypeError):
                        rejected += 1
                        continue
                    length = len(payload.encode('utf-8'))
                    if row['ingest_id'] in existing:
                        accepted.append(row)
                        continue
                    if count >= self.max_rows or size + length > self.max_bytes:
                        rejected += 1
                        continue
                    created_at = time.time()
                    inserts.append((row['ingest_id'], payload, length, created_at))
                    existing.add(row['ingest_id'])
                    accepted.append(row)
                    if not count:
                        oldest_at = created_at
                    count += 1
                    size += length
                for chunk in _chunks(inserts):
                    placeholders = ','.join('(?,?,?,?)' for _ in chunk)
                    self.conn.execute('INSERT INTO pending '
                                      '(ingest_id,payload,payload_bytes,created_at) VALUES ' + placeholders,
                                      [value for record in chunk for value in record])
                self._timing('stage', 'sql', started)
                self._committed('stage')
            except Exception:
                self._rollback()
                raise
            self.rows, self.bytes, self._oldest_at = count, size, oldest_at
            self._maintenance('stage')
            return accepted, rejected

    def due(self, limit, now=None):
        return self.due_batch(limit, now)[0]

    def due_batch(self, limit, now=None):
        """Return FIFO rows and retry evidence, without metadata in log rows."""
        if limit <= 0:
            return [], False
        now = time.time() if now is None else now
        with self._operation('due'):
            started = time.monotonic()
            if self._head_changes == self.conn.total_changes and (
                    len(self._head) >= limit or self._head_complete):
                result = self._head[:limit]
            else:
                # Serialized immutable cache: mutations to returned rows cannot
                # corrupt retries. Page cache handles rows beyond this RAM cap.
                result = self.conn.execute('''SELECT payload, attempts, next_retry_at FROM pending
                    ORDER BY rowid LIMIT ?''', (limit,)).fetchall()
                cached, cached_bytes = [], 0
                for row in result[:self._head_max_rows]:
                    length = len(row[0].encode('utf-8'))
                    if cached_bytes + length > self._head_max_bytes:
                        break
                    cached.append(row)
                    cached_bytes += length
                self._head, self._head_bytes = tuple(cached), cached_bytes
                self._head_complete = len(cached) == len(result) and len(result) < limit
                self._head_changes = self.conn.total_changes
                self._publish_state()
            self._timing('due', 'sql', started)
        due = []
        for row in result:
            if row[2] > now:
                break
            due.append(row)
        return [json.loads(row[0]) for row in due], any(row[1] > 0 for row in due)

    def acknowledge(self, attempted, retryable, now=None):
        """Commit removal or capped retry backoff; never expire a durable event."""
        now = time.time() if now is None else now
        retry_ids = {row['ingest_id'] for row in retryable}
        ids = list(dict.fromkeys(row['ingest_id'] for row in attempted))
        removed_ids = [value for value in ids if value not in retry_ids]
        retried_ids = [value for value in ids if value in retry_ids]
        with self._operation('acknowledge'):
            self._prepare_write('acknowledge')
            removed_count = removed_bytes = 0
            started = time.monotonic()
            try:
                self.conn.execute('BEGIN')
                for chunk in _chunks(removed_ids):
                    placeholders = ','.join('?' for _ in chunk)
                    count, size = self.conn.execute(
                        'SELECT COUNT(*),COALESCE(SUM(payload_bytes),0) FROM pending '
                        f'WHERE ingest_id IN ({placeholders})', chunk).fetchone()
                    self.conn.execute(f'DELETE FROM pending WHERE ingest_id IN ({placeholders})', chunk)
                    removed_count += count
                    removed_bytes += size
                for chunk in _chunks(retried_ids):
                    placeholders = ','.join('?' for _ in chunk)
                    self.conn.execute('''UPDATE pending SET
                        next_retry_at=? + MIN(60, (1 << MIN(attempts, 6))),
                        attempts=MIN(attempts + 1, 2147483647) WHERE ingest_id IN ('''
                                      + placeholders + ')', [now, *chunk])
                oldest = self.conn.execute('SELECT created_at FROM pending ORDER BY rowid LIMIT 1').fetchone()
                self._timing('acknowledge', 'sql', started)
                self._committed('acknowledge')
            except Exception:
                self._rollback()
                raise
            self.rows -= removed_count
            self.bytes -= removed_bytes
            self._oldest_at = oldest[0] if oldest else None
            self._maintenance('acknowledge')

    def snapshot(self):
        # No SQLite lock/IO. Copy bounded immutable metrics under a separate lock.
        state = self._state
        now = time.monotonic()
        with self._metrics_lock:
            operations = {name: {**{key: (dict(value) if isinstance(value, dict) else value)
                                    for key, value in operation.items() if not key.startswith('_')},
                                  'phase_elapsed_seconds': (max(0, now - operation['_phase_started'])
                                                            if operation['phase'] != 'idle' else 0)}
                          for name, operation in self._operations.items()}
        return {key: (dict(value) if isinstance(value, dict) else value)
                for key, value in state.items() if key != 'oldest_at'} | {
            'oldest_age_seconds': max(0, time.time() - state['oldest_at']) if state['oldest_at'] else 0,
            'operations': operations,
        }

    def close(self):
        with self._lock:
            self.conn.close()
