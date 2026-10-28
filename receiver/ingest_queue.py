"""Bounded, crash-safe staging for parsed syslog batches.

Producer and delivery workers share short serialized SQLite transactions.
No network operation holds the spool lock. Rows remain here until PostgreSQL
acknowledges them; ingest_id makes an uncertain commit safe to replay.
UDP and health threads never perform spool IO.
"""

import datetime
import json
import os
import sqlite3
import threading
import time
import uuid


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


class RetrySpool:
    """A bounded SQLite spool; capacity overflow rejects newest rows explicitly.

    Payload and row limits constrain logical use. SQLite's page limit bounds
    allocated storage too, with a small allowance for indexes and metadata.
    DELETE journaling bounds temporary disk overhead to one database copy.
    """

    def __init__(self, path, max_rows=100000, max_bytes=64 * 1024 * 1024):
        self.path = path
        self.max_rows = max_rows
        self.max_bytes = max_bytes
        self._lock = threading.RLock()
        if path != ':memory:':
            os.makedirs(os.path.dirname(os.path.abspath(path)), mode=0o700, exist_ok=True)
        self.conn = sqlite3.connect(path, timeout=1, check_same_thread=False)
        if path != ':memory:':
            os.chmod(path, 0o600)
        self.conn.execute('PRAGMA journal_mode=DELETE')
        self.conn.execute('PRAGMA synchronous=FULL')
        page_size = self.conn.execute('PRAGMA page_size').fetchone()[0]
        self.conn.execute(f'PRAGMA max_page_count={max(64, (max_bytes * 2) // page_size)}')
        self.conn.execute('''CREATE TABLE IF NOT EXISTS pending (
            ingest_id TEXT PRIMARY KEY, payload TEXT NOT NULL,
            payload_bytes INTEGER NOT NULL, created_at REAL NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0, next_retry_at REAL NOT NULL DEFAULT 0
        )''')
        self.conn.execute('CREATE INDEX IF NOT EXISTS pending_due ON pending(next_retry_at, created_at)')
        self.conn.commit()
        self._refresh_size()
        self._publish_state()

    def _refresh_size(self):
        self.rows, self.bytes = self.conn.execute(
            'SELECT COUNT(*), COALESCE(SUM(payload_bytes), 0) FROM pending'
        ).fetchone()
        oldest = self.conn.execute('SELECT created_at FROM pending ORDER BY rowid LIMIT 1').fetchone()
        self._oldest_at = oldest[0] if oldest else None

    def _publish_state(self):
        self._state = {'rows': self.rows, 'bytes': self.bytes,
                       'max_rows': self.max_rows, 'max_bytes': self.max_bytes,
                       'oldest_at': self._oldest_at}

    def stage(self, rows):
        """Return (admitted rows, rejected count), committing before returning."""
        with self._lock:
            return self._stage_locked(rows)

    def _stage_locked(self, rows):
        accepted, rejected = [], 0
        size, count = self.bytes, self.rows
        oldest_at = self._oldest_at
        try:
            with self.conn:
                for row in rows:
                    row.setdefault('ingest_id', str(uuid.uuid4()))
                    try:
                        payload = json.dumps(row, default=_json_value, separators=(',', ':'))
                    except (ValueError, TypeError):
                        rejected += 1
                        continue
                    length = len(payload.encode('utf-8'))
                    if self.conn.execute('SELECT 1 FROM pending WHERE ingest_id=?',
                                         (row['ingest_id'],)).fetchone():
                        accepted.append(row)
                        continue
                    if count >= self.max_rows or size + length > self.max_bytes:
                        rejected += 1
                        continue
                    created_at = time.time()
                    self.conn.execute('''INSERT INTO pending
                        (ingest_id, payload, payload_bytes, created_at) VALUES (?, ?, ?, ?)''',
                        (row['ingest_id'], payload, length, created_at))
                    accepted.append(row)
                    if not count:
                        oldest_at = created_at
                    count += 1
                    size += length
        except Exception:
            self._refresh_size()
            raise
        self.rows, self.bytes = count, size
        self._oldest_at = oldest_at
        self._publish_state()
        return accepted, rejected

    def due(self, limit, now=None):
        return self.due_batch(limit, now)[0]

    def due_batch(self, limit, now=None):
        """Return (rows, retrying) without putting spool metadata in log rows.

        retrying means at least one due row had a prior acknowledged delivery
        failure. A crash before acknowledgement can cause a replay without
        that evidence; PostgreSQL deduplication counts those separately.
        """
        now = time.time() if now is None else now
        with self._lock:
            # FIFO also across retries: do not let a stream of new rows starve
            # a failed older row. rowid breaks timestamp ties deterministically.
            result = self.conn.execute('''SELECT payload, attempts, next_retry_at FROM pending
                ORDER BY rowid LIMIT ?''', (limit,)).fetchall()
        due = []
        for row in result:
            if row[2] > now:
                break
            due.append(row)
        return [json.loads(row[0]) for row in due], any(row[1] > 0 for row in due)

    def acknowledge(self, attempted, retryable, now=None):
        """Remove acknowledged rows; retain failures with capped backoff forever.

        An outage duration alone never discards an already durable event.
        Each call processes at most one supplied batch, with no inline retry loop.
        """
        with self._lock:
            self._acknowledge_locked(attempted, retryable, now)

    def _acknowledge_locked(self, attempted, retryable, now=None):
        now = time.time() if now is None else now
        retry_ids = {row['ingest_id'] for row in retryable}
        removed_count, removed_bytes = 0, 0
        with self.conn:
            for row in attempted:
                ingest_id = row['ingest_id']
                if ingest_id in retry_ids:
                    self.conn.execute('''UPDATE pending SET
                        next_retry_at=? + MIN(60, (1 << MIN(attempts, 6))),
                        attempts=MIN(attempts + 1, 2147483647) WHERE ingest_id=?''',
                        (now, ingest_id))
                else:
                    stored = self.conn.execute('SELECT payload_bytes FROM pending WHERE ingest_id=?',
                                               (ingest_id,)).fetchone()
                    if stored:
                        self.conn.execute('DELETE FROM pending WHERE ingest_id=?', (ingest_id,))
                        removed_count += 1
                        removed_bytes += stored[0]
            oldest = self.conn.execute('SELECT created_at FROM pending ORDER BY rowid LIMIT 1').fetchone()
        self.rows -= removed_count
        self.bytes -= removed_bytes
        self._oldest_at = oldest[0] if oldest else None
        self._publish_state()

    def snapshot(self):
        # Immutable snapshot replacement avoids making health publication wait
        # on a disk sync. This may lag a transaction currently committing.
        state = self._state
        return {key: value for key, value in state.items() if key != 'oldest_at'} | {
            'oldest_age_seconds': max(0, time.time() - state['oldest_at']) if state['oldest_at'] else 0,
        }

    def close(self):
        with self._lock:
            self.conn.close()
