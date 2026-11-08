"""Durability, bounded caching and SQL operation regressions for the spool."""

import json
import os
import sqlite3
import threading
import time

import pytest

from ingest_queue import RetrySpool


def records(count, prefix='record', size=128):
    return [{'ingest_id': f'{prefix}-{i}', 'src_ip': '192.0.2.10', 'raw_log': 'x' * size}
            for i in range(count)]


def test_existing_delete_spool_migrates_without_losing_fifo_or_retries(tmp_path):
    path = tmp_path / 'spool.sqlite3'
    old = sqlite3.connect(path)
    old.execute('PRAGMA journal_mode=DELETE')
    old.execute('''CREATE TABLE pending (
        ingest_id TEXT PRIMARY KEY, payload TEXT NOT NULL, payload_bytes INTEGER NOT NULL,
        created_at REAL NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
        next_retry_at REAL NOT NULL DEFAULT 0)''')
    old.execute('CREATE INDEX pending_due ON pending(next_retry_at,created_at)')
    rows = records(3)
    for row in rows:
        payload = json.dumps(row)
        old.execute('INSERT INTO pending VALUES(?,?,?,?,?,?)',
                    (row['ingest_id'], payload, len(payload), 1, 2, 100))
    old.commit()
    old.close()
    spool = RetrySpool(path)
    try:
        assert spool.conn.execute('PRAGMA journal_mode').fetchone()[0] == 'wal'
        assert spool.conn.execute('PRAGMA synchronous').fetchone()[0] == 2
        assert spool.conn.execute('PRAGMA cache_size').fetchone()[0] == -16384
        assert spool.conn.execute("SELECT name FROM sqlite_master WHERE name='pending_due'").fetchall() == []
        assert spool.due(10, now=99) == []
        assert spool.due_batch(10, now=100) == (rows, True)
        assert spool.snapshot()['rows'] == 3
        assert os.stat(path).st_mode & 0o777 == 0o600
        for suffix in ('-wal', '-shm'):
            assert os.stat(str(path) + suffix).st_mode & 0o777 == 0o600
        spool.acknowledge(rows, [])
    finally:
        spool.close()


def test_sql_statements_scale_with_chunks_not_each_event(tmp_path):
    spool = RetrySpool(tmp_path / 'spool.sqlite3')
    statements = []
    spool.conn.set_trace_callback(statements.append)
    rows = records(500)
    try:
        assert spool.stage(rows) == (rows, 0)
        due = spool.due(500)
        spool.acknowledge(due, due[:100], now=100)
        selects = [sql for sql in statements if sql.lstrip().upper().startswith('SELECT')]
        inserts = [sql for sql in statements if sql.lstrip().upper().startswith('INSERT')]
        deletes = [sql for sql in statements if sql.lstrip().upper().startswith('DELETE')]
        updates = [sql for sql in statements if sql.lstrip().upper().startswith('UPDATE')]
        assert len(selects) == 7  # Three duplicate checks, due, two ack chunks, oldest.
        assert len(inserts) == 3
        assert len(deletes) == 2
        assert len(updates) == 1
        assert spool.snapshot()['rows'] == 100
        assert spool.due(500, now=100) == []
        assert spool.due(500, now=101) == rows[:100]
    finally:
        spool.close()


def test_duplicate_batch_preserves_first_payload_capacity_and_order(tmp_path):
    spool = RetrySpool(tmp_path / 'spool.sqlite3', max_rows=2)
    rows = records(3)
    try:
        duplicate = {**rows[0], 'raw_log': 'replacement must not overwrite durable payload'}
        accepted, rejected = spool.stage([rows[0], duplicate, rows[1], rows[2]])
        assert accepted == [rows[0], duplicate, rows[1]]
        assert rejected == 1
        assert spool.due(10) == rows[:2]
        spool.acknowledge([rows[0], rows[0]], [])
        assert spool.snapshot()['rows'] == 1
        assert spool.snapshot()['bytes'] > 0
        assert spool.due(10) == rows[1:2]
    finally:
        spool.close()


def test_head_cache_avoids_repeat_reads_and_is_not_mutable_by_callers(tmp_path):
    spool = RetrySpool(tmp_path / 'spool.sqlite3')
    rows = records(3)
    statements = []
    try:
        spool.stage(rows)
        spool.conn.set_trace_callback(statements.append)
        first = spool.due(10)
        first[0]['raw_log'] = 'caller changed result'
        assert spool.due(10) == rows
        assert len(statements) == 1
        spool.acknowledge(rows, rows, now=100)
        assert spool.due(10, now=100) == []
        assert spool.due_batch(10, now=101) == (rows, True)
        spool.stage(records(1, prefix='later'))
        assert len(spool.due(10, now=101)) == 4
        spool.acknowledge(rows, [])
        assert spool.due(10)[0]['ingest_id'] == 'later-0'
    finally:
        spool.close()


@pytest.mark.parametrize('cache_limit,record_count,record_size', [(300, 8, 128), (8 * 1024 * 1024, 600, 64)])
def test_head_cache_has_byte_and_row_bounds_without_truncating_delivery(
        tmp_path, monkeypatch, cache_limit, record_count, record_size):
    monkeypatch.setenv('INGEST_SPOOL_HEAD_CACHE_BYTES', str(cache_limit))
    spool = RetrySpool(tmp_path / 'spool.sqlite3')
    rows = records(record_count, size=record_size)
    try:
        spool.stage(rows)
        assert spool.due(1000) == rows
        state = spool.snapshot()['storage']
        assert state['head_cache_bytes'] <= cache_limit
        assert state['head_cache_rows'] <= 512
        assert spool.due(1000) == rows
    finally:
        spool.close()


def test_oversized_head_still_delivers_without_caching(tmp_path, monkeypatch):
    monkeypatch.setenv('INGEST_SPOOL_HEAD_CACHE_BYTES', '32')
    spool = RetrySpool(tmp_path / 'spool.sqlite3')
    try:
        rows = records(2)
        spool.stage(rows)
        assert spool.due(10) == rows
        assert spool.snapshot()['storage']['head_cache_rows'] == 0
        assert spool.snapshot()['storage']['head_cache_bytes'] == 0
    finally:
        spool.close()


def test_page_cache_env_is_bounded(tmp_path, monkeypatch):
    monkeypatch.setenv('INGEST_SPOOL_CACHE_KIB', '999999999')
    monkeypatch.setenv('INGEST_SPOOL_HEAD_CACHE_BYTES', '-1')
    spool = RetrySpool(tmp_path / 'spool.sqlite3')
    try:
        assert spool.conn.execute('PRAGMA cache_size').fetchone()[0] == -65536
        assert spool.snapshot()['storage']['head_cache_max_bytes'] == 1024 * 1024
    finally:
        spool.close()


def test_pinned_reader_wal_guard_preserves_pending_and_recovers(tmp_path):
    path = tmp_path / 'spool.sqlite3'
    spool = RetrySpool(path)
    spool._wal_checkpoint_bytes = 16 * 1024
    spool._wal_max_bytes = 64 * 1024
    admitted = records(1, prefix='initial')
    spool.stage(admitted)
    reader = sqlite3.connect(f'file:{path}?mode=ro', uri=True)
    reader.execute('BEGIN')
    reader.execute('SELECT * FROM pending').fetchall()
    try:
        for index in range(100):
            batch = records(5, prefix=f'batch-{index}', size=1024)
            try:
                spool.stage(batch)
            except sqlite3.OperationalError as exc:
                assert 'pinned' in str(exc)
                break
            admitted.extend(batch)
        else:
            pytest.fail('A pinned reader allowed unlimited WAL growth')
        assert spool.snapshot()['rows'] == len(admitted)
        assert spool.due(1000) == admitted
        assert spool.snapshot()['storage']['checkpoint_busy'] > 0
        with pytest.raises(sqlite3.OperationalError, match='pinned'):
            spool.acknowledge(admitted, [])
        assert spool.due(1000) == admitted
        assert spool.conn.execute('SELECT COUNT(*) FROM pending').fetchone()[0] == len(admitted)
        reader.rollback()
        spool.acknowledge(admitted, [])
        assert spool.snapshot()['rows'] == spool.snapshot()['bytes'] == 0
        assert spool.conn.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
        spool.stage(records(1, prefix='recovered'))
        assert spool.due(10)[0]['ingest_id'] == 'recovered-0'
    finally:
        reader.close()
        spool.close()


def test_checkpoint_error_after_commit_does_not_turn_admission_into_failure(tmp_path, monkeypatch):
    path = tmp_path / 'spool.sqlite3'
    spool = RetrySpool(path)
    spool._wal_checkpoint_bytes = 1
    monkeypatch.setattr(spool, '_checkpoint', lambda _: (_ for _ in ()).throw(sqlite3.OperationalError('busy')))
    rows = records(2)
    try:
        assert spool.stage(rows) == (rows, 0)
        assert spool.snapshot()['rows'] == 2
        assert spool.snapshot()['storage']['checkpoint_errors'] == 1
        reopened = sqlite3.connect(f'file:{path}?mode=ro', uri=True)
        try:
            assert reopened.execute('SELECT COUNT(*) FROM pending').fetchone()[0] == 2
        finally:
            reopened.close()
        spool.acknowledge(rows, [])
        assert spool.snapshot()['rows'] == 0
        assert spool.snapshot()['storage']['checkpoint_errors'] == 2
    finally:
        spool.close()


def test_failed_ack_transaction_preserves_cached_and_durable_rows(tmp_path):
    spool = RetrySpool(tmp_path / 'spool.sqlite3')
    rows = records(2)
    try:
        spool.stage(rows)
        spool.due(10)
        before = spool.snapshot()
        spool.conn.execute("""CREATE TRIGGER reject_delete BEFORE DELETE ON pending
                              BEGIN SELECT RAISE(ABORT, 'simulated failure'); END""")
        with pytest.raises(sqlite3.IntegrityError, match='simulated failure'):
            spool.acknowledge(rows, [])
        assert spool.due(10) == rows
        assert spool.snapshot()['rows'] == before['rows']
        assert spool.snapshot()['bytes'] == before['bytes']
        spool.conn.execute('DROP TRIGGER reject_delete')
        spool.acknowledge(rows, [])
        assert spool.snapshot()['rows'] == 0
    finally:
        spool.close()


def test_lock_wait_and_commit_are_visible_without_blocking_health(tmp_path):
    spool = RetrySpool(tmp_path / 'spool.sqlite3')
    entered, release = threading.Event(), threading.Event()
    connection = spool.conn

    class SlowCommit:
        def __getattr__(self, name):
            return getattr(connection, name)

        def commit(self):
            entered.set()
            assert release.wait(2)
            connection.commit()

    spool.conn = SlowCommit()
    thread = threading.Thread(target=spool.stage, args=(records(1),))
    try:
        spool._lock.acquire()
        thread.start()
        deadline = time.monotonic() + 1
        while 'stage' not in spool.snapshot()['operations'] and time.monotonic() < deadline:
            time.sleep(0.001)
        waiting = spool.snapshot()['operations']['stage']
        assert waiting['phase'] == 'waiting_lock'
        assert waiting['phase_started_at'] > 0
        spool._lock.release()
        assert entered.wait(1)
        committing = spool.snapshot()
        assert committing['rows'] == 0
        assert committing['operations']['stage']['phase'] == 'commit'
        assert committing['operations']['stage']['lock_wait']['count'] == 1
        release.set()
        thread.join(2)
        assert not thread.is_alive()
        committed = spool.snapshot()
        assert committed['rows'] == 1
        assert committed['operations']['stage']['phase'] == 'idle'
        assert committed['operations']['stage']['commit']['count'] == 1
        assert committed['operations']['stage']['commit']['last_seconds'] > 0
        committed['storage']['cache_kib'] = 0
        committed['operations']['stage']['commit']['count'] = 0
        assert spool.snapshot()['storage']['cache_kib'] > 0
        assert spool.snapshot()['operations']['stage']['commit']['count'] == 1
    finally:
        release.set()
        thread.join(2)
        spool.close()
