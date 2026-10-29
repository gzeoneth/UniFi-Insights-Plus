"""Coalesced successful acknowledgements retain durable replay guarantees."""

import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import threading
import time

import pytest

from ingest_queue import RetrySpool


def rows(count, prefix='event'):
    return [{'ingest_id': f'{prefix}-{i}', 'src_ip': '192.0.2.10', 'raw_log': 'test ' * 50}
            for i in range(count)]


def stored_ids(spool):
    return [row[0] for row in spool.conn.execute('SELECT ingest_id FROM pending ORDER BY rowid')]


def test_successful_ack_has_no_write_until_combined_with_next_admission(tmp_path):
    spool = RetrySpool(tmp_path / 'spool.sqlite3')
    first, second = rows(3), rows(2, 'later')
    try:
        spool.stage(first)
        statements = []
        spool.conn.set_trace_callback(statements.append)
        spool.acknowledge(first[:2], [], defer_success=True)
        assert not any(sql.startswith(('BEGIN', 'DELETE', 'UPDATE', 'COMMIT')) for sql in statements)
        assert stored_ids(spool) == [row['ingest_id'] for row in first]
        assert spool.due(10) == first[2:]
        state = spool.snapshot()
        assert state['rows'] == 1 and state['stored_rows'] == 3 and state['ack_pending_rows'] == 2
        assert state['ack_pending_bytes'] > 0 and state['bytes'] > 0
        statements.clear()
        assert spool.stage(second) == (second, 0)
        assert statements.count('COMMIT') == 1
        assert stored_ids(spool) == [row['ingest_id'] for row in first[2:] + second]
        assert spool.due(10) == first[2:] + second
        assert spool.snapshot()['ack_pending_rows'] == 0
        assert spool.conn.execute('PRAGMA synchronous').fetchone()[0] == 2
    finally:
        spool.close()


def test_ack_age_flushes_idle_completed_rows_and_preserves_fifo(tmp_path, monkeypatch):
    clock = [100.0]
    monkeypatch.setattr('ingest_queue.time.monotonic', lambda: clock[0])
    spool = RetrySpool(tmp_path / 'spool.sqlite3')
    data = rows(4)
    try:
        spool.stage(data)
        spool.acknowledge([data[1], data[3]], [], defer_success=True)
        assert spool.due(2) == [data[0], data[2]]
        clock[0] = 100.999
        assert not spool.flush_acknowledgements()
        assert spool.snapshot()['ack_pending_age_seconds'] == pytest.approx(.999)
        clock[0] = 101.0
        assert spool.flush_acknowledgements()
        assert spool.snapshot()['stored_rows'] == 2
        assert spool.snapshot()['ack_pending_rows'] == 0
        assert spool.snapshot()['ack_pending_age_seconds'] == 0
        assert not spool.flush_acknowledgements(force=True)
    finally:
        spool.close()


def test_process_death_before_ack_flush_replays_original_durable_ids(tmp_path):
    path = tmp_path / 'spool.sqlite3'
    script = '''
import os, sys
from ingest_queue import RetrySpool
spool = RetrySpool(sys.argv[1])
rows = [{'ingest_id': 'event-' + str(i), 'raw_log': 'synthetic'} for i in range(300)]
spool.stage(rows)
spool.acknowledge(rows, [], defer_success=True)
assert spool.rows == 0 and spool.snapshot()['ack_pending_rows'] == 300
os._exit(17)
'''
    env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1]))
    result = subprocess.run([sys.executable, '-c', script, str(path)], env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
    assert result.returncode == 17, result.stderr.decode()
    spool = RetrySpool(path)
    try:
        assert [row['ingest_id'] for row in spool.due(500)] == [f'event-{i}' for i in range(300)]
        assert spool.snapshot()['ack_pending_rows'] == 0
        assert spool.conn.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
    finally:
        spool.close()


def test_stage_rollback_keeps_completed_ids_and_new_admission_separate(tmp_path):
    spool = RetrySpool(tmp_path / 'spool.sqlite3')
    original, new = rows(3), rows(1, 'later')
    try:
        spool.stage(original)
        spool.acknowledge(original[:2], [], defer_success=True)
        spool.conn.execute("CREATE TRIGGER reject_insert BEFORE INSERT ON pending BEGIN SELECT RAISE(ABORT,'test failure'); END")
        with pytest.raises(sqlite3.IntegrityError, match='test failure'):
            spool.stage(new)
        assert spool.snapshot()['rows'] == 1
        assert spool.snapshot()['ack_pending_rows'] == 2
        assert stored_ids(spool) == [row['ingest_id'] for row in original]
        assert spool.due(10) == original[2:]
        spool.conn.execute('DROP TRIGGER reject_insert')
        assert spool.stage(new) == (new, 0)
        assert spool.due(10) == original[2:] + new
        assert spool.snapshot()['stored_rows'] == 2
    finally:
        spool.close()


def test_ack_flush_rollback_retains_retryable_deletion_and_logical_counts(tmp_path):
    spool = RetrySpool(tmp_path / 'spool.sqlite3')
    data = rows(3)
    try:
        spool.stage(data)
        spool.acknowledge(data[:2], [], defer_success=True)
        spool.conn.execute("CREATE TRIGGER reject_delete BEFORE DELETE ON pending BEGIN SELECT RAISE(ABORT,'test failure'); END")
        with pytest.raises(sqlite3.IntegrityError, match='test failure'):
            spool.flush_acknowledgements(force=True)
        assert spool.due(10) == data[2:]
        assert spool.snapshot()['rows'] == 1
        assert spool.snapshot()['ack_pending_rows'] == 2
        assert len(stored_ids(spool)) == 3
        spool.conn.execute('DROP TRIGGER reject_delete')
        assert spool.flush_acknowledgements(force=True)
        assert stored_ids(spool) == [data[2]['ingest_id']]
    finally:
        spool.close()


def test_retry_backoff_commits_even_when_success_deferral_requested(tmp_path):
    spool = RetrySpool(tmp_path / 'spool.sqlite3')
    data = rows(4)
    try:
        spool.stage(data)
        spool.acknowledge(data[:2], [], defer_success=True)
        spool.acknowledge(data[2:], data[2:3], now=100, defer_success=True)
        assert stored_ids(spool) == [data[2]['ingest_id']]
        assert spool.snapshot()['rows'] == 1
        assert spool.snapshot()['ack_pending_rows'] == 0
        assert spool.due(10, now=100) == []
        assert spool.due_batch(10, now=101) == (data[2:3], True)
    finally:
        spool.close()


def test_repeated_and_unknown_acknowledgements_do_not_change_counts_twice(tmp_path):
    spool = RetrySpool(tmp_path / 'spool.sqlite3')
    data = rows(2)
    try:
        spool.stage(data)
        spool.acknowledge(data, [], defer_success=True)
        spool.acknowledge(data + rows(1, 'unknown'), [], defer_success=True)
        assert spool.snapshot()['rows'] == spool.snapshot()['bytes'] == 0
        assert spool.snapshot()['ack_pending_rows'] == 2
        spool.acknowledge(data, [])
        assert stored_ids(spool) == []
        assert spool.snapshot()['rows'] == spool.snapshot()['bytes'] == 0
    finally:
        spool.close()


def test_capacity_reclaimed_in_same_transaction_as_new_rows(tmp_path):
    spool = RetrySpool(tmp_path / 'spool.sqlite3', max_rows=2)
    first, second = rows(2), rows(2, 'later')
    try:
        spool.stage(first)
        spool.acknowledge(first, [], defer_success=True)
        assert spool.stage(second) == (second, 0)
        assert spool.due(10) == second
        assert spool.snapshot()['stored_rows'] == 2
        spool.acknowledge(second, [], defer_success=True)
        assert spool.stage(first) == (first, 0)  # Reused IDs are admitted after their removal.
        assert spool.due(10) == first
    finally:
        spool.close()


def test_ack_buffer_is_bounded_and_oversized_call_commits_immediately(tmp_path):
    spool = RetrySpool(tmp_path / 'spool.sqlite3')
    spool._deferred_ack_max_rows = 3
    data = rows(8)
    try:
        spool.stage(data)
        spool.acknowledge(data[:2], [], defer_success=True)
        spool.acknowledge(data[2:4], [], defer_success=True)
        assert spool.snapshot()['ack_pending_rows'] == 2
        assert spool.snapshot()['stored_rows'] == 6
        assert spool.due(10) == data[4:]
        spool.acknowledge(data[4:], [], defer_success=True)
        assert spool.snapshot()['rows'] == spool.snapshot()['stored_rows'] == 0
        assert spool.snapshot()['ack_pending_rows'] == 0
    finally:
        spool.close()


def test_ack_capacity_flushes_without_needing_more_arrivals(tmp_path):
    spool = RetrySpool(tmp_path / 'spool.sqlite3')
    spool._deferred_ack_max_rows = 3
    data = rows(3)
    try:
        spool.stage(data)
        spool.acknowledge(data, [], defer_success=True)
        assert stored_ids(spool) == []
        assert spool.snapshot()['ack_pending_rows'] == 0
    finally:
        spool.close()


@pytest.mark.parametrize('has_ack', [False, True])
def test_idle_ack_poll_does_not_wait_for_unrelated_storage_lock(tmp_path, has_ack):
    spool = RetrySpool(tmp_path / 'spool.sqlite3')
    if has_ack:
        data = rows(2)
        spool.stage(data)
        spool.acknowledge(data, [], defer_success=True)
    finished = threading.Event()
    result = []

    def poll():
        result.append(spool.flush_acknowledgements())
        finished.set()

    thread = threading.Thread(target=poll)
    try:
        with spool._lock:
            thread.start()
            assert finished.wait(.5)
        thread.join(1)
        assert result == [False]
    finally:
        thread.join(1)
        spool.close()


def test_close_flushes_successes_and_does_not_resurrect_on_clean_restart(tmp_path):
    path = tmp_path / 'spool.sqlite3'
    spool = RetrySpool(path)
    data = rows(5)
    spool.stage(data)
    spool.acknowledge(data[:3], [], defer_success=True)
    spool.close()
    reopened = RetrySpool(path)
    try:
        assert reopened.due(10) == data[3:]
    finally:
        reopened.close()


def test_pinned_wal_does_not_forget_completed_ids_when_ack_flush_fails(tmp_path):
    path = tmp_path / 'spool.sqlite3'
    spool = RetrySpool(path)
    spool._wal_checkpoint_bytes = 16 * 1024
    spool._wal_max_bytes = 64 * 1024
    initial = rows(1)
    spool.stage(initial)
    reader = sqlite3.connect(f'file:{path}?mode=ro', uri=True)
    reader.execute('BEGIN')
    reader.execute('SELECT * FROM pending').fetchall()
    admitted = list(initial)
    try:
        for index in range(100):
            data = rows(10, f'batch-{index}')
            try:
                spool.stage(data)
            except sqlite3.OperationalError as exc:
                assert 'pinned' in str(exc)
                break
            admitted.extend(data)
        else:
            pytest.fail('Expected bounded WAL growth')
        spool.acknowledge(admitted, [], defer_success=True)
        assert spool.rows == 0
        assert spool.snapshot()['ack_pending_rows'] == len(admitted)
        with pytest.raises(sqlite3.OperationalError, match='pinned'):
            spool.flush_acknowledgements(force=True)
        assert spool.rows == 0 and spool.due(100) == []
        assert len(stored_ids(spool)) == len(admitted)
        reader.rollback()
        assert spool.flush_acknowledgements(force=True)
        assert spool.snapshot()['stored_rows'] == 0
        assert spool.stage(rows(2, 'recovered'))[1] == 0
        assert spool.conn.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
    finally:
        reader.close()
        spool.close()


def test_failed_read_during_deferral_does_not_partially_update_logical_counts(tmp_path):
    spool = RetrySpool(tmp_path / 'spool.sqlite3')
    data = rows(3)
    spool.stage(data)
    original = spool._oldest_pending
    try:
        def fail_read(*args):
            raise sqlite3.OperationalError('test read failure')
        spool._oldest_pending = fail_read
        with pytest.raises(sqlite3.OperationalError, match='test read failure'):
            spool.acknowledge(data[:2], [], defer_success=True)
        assert spool.snapshot()['rows'] == 3
        assert spool.snapshot()['ack_pending_rows'] == 0
        assert spool.due(10) == data
        spool._oldest_pending = original
        spool.acknowledge(data[:2], [], defer_success=True)
        assert spool.due(10) == data[2:]
    finally:
        spool._oldest_pending = original
        spool.close()


def test_deferred_prefix_does_not_limit_later_batches_or_corrupt_head_cache(tmp_path):
    spool = RetrySpool(tmp_path / 'spool.sqlite3')
    data = rows(1600)
    try:
        spool.stage(data)
        assert spool.due(200) == data[:200]
        spool.acknowledge(data[:500], [], defer_success=True)
        assert spool.due(1000) == data[500:1500]
        assert spool.due(1000) == data[500:1500]
        spool.acknowledge(data[500:700], [], defer_success=True)
        assert spool.due(1000) == data[700:]
    finally:
        spool.close()


def test_concurrent_admission_and_coalesced_delivery_retains_every_id(tmp_path):
    spool = RetrySpool(tmp_path / 'spool.sqlite3')
    finished = threading.Event()
    failures = []
    delivered = []
    data = rows(12000)

    def producer():
        try:
            for offset in range(0, len(data), 60):
                accepted, rejected = spool.stage(data[offset:offset + 60])
                assert len(accepted) == 60 and rejected == 0
        except BaseException as exc:
            failures.append(exc)
        finally:
            finished.set()

    def consumer():
        try:
            while not finished.is_set() or spool.rows:
                batch = spool.due(200)
                if batch:
                    delivered.extend(row['ingest_id'] for row in batch)
                    spool.acknowledge(batch, [], defer_success=True)
                else:
                    spool.flush_acknowledgements()
                    time.sleep(.001)
            spool.flush_acknowledgements(force=True)
        except BaseException as exc:
            failures.append(exc)

    threads = [threading.Thread(target=producer), threading.Thread(target=consumer)]
    try:
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(15)
        assert not any(thread.is_alive() for thread in threads)
        assert not failures
        assert delivered == [row['ingest_id'] for row in data]
        assert spool.snapshot()['rows'] == spool.snapshot()['stored_rows'] == 0
        assert spool.conn.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
    finally:
        for thread in threads:
            thread.join(15)
        spool.close()
