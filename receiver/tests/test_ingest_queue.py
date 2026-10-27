"""Bounded durable delivery, accurate acknowledgements and independent intake."""
import datetime
import importlib
import json
import queue
import sys
import threading
import time
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from ingest_queue import RetrySpool


def test_spool_survives_restart_and_preserves_ingest_id(tmp_path):
    path = str(tmp_path / 'spool.sqlite3')
    spool = RetrySpool(path)
    row = {'timestamp': datetime.datetime(2026, 10, 28, tzinfo=datetime.timezone.utc), 'raw_log': 'example'}
    accepted, rejected = spool.stage([row])
    assert len(accepted) == 1 and rejected == 0
    first = spool.due(50)[0]
    spool.close()
    spool = RetrySpool(path)
    replay = spool.due(50)[0]
    assert replay == first
    assert replay['ingest_id'] == row['ingest_id']
    assert replay['timestamp'] == '2026-10-28T00:00:00+00:00'
    spool.acknowledge([replay], [])
    assert spool.snapshot()['rows'] == 0
    spool.close()


def test_spool_capacity_drops_newest_and_retains_failed_rows(tmp_path):
    spool = RetrySpool(str(tmp_path / 'spool.sqlite3'), max_rows=2, max_bytes=4096)
    accepted, rejected = spool.stage([{'raw_log': str(i)} for i in range(3)])
    assert len(accepted) == 2 and rejected == 1
    spool.acknowledge(accepted, accepted, now=100)
    assert spool.due(50, now=100) == []
    retry = spool.due(50, now=101)
    assert [r['ingest_id'] for r in retry] == [r['ingest_id'] for r in accepted]
    # Many failures cap the backoff and keep data; elapsed outages never expire it.
    for i in range(80):
        spool.acknowledge(retry, retry, now=1000)
    assert spool.due(50, now=1059) == []
    assert len(spool.due(50, now=1060)) == 2
    spool.close()


def test_due_batch_reports_persisted_retry_evidence_without_altering_payload(tmp_path):
    path = str(tmp_path / 'spool.sqlite3')
    spool = RetrySpool(path)
    spool.stage([{'raw_log': 'synthetic retry'}])
    rows, retrying = spool.due_batch(50, now=100)
    assert len(rows) == 1 and retrying is False
    assert 'attempts' not in rows[0]
    spool.acknowledge(rows, rows, now=100)
    assert spool.due_batch(50, now=100) == ([], False)
    spool.close()
    spool = RetrySpool(path)
    replay, retrying = spool.due_batch(50, now=101)
    assert replay == rows and retrying is True
    spool.close()


def test_spool_payload_bytes_bound_and_duplicate_stage(tmp_path):
    spool = RetrySpool(str(tmp_path / 'spool.sqlite3'), max_rows=10, max_bytes=250)
    row = {'raw_log': 'a' * 100}
    assert spool.stage([row])[1] == 0
    assert spool.stage([row])[1] == 0
    assert spool.snapshot()['rows'] == 1
    assert spool.stage([{'raw_log': 'b' * 200}])[1] == 1
    assert spool.snapshot()['bytes'] <= 250
    spool.close()


@pytest.fixture
def receiver(monkeypatch, tmp_path):
    # main imports auth/deps, whose production boot intentionally waits for PG.
    for name in ('backfill', 'blacklist', 'unifi_api', 'pihole_api', 'routes.auth', 'deps'):
        monkeypatch.setitem(sys.modules, name, MagicMock())
    monkeypatch.delitem(sys.modules, 'main', raising=False)
    module = importlib.import_module('main')
    monkeypatch.setenv('INGEST_SPOOL_PATH', str(tmp_path / 'spool.sqlite3'))
    monkeypatch.setenv('INGEST_STATUS_PATH', str(tmp_path / 'health.json'))
    monkeypatch.setattr(module, 'get_config', lambda _db, _key, default=None: default)
    db = MagicMock()
    enricher = MagicMock()
    enricher.enrich.side_effect = lambda parsed, **kwargs: parsed
    r = module.SyslogReceiver(db, enricher)
    yield r
    if r._worker and r._worker.is_alive():
        r.stop()
    if r._spool is not None:
        r._spool.close()
        r._spool = None


def test_partial_insert_counts_only_confirmed_rows_and_retains_retry(receiver):
    receiver.batch = [{'raw_log': str(i)} for i in range(4)]
    def result(rows):
        return SimpleNamespace(inserted=1, duplicates=1, dropped=1, retryable=[rows[3]])
    receiver.db.insert_logs_batch.side_effect = result
    receiver._flush_batch()
    assert receiver.stats['inserted'] == 1
    assert receiver.stats['duplicates'] == 1
    assert receiver.stats['dropped'] == 1
    assert receiver.stats['flush_errors'] == 1
    assert receiver._spool.snapshot()['rows'] == 1
    receiver._db_retry_at = 0
    receiver._spool.conn.execute('UPDATE pending SET next_retry_at=0')
    receiver._spool.conn.commit()
    receiver.db.insert_logs_batch.side_effect = lambda rows: SimpleNamespace(
        inserted=len(rows), duplicates=0, dropped=0, retryable=[])
    receiver._retry_spool()
    assert receiver.stats['inserted'] == 2
    assert receiver._spool.snapshot()['rows'] == 0


def test_failed_db_write_never_increments_inserted_or_drops_durable_rows(receiver):
    receiver.batch = [{'raw_log': 'pending'}]
    receiver.db.insert_logs_batch.side_effect = RuntimeError('database unavailable')
    receiver._flush_batch()
    assert receiver.stats['inserted'] == 0
    assert receiver.stats['dropped'] == 0
    assert receiver.stats['flush_errors'] == 1
    assert receiver._spool.snapshot()['rows'] == 1


def test_delivery_counter_separates_first_attempts_from_known_retries(receiver):
    successful = lambda rows: SimpleNamespace(inserted=len(rows), duplicates=0, dropped=0, retryable=[])
    receiver.db.insert_logs_batch.side_effect = successful
    receiver.batch = [{'raw_log': 'synthetic first send'}]
    receiver._flush_batch()
    assert receiver.stats['delivery_attempts'] == 1
    assert receiver.stats['retry_attempts'] == 0

    receiver.db.insert_logs_batch.side_effect = RuntimeError('synthetic outage')
    receiver.batch = [{'raw_log': 'synthetic pending send'}]
    receiver._flush_batch()
    assert receiver.stats['delivery_attempts'] == 2
    assert receiver.stats['retry_attempts'] == 0  # Failed first send is not a retry.
    assert receiver.stats['flush_errors'] == 1
    receiver._retry_spool()
    assert receiver.stats['delivery_attempts'] == 2  # Backoff is not an attempt.

    receiver._db_retry_at = 0
    receiver._spool.conn.execute('UPDATE pending SET next_retry_at=0')
    receiver._spool.conn.commit()
    receiver.db.insert_logs_batch.side_effect = successful
    receiver._retry_spool()
    assert receiver.stats['delivery_attempts'] == 3
    assert receiver.stats['retry_attempts'] == 1
    assert receiver.stats['inserted'] == 2
    assert receiver._spool.rows == 0


def test_blocked_db_worker_does_not_block_intake_and_memory_is_bounded(receiver, monkeypatch):
    import main
    monkeypatch.setattr(main, 'BATCH_SIZE', 1)
    monkeypatch.setattr(main, 'parse_log', lambda _raw: {'raw_log': 'event'})
    receiver.queue = queue.Queue(maxsize=3)
    entered, release = threading.Event(), threading.Event()
    def blocked_insert(rows):
        entered.set()
        release.wait(3)
        return SimpleNamespace(inserted=len(rows), duplicates=0, dropped=0, retryable=[])
    receiver.db.insert_logs_batch.side_effect = blocked_insert
    receiver.running = True
    receiver._worker = threading.Thread(target=receiver._process_queue, daemon=True)
    receiver._worker.start()
    receiver._accept_datagram(b'first', ('gateway', 514))
    assert entered.wait(1)
    try:
        started = time.monotonic()
        for _ in range(100):
            receiver._accept_datagram(b'burst', ('gateway', 514))
        assert time.monotonic() - started < 0.2
        assert receiver.queue.qsize() == 3
        assert receiver.stats['received'] == 101
        assert receiver.stats['queue_dropped'] == 97
        receiver._write_status()
        snapshot = json.loads(open(receiver._status_path).read())
        assert snapshot['queue']['depth'] == 3
        assert snapshot['queue']['capacity'] == 3
        assert snapshot['queue']['oldest_age_seconds'] >= 0
        assert 'raw_log' not in json.dumps(snapshot)
        assert snapshot['worker_alive'] is True
    finally:
        release.set()
        receiver.stop()


def test_shutdown_stages_unflushed_batch_without_database_call(receiver):
    receiver.batch = [{'raw_log': 'pending'}]
    receiver.stop()
    receiver.db.insert_logs_batch.assert_not_called()
    assert receiver._spool.snapshot()['rows'] == 1
    status = json.loads(open(receiver._status_path).read())
    assert status['running'] is False


def test_shutdown_request_is_safe_even_while_queue_mutex_is_held(receiver):
    receiver.running = True
    with receiver.queue.mutex:
        receiver.request_stop()
    assert receiver.running is False
    assert receiver._shutdown_requested is True
    receiver.db.insert_logs_batch.assert_not_called()
