"""Bounded durable delivery, accurate acknowledgements and independent intake."""
import datetime
import importlib
import json
import queue
import sqlite3
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
    receiver._retry_spool()
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
    receiver._retry_spool()
    assert receiver.stats['inserted'] == 0
    assert receiver.stats['dropped'] == 0
    assert receiver.stats['flush_errors'] == 1
    assert receiver._spool.snapshot()['rows'] == 1


def test_delivery_counter_separates_first_attempts_from_known_retries(receiver):
    successful = lambda rows: SimpleNamespace(inserted=len(rows), duplicates=0, dropped=0, retryable=[])
    receiver.db.insert_logs_batch.side_effect = successful
    receiver.batch = [{'raw_log': 'synthetic first send'}]
    receiver._flush_batch()
    receiver._retry_spool()
    assert receiver.stats['delivery_attempts'] == 1
    assert receiver.stats['retry_attempts'] == 0

    receiver.db.insert_logs_batch.side_effect = RuntimeError('synthetic outage')
    receiver.batch = [{'raw_log': 'synthetic pending send'}]
    receiver._flush_batch()
    receiver._retry_spool()
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


def test_blocked_db_worker_does_not_block_durable_staging(receiver, monkeypatch):
    import main
    receiver.batch_size = 1
    monkeypatch.setattr(main, 'parse_log', lambda _raw: {'raw_log': 'event'})
    receiver.queue = queue.Queue(maxsize=3)
    entered, release = threading.Event(), threading.Event()
    def blocked_insert(rows):
        entered.set()
        release.wait(3)
        return SimpleNamespace(inserted=len(rows), duplicates=0, dropped=0, retryable=[])
    receiver.db.insert_logs_batch.side_effect = blocked_insert
    receiver.running = True
    receiver._start_workers()
    receiver._accept_datagram(b'first', ('gateway', 514))
    assert entered.wait(1)
    try:
        # PostgreSQL has not returned, but the producer drains and durably
        # stages each later event. The old combined worker could not do this.
        for index in range(20):
            receiver._accept_datagram(b'burst', ('gateway', 514))
            wait_until(lambda: receiver.stats['staged'] == index + 2)
        assert receiver.queue.qsize() == 0
        assert receiver.stats['received'] == 21
        assert receiver.stats['queue_dropped'] == 0
        assert receiver.stats['inserted'] == 0
        assert receiver._spool.snapshot()['rows'] == 21
        receiver._write_status()
        snapshot = json.loads(open(receiver._status_path).read())
        assert snapshot['queue']['depth'] == 0
        assert snapshot['queue']['capacity'] == 3
        assert snapshot['queue']['oldest_age_seconds'] >= 0
        assert 'raw_log' not in json.dumps(snapshot)
        assert snapshot['worker_alive'] is True
        assert snapshot['workers']['delivery']['alive'] is True
        assert snapshot['workers']['delivery']['busy_since'] is not None
    finally:
        release.set()
        receiver.stop()


def wait_until(condition, timeout=2):
    deadline = time.monotonic() + timeout
    while not condition():
        assert time.monotonic() < deadline, 'worker did not make expected progress'
        time.sleep(0.005)


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


def test_intake_overflow_is_bounded_and_counted(receiver):
    receiver.queue = queue.Queue(maxsize=3)
    for _ in range(100):
        receiver._accept_datagram(b'event', ('192.0.2.1', 514))
    assert receiver.queue.qsize() == 3
    assert receiver.stats['queue_dropped'] == receiver.stats['dropped'] == 97


def test_new_rows_cannot_leapfrog_delayed_head(tmp_path):
    spool = RetrySpool(str(tmp_path / 'spool.sqlite3'))
    older, _ = spool.stage([{'raw_log': 'older'}])
    spool.acknowledge(older, older, now=100)
    spool.stage([{'raw_log': 'newer'}])
    assert spool.due(50, now=100) == []
    assert [row['raw_log'] for row in spool.due(50, now=101)] == ['older', 'newer']
    spool.close()


def test_spool_concurrent_producer_consumer_preserves_order(tmp_path):
    spool = RetrySpool(str(tmp_path / 'spool.sqlite3'), max_rows=500)
    errors, delivered = [], []
    producer_done = threading.Event()

    def produce():
        try:
            for start in range(0, 250, 5):
                admitted, rejected = spool.stage([{'raw_log': str(i)} for i in range(start, start + 5)])
                assert len(admitted) == 5 and rejected == 0
        except Exception as exc:
            errors.append(exc)
        finally:
            producer_done.set()

    def consume():
        try:
            while not producer_done.is_set() or spool.snapshot()['rows']:
                rows = spool.due(7)
                if rows:
                    delivered.extend(int(row['raw_log']) for row in rows)
                    spool.acknowledge(rows, [])
                else:
                    time.sleep(0.001)
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=target, daemon=True) for target in (produce, consume)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(5)
        assert not thread.is_alive()
    assert errors == []
    assert delivered == list(range(250))
    assert spool.snapshot()['rows'] == spool.snapshot()['bytes'] == 0
    spool.close()


def test_sqlite_disk_full_rolls_back_the_whole_staging_transaction(tmp_path):
    path = str(tmp_path / 'spool.sqlite3')
    spool = RetrySpool(path)
    pages = spool.conn.execute('PRAGMA page_count').fetchone()[0]
    spool.conn.execute(f'PRAGMA max_page_count={pages}')
    with pytest.raises(sqlite3.OperationalError, match='full'):
        spool.stage([{'raw_log': 'small'}, {'raw_log': 'x' * 65536}])
    assert spool.snapshot()['rows'] == 0
    assert spool.due(50) == []
    spool.close()
    reopened = RetrySpool(path)
    assert reopened.snapshot()['rows'] == 0
    reopened.close()


def test_staging_failure_counts_loss_and_recovers_on_next_batch(receiver, monkeypatch):
    receiver._ensure_spool()
    original = receiver._spool.stage
    monkeypatch.setattr(receiver._spool, 'stage', MagicMock(side_effect=sqlite3.OperationalError('disk full')))
    receiver.batch = [{'raw_log': str(i)} for i in range(3)]
    receiver._flush_batch()
    assert receiver.stats['spool_errors'] == 1
    assert receiver.stats['staged'] == 0
    assert receiver.stats['spool_dropped'] == receiver.stats['dropped'] == 3
    assert receiver.health_snapshot()['spool']['failed'] is True
    monkeypatch.setattr(receiver._spool, 'stage', original)
    receiver.batch = [{'raw_log': 'recovered'}]
    receiver._flush_batch()
    assert receiver.stats['staged'] == 1
    assert receiver.health_snapshot()['spool']['failed'] is False


def test_uncertain_pg_commit_replays_same_ids_without_duplicate_insert_count(receiver):
    committed_ids = set()
    calls = []

    def uncertain_insert(rows):
        ids = {row['ingest_id'] for row in rows}
        calls.append(ids)
        new = ids - committed_ids
        committed_ids.update(ids)
        if len(calls) == 1:
            raise ConnectionError('connection lost after simulated commit')
        return SimpleNamespace(inserted=len(new), duplicates=len(ids) - len(new), dropped=0, retryable=[])

    receiver.db.insert_logs_batch.side_effect = uncertain_insert
    receiver.batch = [{'raw_log': 'uncertain'}]
    receiver._flush_batch()
    receiver._retry_spool()
    assert receiver._spool.snapshot()['rows'] == 1
    assert receiver.stats['inserted'] == 0  # Commit was not acknowledged to this process.
    receiver._db_retry_at = 0
    receiver._spool.conn.execute('UPDATE pending SET next_retry_at=0')
    receiver._spool.conn.commit()
    receiver._retry_spool()
    assert calls[0] == calls[1]
    assert len(committed_ids) == receiver.stats['duplicates'] == 1
    assert receiver._spool.snapshot()['rows'] == 0
    assert receiver.stats['dropped'] == 0


def test_failed_spool_ack_replays_and_does_not_count_rejected_row_twice(receiver, monkeypatch):
    receiver.batch = [{'raw_log': 'invalid row'}]
    receiver._flush_batch()
    original = receiver._spool.acknowledge
    monkeypatch.setattr(receiver._spool, 'acknowledge', MagicMock(side_effect=sqlite3.OperationalError('read only')))
    receiver.db.insert_logs_batch.side_effect = lambda rows: SimpleNamespace(
        inserted=0, duplicates=0, dropped=len(rows), retryable=[])
    receiver._retry_spool()
    assert receiver._spool.snapshot()['rows'] == 1
    assert receiver.stats['dropped'] == 0
    monkeypatch.setattr(receiver._spool, 'acknowledge', original)
    receiver._db_retry_at = 0
    receiver._retry_spool()
    assert receiver.stats['dropped'] == 1
    assert receiver._spool.snapshot()['rows'] == 0


def test_ack_failure_and_concurrent_staging_preserve_every_event(receiver, monkeypatch):
    receiver.batch_size = 1
    receiver.batch = [{'raw_log': 'first'}]
    receiver._flush_batch()
    original = receiver._spool.acknowledge
    committed = set()
    entered, release = threading.Event(), threading.Event()

    def insert(rows):
        entered.set()
        release.wait(2)
        count = sum(row['ingest_id'] not in committed for row in rows)
        committed.update(row['ingest_id'] for row in rows)
        return SimpleNamespace(inserted=count, duplicates=len(rows) - count, dropped=0, retryable=[])

    receiver.db.insert_logs_batch.side_effect = insert
    monkeypatch.setattr(receiver._spool, 'acknowledge', MagicMock(side_effect=sqlite3.OperationalError('write failed')))
    delivery = threading.Thread(target=receiver._retry_spool)
    delivery.start()
    assert entered.wait(1)
    receiver.batch = [{'raw_log': 'second'}]
    receiver._flush_batch()
    release.set()
    delivery.join(2)
    assert not delivery.is_alive()
    assert receiver.stats['staged'] == receiver._spool.snapshot()['rows'] == 2
    assert receiver.stats['inserted'] == 1
    assert receiver.stats['dropped'] == 0
    monkeypatch.setattr(receiver._spool, 'acknowledge', original)
    receiver._db_retry_at = 0
    receiver._retry_spool()
    receiver._retry_spool()
    assert len(committed) == receiver.stats['inserted'] == 2
    assert receiver.stats['duplicates'] == 1
    assert receiver._spool.snapshot()['rows'] == 0


def test_malformed_database_ack_never_removes_rows(receiver):
    receiver.batch = [{'raw_log': 'pending'}]
    receiver._flush_batch()
    receiver.db.insert_logs_batch.return_value = SimpleNamespace(inserted=0, duplicates=0, dropped=0, retryable=[])
    receiver._retry_spool()
    assert receiver.stats['inserted'] == 0
    assert receiver.stats['flush_errors'] == 1
    assert receiver._spool.snapshot()['rows'] == 1


def test_shutdown_drains_to_disk_even_when_pg_is_blocked(receiver, monkeypatch):
    import main
    receiver.batch_size = 1
    monkeypatch.setattr(main, 'parse_log', lambda raw: {'raw_log': raw})
    entered, release = threading.Event(), threading.Event()

    def blocked_insert(rows):
        entered.set()
        release.wait(3)
        return SimpleNamespace(inserted=len(rows), duplicates=0, dropped=0, retryable=[])

    receiver.db.insert_logs_batch.side_effect = blocked_insert
    receiver.running = True
    receiver._start_workers()
    receiver._accept_datagram(b'first', ('192.0.2.1', 514))
    assert entered.wait(1)
    receiver.batch_size = 200
    receiver.batch_timeout = 5
    for i in range(10):
        receiver._accept_datagram(f'pending-{i}'.encode(), ('192.0.2.1', 514))
    receiver._shutdown_deadline = time.monotonic() + 0.25
    try:
        receiver.stop()
        assert not receiver._worker.is_alive()
        assert receiver._delivery_worker.is_alive()
        assert receiver.stats['staged'] == 11
        assert receiver.stats['dropped'] == 0
        assert receiver._spool.snapshot()['rows'] == 11
        # Independent connection/restart sees the committed copy while PG waits.
        reopened = RetrySpool(receiver._spool_path)
        assert len(reopened.due(50)) == 11
        reopened.close()
    finally:
        release.set()
        receiver._delivery_worker.join(2)
    assert receiver.db.insert_logs_batch.call_count == 1  # No new delivery during shutdown.


def test_worker_failure_is_visible_while_health_publisher_is_alive(receiver, monkeypatch):
    monkeypatch.setattr(receiver, '_retry_spool', MagicMock(side_effect=RuntimeError('unexpected')))
    receiver.running = True
    receiver._delivery_worker = threading.Thread(target=receiver._deliver_spool, daemon=True)
    receiver._delivery_worker.start()
    receiver._delivery_worker.join(1)
    snapshot = receiver.health_snapshot()
    assert snapshot['workers']['delivery']['failed'] is True
    assert snapshot['workers']['delivery']['alive'] is False
    assert 'worker_error' in snapshot['collection']['reasons']


def test_batch_age_resets_after_staging_and_matches_public_classification(receiver, monkeypatch):
    import main
    monkeypatch.delitem(sys.modules, 'routes.health', raising=False)
    health = importlib.import_module('routes.health')
    started = time.monotonic()
    clock = [started]
    monkeypatch.setattr(main.time, 'monotonic', lambda: clock[0])
    monkeypatch.setattr(main, 'parse_log', lambda raw: {'raw_log': raw})
    # Model live workers while exercising the actual producer and snapshot path.
    monkeypatch.setattr(receiver, '_worker', MagicMock())
    monkeypatch.setattr(receiver, '_delivery_worker', MagicMock())
    receiver.running = True
    receiver._handle_message(b'synthetic first packet', ('192.0.2.1', 514))
    clock[0] += 0.5
    snapshot = receiver.health_snapshot()
    assert snapshot['batch']['oldest_age_seconds'] == 0.5
    assert snapshot['collection']['state'] == 'processing'
    assert snapshot['collection']['attention_required'] is False
    receiver._write_status()
    assert health.read_ingest_health()['collection'] == snapshot['collection']

    clock[0] += 12
    assert receiver.health_snapshot()['collection']['attention_reasons'] == ['backlog_lag']
    receiver._flush_batch()
    assert receiver.health_snapshot()['batch']['oldest_age_seconds'] is None
    receiver._handle_message(b'synthetic second packet', ('192.0.2.1', 514))
    clock[0] += 0.2
    assert receiver.health_snapshot()['batch']['oldest_age_seconds'] == pytest.approx(0.2)


def test_shutdown_reports_volatile_work_if_producer_cannot_finish(receiver, monkeypatch):
    import main
    entered, release = threading.Event(), threading.Event()

    def blocked_parse(raw):
        entered.set()
        release.wait(3)
        return {'raw_log': raw}

    monkeypatch.setattr(main, 'parse_log', blocked_parse)
    receiver.running = True
    receiver._start_workers()
    receiver._accept_datagram(b'being-parsed', ('192.0.2.1', 514))
    assert entered.wait(1)
    receiver._accept_datagram(b'still-in-memory', ('192.0.2.1', 514))
    receiver._shutdown_deadline = time.monotonic() + 0.05
    try:
        receiver.stop()
        assert receiver.stats['shutdown_dropped'] == 1
        assert receiver.stats['dropped'] == 1
        snapshot = receiver.health_snapshot()
        assert snapshot['workers']['producer']['alive'] is True
        assert snapshot['batch']['inflight'] == 1
        assert snapshot['batch']['pending'] == 0
        assert 'processing' in snapshot['collection']['reasons']
    finally:
        release.set()
        receiver._worker.join(2)
    assert receiver.stats['staged'] == 1
    assert receiver._spool.snapshot()['rows'] == 1
