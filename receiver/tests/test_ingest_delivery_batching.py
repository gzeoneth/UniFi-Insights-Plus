"""PostgreSQL coalescing holds committed rows, never uncommitted intake."""
import json
import sqlite3
import sys
from types import SimpleNamespace

import pytest

from tests.test_ingest_queue import receiver, wait_until


class Clock:
    def __init__(self):
        self.wall = 1000.0
        self.monotonic = 100.0

    def advance(self, seconds):
        self.wall += seconds
        self.monotonic += seconds


@pytest.fixture
def clock(receiver, monkeypatch):
    import ingest_queue

    clock = Clock()
    fake_time = SimpleNamespace(time=lambda: clock.wall,
                                monotonic=lambda: clock.monotonic)
    # Replace module references, not the process-wide time functions used by
    # pytest and real worker synchronization in the integration tests below.
    monkeypatch.setattr(sys.modules['main'], 'time', fake_time)
    monkeypatch.setattr(ingest_queue, 'time', fake_time)
    return clock


def successful(rows):
    return SimpleNamespace(inserted=len(rows), duplicates=0, dropped=0, retryable=[])


def stage(receiver, start, count):
    rows = [{'raw_log': f'synthetic event {index}'} for index in range(start, start + count)]
    receiver.batch = rows
    receiver._flush_batch()
    assert not receiver.batch
    return rows


def committed_payloads(receiver):
    # A separate connection must see every held row before PG is called.
    with sqlite3.connect(receiver._spool_path) as connection:
        return [json.loads(row[0]) for row in connection.execute(
            'SELECT payload FROM pending ORDER BY rowid')]


def test_delivery_defaults_do_not_extend_durable_admission(receiver):
    assert (receiver.batch_size, receiver.batch_timeout) == (200, 1.0)
    assert (receiver.delivery_batch_size, receiver.delivery_batch_timeout) == (1000, 2.0)
    snapshot = receiver.health_snapshot()
    assert snapshot['delivery'] == {'batch_size': 1000, 'effective_batch_size': 1000,
                                    'flush_interval_seconds': 2.0}


@pytest.mark.parametrize('size, interval, expected', [
    ('50', '0.5', (50, 0.5)),
    ('5000', '100', (1000, 5.0)),
    ('0', 'nan', (1000, 2.0)),
    ('invalid', '-1', (1000, 2.0)),
    ('1', '0.001', (1, 0.05)),
])
def test_delivery_config_is_independent_and_bounded(receiver, monkeypatch, size, interval, expected):
    monkeypatch.setenv('INGEST_BATCH_SIZE', '20')
    monkeypatch.setenv('INGEST_FLUSH_INTERVAL_SECONDS', '0.25')
    monkeypatch.setenv('INGEST_DELIVERY_BATCH_SIZE', size)
    monkeypatch.setenv('INGEST_DELIVERY_FLUSH_INTERVAL_SECONDS', interval)
    configured = type(receiver)(receiver.db, receiver.enricher)
    assert (configured.batch_size, configured.batch_timeout) == (20, 0.25)
    assert (configured.delivery_batch_size, configured.delivery_batch_timeout) == expected
    assert configured.effective_delivery_batch_size == expected[0]


def test_sparse_rows_are_committed_during_hold_and_arrivals_do_not_postpone_it(receiver, clock):
    receiver.db.insert_logs_batch.side_effect = successful
    first = stage(receiver, 0, 1)
    receiver._retry_spool(coalesce=True)
    deadline = receiver._delivery_batch_deadline
    assert deadline == clock.monotonic + 2.0
    assert committed_payloads(receiver) == first
    assert receiver._spool.snapshot()['storage']['synchronous'] == 'FULL'
    receiver.db.insert_logs_batch.assert_not_called()

    clock.advance(1.5)
    later = stage(receiver, 1, 1)
    receiver._retry_spool(coalesce=True)
    assert receiver._delivery_batch_deadline == deadline
    assert committed_payloads(receiver) == first + later
    receiver.db.insert_logs_batch.assert_not_called()

    clock.advance(0.5)
    assert receiver._retry_spool(coalesce=True) is True
    assert receiver.db.insert_logs_batch.call_args.args[0] == first + later
    assert receiver._spool.rows == 0


def test_monotonic_deadline_bounds_hold_when_wall_clock_moves_backwards(receiver, clock):
    receiver.db.insert_logs_batch.side_effect = successful
    stage(receiver, 0, 1)
    receiver._retry_spool(coalesce=True)
    clock.wall -= 60
    clock.monotonic += 2.0
    assert receiver._spool.snapshot()['oldest_age_seconds'] == 0
    assert receiver._retry_spool(coalesce=True) is True
    assert receiver.stats['inserted'] == 1


def test_full_delivery_batch_combines_five_durable_admission_batches(receiver, clock):
    receiver.db.insert_logs_batch.side_effect = successful
    staged = []
    for index in range(5):
        staged += stage(receiver, index * 200, 200)
        receiver._retry_spool(coalesce=True)
        assert receiver.db.insert_logs_batch.call_count == (1 if index == 4 else 0)
        clock.advance(0.1)
    assert receiver.db.insert_logs_batch.call_args.args[0] == staged
    assert receiver.stats['staged'] == receiver.stats['inserted'] == 1000
    assert receiver._spool.rows == 0


def test_aged_backlog_drains_immediately_in_bounded_fifo_batches(receiver, clock):
    receiver.db.insert_logs_batch.side_effect = successful
    staged = stage(receiver, 0, 2500)
    clock.advance(30)
    for _ in range(3):
        assert receiver._retry_spool(coalesce=True) is True
    calls = [call.args[0] for call in receiver.db.insert_logs_batch.call_args_list]
    assert list(map(len, calls)) == [1000, 1000, 500]
    assert [row for rows in calls for row in rows] == staged
    assert receiver._spool.rows == 0


def test_retry_head_and_backoff_are_preserved_with_new_arrivals(receiver, clock):
    receiver.delivery_batch_size = receiver.effective_delivery_batch_size = 3
    first = stage(receiver, 0, 3)
    receiver.db.insert_logs_batch.side_effect = RuntimeError('synthetic database outage')
    assert receiver._retry_spool(coalesce=True) is True
    assert receiver.stats['inserted'] == 0
    assert committed_payloads(receiver) == first
    later = stage(receiver, 3, 2)
    receiver._retry_spool(coalesce=True)
    assert receiver.db.insert_logs_batch.call_count == 1

    clock.advance(1.0)
    receiver.db.insert_logs_batch.side_effect = successful
    assert receiver._retry_spool(coalesce=True) is True
    assert receiver.db.insert_logs_batch.call_args.args[0] == first
    assert receiver.stats['retry_attempts'] == 1
    assert receiver.stats['inserted'] == 3
    # The younger tail gets its own remaining hold; it cannot bypass the
    # failed head or restart the head's two-second coalescing interval.
    receiver._retry_spool(coalesce=True)
    assert receiver.db.insert_logs_batch.call_count == 2
    clock.advance(1.0)
    assert receiver._retry_spool(coalesce=True) is True
    assert receiver.db.insert_logs_batch.call_args.args[0] == later
    assert receiver.stats['inserted'] == 5
    assert receiver._spool.rows == 0


def test_stop_during_hold_preserves_committed_rows_for_restart(receiver, clock):
    receiver.db.insert_logs_batch.side_effect = successful
    staged = stage(receiver, 0, 3)
    receiver.running = True
    receiver._start_workers()
    wait_until(lambda: receiver._delivery_batch_deadline is not None)
    receiver.stop()
    assert not receiver._worker.is_alive()
    assert not receiver._delivery_worker.is_alive()
    receiver.db.insert_logs_batch.assert_not_called()
    assert committed_payloads(receiver) == staged
    receiver._spool.close()
    receiver._spool = None

    # Simulate process downtime. Replay uses persisted staging age rather than
    # starting a new two-second delay on every restart.
    clock.advance(3)
    replacement = type(receiver)(receiver.db, receiver.enricher)
    replacement._ensure_spool()
    try:
        assert replacement._retry_spool(coalesce=True) is True
        assert receiver.db.insert_logs_batch.call_args.args[0] == staged
        assert replacement._spool.rows == 0
    finally:
        replacement._spool.close()


def test_delivery_worker_flushes_sparse_durable_rows_after_bounded_hold(receiver, monkeypatch):
    import main

    receiver.batch_size = 1
    receiver.delivery_batch_timeout = 0.3
    receiver.db.insert_logs_batch.side_effect = successful
    monkeypatch.setattr(main, 'parse_log', lambda raw: {'raw_log': raw})
    receiver.running = True
    receiver._start_workers()
    try:
        receiver._accept_datagram(b'synthetic sparse event', ('192.0.2.10', 514))
        wait_until(lambda: receiver.stats['staged'] == 1)
        assert len(committed_payloads(receiver)) == 1
        receiver.db.insert_logs_batch.assert_not_called()
        wait_until(lambda: receiver.stats['inserted'] == 1)
        assert receiver.db.insert_logs_batch.call_count == 1
        assert receiver._spool.rows == 0
    finally:
        receiver.stop()


@pytest.mark.parametrize('coalesce, batch_size, calls_expected, rows_per_call', [
    (False, 200, 60, 40),  # Previous immediate-delivery cadence.
    (True, 1000, 30, 80),
])
def test_cadence_reduces_transaction_calls_without_losing_rows(
        receiver, clock, coalesce, batch_size, calls_expected, rows_per_call):
    """Synthetic 40 rows/s, one durable stage/s; not a disk-I/O benchmark."""
    db = receiver.db
    db.insert_logs_batch.side_effect = successful
    receiver.delivery_batch_size = receiver.effective_delivery_batch_size = batch_size
    expected = []
    for second in range(60):
        # Poll the oldest rows before the next second's intake, as the worker
        # also does between staging wakes. This creates two-stage PG batches.
        receiver._retry_spool(coalesce=coalesce)
        expected += stage(receiver, second * 40, 40)
        receiver._retry_spool(coalesce=coalesce)
        clock.advance(1)
    while receiver._spool.rows:
        receiver._retry_spool(coalesce=coalesce)
        clock.advance(1)
    calls = [call.args[0] for call in db.insert_logs_batch.call_args_list]
    assert len(calls) == calls_expected
    assert all(len(rows) == rows_per_call for rows in calls)
    assert [row for rows in calls for row in rows] == expected
    assert receiver.stats['inserted'] == 2400
    assert receiver.stats['dropped'] == 0


def test_repeated_failures_shrink_batches_to_floor_without_losing_or_reordering(receiver, clock):
    staged = stage(receiver, 0, 1000)
    receiver.db.insert_logs_batch.side_effect = RuntimeError('synthetic database timeout')
    for requested, reduced in ((1000, 500), (500, 250), (250, 125),
                               (125, 62), (62, 50), (50, 50)):
        assert receiver._retry_spool(coalesce=True) is True
        assert receiver.db.insert_logs_batch.call_args.args[0] == staged[:requested]
        assert receiver.effective_delivery_batch_size == reduced
        assert receiver._spool.rows == 1000
        assert receiver.stats['inserted'] == receiver.stats['dropped'] == 0
        calls = receiver.db.insert_logs_batch.call_count
        receiver._retry_spool(coalesce=True)
        assert receiver.db.insert_logs_batch.call_count == calls  # Backoff still applies.
        clock.advance(64)
    assert committed_payloads(receiver) == staged

    receiver.db.insert_logs_batch.reset_mock()
    receiver.db.insert_logs_batch.side_effect = successful
    while receiver._spool.rows:
        assert receiver._retry_spool(coalesce=True) is True
    delivered = [row for call in receiver.db.insert_logs_batch.call_args_list for row in call.args[0]]
    assert delivered == staged
    assert receiver.stats['inserted'] == 1000
    assert receiver.stats['dropped'] == 0


@pytest.mark.parametrize('seconds, dropped, expected', [
    (10.0, False, 500), (9.99, False, 1000),
    (0.0, True, 1000), (10.0, True, 500),
])
def test_slow_success_shrinks_but_fast_rejected_rows_do_not(receiver, clock, seconds, dropped, expected):
    stage(receiver, 0, 1000)

    def result(rows):
        clock.advance(seconds)
        return SimpleNamespace(inserted=0 if dropped else len(rows), duplicates=0,
                               dropped=len(rows) if dropped else 0, retryable=[])

    receiver.db.insert_logs_batch.side_effect = result
    assert receiver._retry_spool(coalesce=True) is True
    assert receiver.effective_delivery_batch_size == expected
    assert receiver._delivery_fast_successes == 0
    assert receiver._spool.rows == 0


def test_partial_retry_result_also_shrinks_the_limit(receiver, clock):
    staged = stage(receiver, 0, 1000)
    receiver.db.insert_logs_batch.side_effect = lambda rows: SimpleNamespace(
        inserted=999, duplicates=0, dropped=0, retryable=rows[-1:])
    assert receiver._retry_spool(coalesce=True) is True
    assert receiver.effective_delivery_batch_size == 500
    assert committed_payloads(receiver) == staged[-1:]
    assert receiver.stats['inserted'] == 999
    clock.advance(1)
    receiver.db.insert_logs_batch.side_effect = successful
    assert receiver._retry_spool(coalesce=True) is True
    assert receiver.db.insert_logs_batch.call_args.args[0] == staged[-1:]
    assert receiver.effective_delivery_batch_size == 500
    assert receiver.stats['inserted'] == 1000


def test_four_fast_full_batches_grow_limit_without_exceeding_configured_max(receiver, clock):
    receiver.effective_delivery_batch_size = 50
    receiver.db.insert_logs_batch.side_effect = successful
    staged = []
    for expected in (100, 200, 400, 800, 1000, 1000):
        current = receiver.effective_delivery_batch_size
        for index in range(4):
            staged += stage(receiver, len(staged), current)
            # Fresh batches flush at the effective threshold, not the ceiling.
            assert receiver._retry_spool(coalesce=True) is True
            assert len(receiver.db.insert_logs_batch.call_args.args[0]) == current
            assert receiver.effective_delivery_batch_size == (expected if index == 3 else current)
    delivered = [row for call in receiver.db.insert_logs_batch.call_args_list for row in call.args[0]]
    assert delivered == staged
    assert receiver._spool.rows == 0
    assert receiver.stats['dropped'] == 0


@pytest.mark.parametrize('reset_kind', ['partial', 'rejected', 'moderate'])
def test_partial_rejected_or_not_fast_batch_resets_growth_streak(receiver, clock, reset_kind):
    receiver.effective_delivery_batch_size = 100
    receiver.db.insert_logs_batch.side_effect = successful
    for index in range(3):
        stage(receiver, index * 100, 100)
        receiver._retry_spool(coalesce=True)
    assert receiver._delivery_fast_successes == 3

    def result(rows):
        if reset_kind == 'moderate':
            clock.advance(2.0)
        return SimpleNamespace(inserted=0 if reset_kind == 'rejected' else len(rows), duplicates=0,
                               dropped=len(rows) if reset_kind == 'rejected' else 0, retryable=[])

    receiver.db.insert_logs_batch.side_effect = result
    stage(receiver, 300, 20 if reset_kind == 'partial' else 100)
    clock.advance(2)
    assert receiver._retry_spool(coalesce=True) is True
    assert receiver.effective_delivery_batch_size == 100
    assert receiver._delivery_fast_successes == 0
    receiver.db.insert_logs_batch.side_effect = successful
    for index in range(4):
        stage(receiver, 400 + index * 100, 100)
        receiver._retry_spool(coalesce=True)
        assert receiver.effective_delivery_batch_size == (200 if index == 3 else 100)


def test_spool_cleanup_latency_does_not_reduce_database_batch_size(receiver, clock, monkeypatch):
    receiver.db.insert_logs_batch.side_effect = successful
    stage(receiver, 0, 1000)
    acknowledge = receiver._spool.acknowledge

    def slow_ack(*args, **kwargs):
        clock.advance(20)
        return acknowledge(*args, **kwargs)

    monkeypatch.setattr(receiver._spool, 'acknowledge', slow_ack)
    assert receiver._retry_spool(coalesce=True) is True
    assert receiver.effective_delivery_batch_size == 1000
    assert receiver._delivery_fast_successes == 1


@pytest.mark.parametrize('configured', [1, 25, 50])
def test_small_configured_max_is_also_the_adaptive_floor(receiver, clock, configured):
    receiver.delivery_batch_size = receiver.effective_delivery_batch_size = configured
    stage(receiver, 0, configured)
    receiver.db.insert_logs_batch.side_effect = RuntimeError('synthetic database outage')
    receiver._retry_spool(coalesce=True)
    assert receiver.effective_delivery_batch_size == configured
    clock.advance(1)
    receiver.db.insert_logs_batch.side_effect = successful
    receiver._retry_spool(coalesce=True)
    for index in range(4):
        stage(receiver, (index + 1) * configured, configured)
        receiver._retry_spool(coalesce=True)
        assert receiver.effective_delivery_batch_size == configured
