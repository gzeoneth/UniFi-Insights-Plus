"""Observe real stage/ack waits without holding storage locks in health reads."""

import json
import threading
import time
from types import SimpleNamespace

import pytest

from ingest_runtime import DEFAULT_QUEUE_CAPACITY, status_path
from tests.test_ingest_queue import receiver  # shared isolated receiver fixture


def test_health_defaults_to_shared_memory_without_overriding_explicit_path(monkeypatch):
    monkeypatch.delenv('INGEST_STATUS_PATH', raising=False)
    monkeypatch.setattr('ingest_runtime.os.path.isdir', lambda path: path == '/dev/shm')
    assert status_path() == '/dev/shm/unifi-log-insight/receiver-health.json'
    monkeypatch.setenv('INGEST_STATUS_PATH', '/tmp/explicit-health.json')
    assert status_path() == '/tmp/explicit-health.json'
    monkeypatch.setenv('INGEST_STATUS_PATH', '')
    assert status_path() == ''
    monkeypatch.delenv('INGEST_STATUS_PATH')
    monkeypatch.setattr('ingest_runtime.os.path.isdir', lambda path: False)
    assert status_path() == '/run/unifi-log-insight/receiver-health.json'


@pytest.mark.parametrize('phase', ['spool_stage', 'spool_read', 'spool_ack'])
def test_health_publishes_during_blocked_storage_phase(receiver, monkeypatch, phase):
    receiver._ensure_spool()
    entered, release = threading.Event(), threading.Event()
    operation = {'spool_stage': 'stage', 'spool_read': 'due_batch', 'spool_ack': 'acknowledge'}[phase]
    original = getattr(receiver._spool, operation)
    def slow(*args, **kwargs):
        entered.set()
        assert release.wait(3)
        return original(*args, **kwargs)
    if phase != 'spool_stage':
        receiver.batch = [{'raw_log': 'synthetic'}]
        receiver._flush_batch()
        receiver.db.insert_logs_batch.side_effect = lambda rows: SimpleNamespace(
            inserted=len(rows), duplicates=0, dropped=0, retryable=[])
    else:
        receiver.batch = [{'raw_log': 'synthetic'}]
    monkeypatch.setattr(receiver._spool, operation, slow)
    worker_name = 'producer' if phase == 'spool_stage' else 'delivery'
    thread = threading.Thread(target=receiver._flush_batch if phase == 'spool_stage' else receiver._retry_spool)
    thread.start()
    try:
        assert entered.wait(1)
        start = time.monotonic()
        receiver._write_status()
        assert time.monotonic() - start < 0.5
        with open(receiver._status_path) as stream:
            health = json.load(stream)
        worker = health['workers'][worker_name]
        assert worker['phase'] == phase
        assert worker['busy_since'] is not None
        assert worker['phase_started_at'] is not None
        assert health['updated_at'] >= worker['phase_started_at']
    finally:
        release.set()
        thread.join(3)
    assert not thread.is_alive()
    assert receiver._workers[worker_name]['phase'] == 'idle'
    assert receiver._workers[worker_name]['busy_since'] is None


def test_default_intake_absorbs_long_pause_burst_and_still_counts_overflow(receiver):
    assert receiver.queue.maxsize == DEFAULT_QUEUE_CAPACITY
    # 125 seconds at 70 events/s: larger than the old 4,096-packet queue.
    for _ in range(8750):
        receiver._accept_datagram(b'example', ('192.0.2.1', 514))
    assert receiver.stats['queue_dropped'] == 0
    for _ in range(DEFAULT_QUEUE_CAPACITY - 8750 + 1):
        receiver._accept_datagram(b'example', ('192.0.2.1', 514))
    assert receiver.queue.qsize() == DEFAULT_QUEUE_CAPACITY
    assert receiver.stats['queue_dropped'] == 1
    assert receiver.stats['dropped'] == 1
