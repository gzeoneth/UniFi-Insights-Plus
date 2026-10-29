"""Optional database-file reloads must not hold event staging or delivery."""
import importlib
import sys
import threading
import time
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest


@pytest.fixture
def receiver(monkeypatch, tmp_path):
    for name in ('backfill', 'blacklist', 'unifi_api', 'pihole_api', 'routes.auth', 'deps'):
        monkeypatch.setitem(sys.modules, name, MagicMock())
    monkeypatch.delitem(sys.modules, 'main', raising=False)
    module = importlib.import_module('main')
    monkeypatch.setattr(module, 'get_config', lambda _db, _key, default=None: default)
    monkeypatch.setattr(module, 'parse_log', lambda raw: {'raw_log': raw})
    monkeypatch.setenv('INGEST_SPOOL_PATH', str(tmp_path / 'spool.sqlite3'))
    monkeypatch.setenv('INGEST_STATUS_PATH', '')
    db, enricher = MagicMock(), MagicMock()
    enricher.enrich.side_effect = lambda row, **kwargs: row
    db.insert_logs_batch.side_effect = lambda rows: SimpleNamespace(
        inserted=len(rows), duplicates=0, dropped=0, retryable=[])
    receiver = module.SyslogReceiver(db, enricher)
    receiver.batch_size = 1
    receiver.running = True
    yield receiver
    receiver.stop()
    if receiver._spool is not None:
        receiver._spool.close()


def test_slow_reload_does_not_block_staging_or_delivery(receiver):
    entered, release, delivered = threading.Event(), threading.Event(), threading.Event()

    def reload():
        entered.set()
        assert release.wait(5)

    def insert(rows):
        delivered.set()
        return SimpleNamespace(inserted=len(rows), duplicates=0, dropped=0, retryable=[])

    receiver.enricher.reload_geoip.side_effect = reload
    receiver.db.insert_logs_batch.side_effect = insert
    receiver._start_workers()
    receiver.geoip_reload_requested = True
    try:
        assert entered.wait(2)
        receiver._accept_datagram(b'synthetic during reload', ('192.0.2.1', 514))
        assert delivered.wait(2), 'Reload held the event pipeline'
        assert receiver.stats['staged'] == 1
        assert receiver.stats['dropped'] == 0
    finally:
        release.set()


def test_background_geoip_read_does_not_block_unrelated_ingestion(receiver, tmp_path):
    from enrichment import GeoIPEnricher

    geoip = GeoIPEnricher(str(tmp_path / 'synthetic-mmdb'))
    entered, release, delivered = threading.Event(), threading.Event(), threading.Event()
    city = MagicMock()

    def lookup(ip):
        if ip == '192.0.2.1':
            entered.set()
            assert release.wait(10)
        return SimpleNamespace(country=SimpleNamespace(iso_code='AU'),
                               city=SimpleNamespace(name='Example city'), location=None)

    city.city.side_effect = lookup
    geoip.city_reader = city
    receiver.enricher.enrich.side_effect = lambda row, **kwargs: {
        **row, **geoip.lookup('198.51.100.2')}

    def insert(rows):
        assert rows[0]['geo_country'] == 'AU'
        delivered.set()
        return SimpleNamespace(inserted=len(rows), duplicates=0, dropped=0, retryable=[])

    receiver.db.insert_logs_batch.side_effect = insert
    background = threading.Thread(target=lambda: geoip.lookup('192.0.2.1'), daemon=True)
    background.start()
    try:
        assert entered.wait(2)
        receiver._start_workers()
        receiver._accept_datagram(b'synthetic unrelated cold lookup', ('192.0.2.10', 514))
        assert delivered.wait(2), 'Background GeoIP read held ingestion'
        assert receiver.stats['staged'] == 1
        assert receiver.stats['dropped'] == 0
    finally:
        release.set()
        background.join(2)
        receiver.stop()
        geoip.close()


def test_reload_requests_coalesce_and_worker_recovers_after_failure(receiver):
    entered, release, second = threading.Event(), threading.Event(), threading.Event()
    calls = []

    def reload():
        calls.append(threading.current_thread().name)
        if len(calls) == 1:
            entered.set()
            assert release.wait(5)
            raise OSError('synthetic unavailable replacement')
        second.set()

    receiver.enricher.reload_geoip.side_effect = reload
    receiver._start_workers()
    receiver.geoip_reload_requested = True
    try:
        assert entered.wait(2)
        for _ in range(20):
            receiver.geoip_reload_requested = True
        release.set()
        assert second.wait(2)
        receiver.stop()
        assert calls == ['ingest-maintenance', 'ingest-maintenance']
        assert not receiver._maintenance_worker.is_alive()
    finally:
        release.set()


def test_idle_delivery_flushes_committed_ack_without_reinserting(receiver):
    receiver.batch = [{'raw_log': 'synthetic committed event'}]
    receiver._flush_batch()
    receiver._retry_spool()
    assert receiver._spool.snapshot()['rows'] == 0
    assert receiver._spool.snapshot()['ack_pending_rows'] == 1
    receiver._spool._deferred_ack_max_age = 0.01
    receiver._start_workers()
    deadline = time.monotonic() + 2
    while receiver._spool.snapshot()['stored_rows'] and time.monotonic() < deadline:
        time.sleep(0.01)
    assert receiver._spool.snapshot()['stored_rows'] == 0
    assert receiver.db.insert_logs_batch.call_count == 1
    assert receiver.stats['inserted'] == 1
    assert receiver.stats['duplicates'] == 0


def test_rejected_rows_are_not_deferred_as_committed(receiver):
    receiver.batch = [{'raw_log': 'synthetic bad event'}]
    receiver._flush_batch()
    receiver.db.insert_logs_batch.side_effect = lambda rows: SimpleNamespace(
        inserted=0, duplicates=0, dropped=1, retryable=[])
    receiver._retry_spool()
    assert receiver.stats['dropped'] == 1
    assert receiver._spool.snapshot()['stored_rows'] == 0
    assert receiver._spool.snapshot()['ack_pending_rows'] == 0


def test_ack_cleanup_failure_retains_committed_rows_and_recovers(receiver, monkeypatch):
    receiver.batch = [{'raw_log': 'synthetic durable event'}, {'raw_log': 'synthetic later event'}]
    receiver._flush_batch()
    receiver._retry_spool()
    flush = receiver._spool.flush_acknowledgements
    broken = MagicMock(side_effect=OSError('synthetic storage unavailable'))
    monkeypatch.setattr(receiver._spool, 'flush_acknowledgements', broken)
    receiver._flush_acknowledgements(force=True)
    receiver._flush_acknowledgements()
    assert broken.call_count == 1  # Do not hammer stalled storage on each poll.
    assert receiver._spool.snapshot()['stored_rows'] == 2
    assert receiver.stats['inserted'] == 1
    assert receiver.stats['dropped'] == 0
    assert receiver._spool_failed is True
    monkeypatch.setattr(receiver._spool, 'flush_acknowledgements', flush)
    receiver._retry_spool()
    assert receiver.stats['inserted'] == 2
    assert receiver._spool_failed is True  # Deferred success is not a storage commit.
    receiver._flush_acknowledgements(force=True)
    assert receiver._spool.snapshot()['stored_rows'] == 0
    assert receiver._spool_failed is False
