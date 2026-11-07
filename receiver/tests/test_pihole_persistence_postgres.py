"""Pi-hole replay and migration-index lifecycle on disposable PostgreSQL 16.

Set TEST_POSTGRES_DSN to an explicitly disposable loopback database. Each
test owns a random schema, and never reads application connection settings.
"""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import threading
import time
from uuid import uuid4
from unittest.mock import Mock

import psycopg2
from psycopg2 import pool, sql
import pytest

from db import Database


@pytest.fixture
def persistence_db(monkeypatch):
    dsn = os.environ.get('TEST_POSTGRES_DSN')
    if not dsn:
        pytest.skip('set TEST_POSTGRES_DSN for disposable PostgreSQL checks')
    params = psycopg2.extensions.parse_dsn(dsn)
    if params.get('host') not in ('127.0.0.1', 'localhost', '::1'):
        pytest.fail('Pi-hole integration DSN must use an explicit loopback host')
    monkeypatch.delenv('PIHOLE_HOST', raising=False)
    schema = 'pihole_persistence_' + uuid4().hex
    admin = psycopg2.connect(dsn)
    admin.autocommit = True
    with admin.cursor() as cur:
        cur.execute(sql.SQL('CREATE SCHEMA {}').format(sql.Identifier(schema)))
    params['options'] = params.get('options', '') + f' -c search_path={schema}'
    database = Database(conn_params=params, min_conn=1, max_conn=6)
    try:
        database.pool = pool.ThreadedConnectionPool(1, 6, **params)
        with database.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute((Path(__file__).resolve().parents[2] / 'init.sql').read_text())
                # Columns added by runtime schema migration. Its legacy
                # validation is public-schema-specific; keep this fixture
                # isolated without altering that unrelated behavior.
                cur.execute('''ALTER TABLE logs
                    ADD COLUMN remote_ip INET, ADD COLUMN ingest_id UUID,
                    ADD COLUMN source TEXT, ADD COLUMN event_source TEXT,
                    ADD COLUMN event_id TEXT, ADD COLUMN event_name TEXT,
                    ADD COLUMN ips_signature TEXT, ADD COLUMN ips_signature_id TEXT,
                    ADD COLUMN ips_severity SMALLINT, ADD COLUMN ips_risk TEXT''')
                cur.execute('CREATE UNIQUE INDEX idx_logs_ingest_id ON logs(ingest_id) '
                            'WHERE ingest_id IS NOT NULL')
        yield database
    finally:
        database.cancel_index_maintenance()
        if database._service_index_thread:
            database._service_index_thread.join(timeout=10)
        database.close()
        with admin.cursor() as cur:
            cur.execute(sql.SQL('DROP SCHEMA {} CASCADE').format(sql.Identifier(schema)))
        admin.close()


def _event(query_id, *, epoch=1760000000.125, **extra):
    raw = {'id': query_id, 'time': epoch, 'client': {'ip': '192.0.2.10'},
           'domain': 'capture.example.test', 'type': 'A', 'status': 'FORWARDED'}
    raw.update(extra)
    return {'timestamp': datetime.fromtimestamp(epoch, tz=timezone.utc),
            'log_type': 'dns', 'source': 'pihole', 'src_ip': '192.0.2.10',
            'dns_query': raw['domain'], 'dns_type': raw['type'], 'raw_log': json.dumps(raw)}


def _count(database):
    with database.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT count(*), count(DISTINCT ingest_id) FROM logs')
            return cur.fetchone()


def _index(database):
    with database.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT indisvalid FROM pg_index WHERE indexrelid = "
                        "to_regclass('idx_logs_fw_service_name_null_id')")
            return cur.fetchone()


def test_overlapping_workers_serialize_and_never_regress_cursor(persistence_db, monkeypatch):
    database = persistence_db
    other = Database(conn_params=database.conn_params)
    other.pool = pool.ThreadedConnectionPool(1, 2, **database.conn_params)
    entered, release = threading.Event(), threading.Event()
    insert_counts = []
    original = database._execute_log_insert

    def first_insert(cur, logs):
        entered.set()
        assert release.wait(5)
        count = original(cur, logs)
        insert_counts.append(count)
        return count

    def second_insert(cur, logs):
        count = original(cur, logs)
        insert_counts.append(count)
        return count

    monkeypatch.setattr(database, '_execute_log_insert', first_insert)
    monkeypatch.setattr(other, '_execute_log_insert', second_insert)
    events = [_event(i) for i in range(1, 1001)]
    try:
        with ThreadPoolExecutor(max_workers=2) as workers:
            first = workers.submit(database.insert_pihole_batch, events, 1000)
            assert entered.wait(5)
            second = workers.submit(other.insert_pihole_batch, events, 900)
            time.sleep(0.1)
            assert not second.done()  # The absent initial cursor row is locked too.
            release.set()
            assert first.result(timeout=10) == second.result(timeout=10) == 1000
        assert insert_counts == [1000, 0]
        assert _count(database) == (1000, 1000)
        assert database.get_config('pihole_last_cursor') == 1000
    finally:
        release.set()
        other.close()


def test_commit_reply_lost_then_restarted_worker_replays_once(persistence_db, monkeypatch):
    database = persistence_db
    real_pool = database.pool

    class LostCommitReply:
        def __init__(self, conn):
            self.conn = conn
        def __getattr__(self, key):
            return getattr(self.conn, key)
        def commit(self):
            self.conn.commit()
            raise psycopg2.OperationalError('synthetic lost commit acknowledgement')

    class AmbiguousPool:
        def getconn(self):
            return LostCommitReply(real_pool.getconn())
        def putconn(self, conn, close=False):
            real_pool.putconn(conn.conn, close=close)

    events = [_event(1), _event(2)]
    monkeypatch.setattr(database, 'pool', AmbiguousPool())
    with pytest.raises(psycopg2.OperationalError):
        database.insert_pihole_batch(events, 2)
    monkeypatch.setattr(database, 'pool', real_pool)
    restarted = Database(conn_params=database.conn_params)
    restarted.pool = pool.ThreadedConnectionPool(1, 2, **database.conn_params)
    try:
        assert restarted.insert_pihole_batch(events, 2) == 2
        assert _count(restarted) == (2, 2)
        assert restarted.get_config('pihole_last_cursor') == 2
    finally:
        restarted.close()


def test_host_alias_reset_and_changed_reply_do_not_duplicate(persistence_db):
    database = persistence_db
    generation = database.set_pihole_host('https://pihole.example.test/')
    assert database.insert_pihole_batch([_event(1)], 1,
        expected_host='https://pihole.example.test', expected_generation=generation) == 1
    source = database.get_config('pihole_source_id')
    generation = database.set_pihole_host('https://192.0.2.53')
    changed = _event(1, status='CACHE', reply={'type': 'IP', 'time': 0.0001})
    changed['dns_answer'] = '203.0.113.20'
    assert database.insert_pihole_batch([changed], 1,
        expected_host='https://192.0.2.53', expected_generation=generation) == 1
    assert _count(database) == (1, 1)
    assert database.get_config('pihole_source_id') == source
    # The upstream database can reuse IDs; a genuinely later event is distinct.
    assert database.insert_pihole_batch([_event(1, epoch=1760000010.125)], 1) == 1
    assert _count(database) == (2, 2)


def test_old_generation_rejected_even_after_switch_away_and_back(persistence_db):
    database = persistence_db
    original = database.set_pihole_host('https://pihole.example.test')
    database.set_pihole_host('https://other.example.test')
    current = database.set_pihole_host('https://pihole.example.test')
    assert current > original
    assert database.insert_pihole_batch([_event(10)], 10,
        expected_host='https://pihole.example.test', expected_generation=original) is None
    assert _count(database) == (0, 0)
    assert database.get_config('pihole_last_cursor') == 0
    assert database.insert_pihole_batch([_event(2)], 2,
        expected_host='https://other.example.test', expected_generation=current) is None


def test_host_change_serializes_behind_committing_old_poll(persistence_db, monkeypatch):
    database = persistence_db
    generation = database.set_pihole_host('https://old.example.test')
    entered, release = threading.Event(), threading.Event()
    original = database._execute_log_insert

    def slow_insert(cur, logs):
        entered.set()
        assert release.wait(5)
        return original(cur, logs)

    monkeypatch.setattr(database, '_execute_log_insert', slow_insert)
    with ThreadPoolExecutor(max_workers=2) as workers:
        old_poll = workers.submit(database.insert_pihole_batch, [_event(10)], 10,
            expected_host='https://old.example.test', expected_generation=generation)
        assert entered.wait(5)
        changed = workers.submit(database.set_pihole_host, 'https://new.example.test')
        time.sleep(0.1)
        assert not changed.done()
        release.set()
        assert old_poll.result(timeout=5) == 10
        assert changed.result(timeout=5) > generation
    assert database.get_config('pihole_last_cursor') == 0
    assert database.insert_pihole_batch([_event(11)], 11,
        expected_host='https://old.example.test', expected_generation=generation) is None
    assert _count(database) == (1, 1)


def test_batch_replay_measurement_uses_existing_unique_index(persistence_db, record_property):
    database = persistence_db
    events = [_event(i) for i in range(1, 5001)]
    begin = time.perf_counter()
    assert database.insert_pihole_batch(events, 5000) == 5000
    inserted = time.perf_counter()
    assert database.insert_pihole_batch(events, 4000) == 5000
    replayed = time.perf_counter()
    assert _count(database) == (5000, 5000)
    record_property('pihole_events', 5000)
    record_property('initial_insert_ms', round((inserted - begin) * 1000, 3))
    record_property('duplicate_replay_ms', round((replayed - inserted) * 1000, 3))
    record_property('retained_rows_after_replay', 5000)


def test_failed_batch_rolls_back_source_uuid_rows_and_cursor(persistence_db):
    database = persistence_db
    invalid = _event(2)
    invalid['src_ip'] = 'not an IP'
    with pytest.raises(psycopg2.DataError):
        database.insert_pihole_batch([_event(1), invalid], 2)
    assert _count(database) == (0, 0)
    assert database.get_config('pihole_last_cursor') is None
    assert database.get_config('pihole_source_id') is None
    with pytest.raises(ValueError):
        database.insert_pihole_batch([_event(3, time='NaN')], 3)
    assert _count(database) == (0, 0)


def test_pihole_forces_synchronous_commit_before_ack(persistence_db, monkeypatch):
    database = persistence_db
    original = database._execute_log_insert
    observed = []
    def insert(cur, logs):
        cur.execute('SHOW synchronous_commit')
        observed.append(cur.fetchone()[0])
        return original(cur, logs)
    monkeypatch.setattr(database, '_execute_log_insert', insert)
    with database.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute('SET synchronous_commit = off')
    database.insert_pihole_batch([_event(1)], 1)
    assert observed == ['on']


def test_collector_chunks_and_alias_reload_use_real_database_contract(persistence_db, monkeypatch):
    import pihole_api
    database = persistence_db
    monkeypatch.setattr(pihole_api, 'decrypt_api_key', lambda value: value)
    database.set_pihole_host('https://pihole.example.test')
    for key, value in (('pihole_password', 'synthetic-password'),
                       ('pihole_enabled', True), ('pihole_enrichment', 'none')):
        database.set_config(key, value)
    collector = pihole_api.PiHolePoller(database)
    collector._api_get = Mock(return_value={'queries': [
        json.loads(_event(i)['raw_log']) for i in range(1200, 0, -1)]})
    try:
        assert collector.poll() is True
        assert collector._last_cursor == database.get_config('pihole_last_cursor') == 1200
        assert _count(database) == (1200, 1200)
        database.set_pihole_host('https://192.0.2.53')
        collector.reload_config(restart_polling=False)
        assert collector._last_cursor == 0
        assert collector.poll(stop_event=threading.Event()) is True
        assert collector._last_cursor == 1200
        assert _count(database) == (1200, 1200)
        # An explicitly reset source can reuse a numeric query ID at a later
        # timestamp without confusing it with the earlier database epoch.
        database.set_pihole_host('https://pihole.example.test')
        collector.reload_config(restart_polling=False)
        collector._api_get.return_value = {'queries': [
            json.loads(_event(1, epoch=1760000010.125)['raw_log'])]}
        assert collector.poll(stop_event=threading.Event()) is True
        assert collector._last_cursor == 1
        assert _count(database) == (1201, 1201)
    finally:
        collector.stop_polling()


@pytest.mark.parametrize('marker', [None, False, 'true', 'false', 1, {}])
def test_unfinished_or_malformed_marker_keeps_valid_index(persistence_db, marker):
    database = persistence_db
    if marker is not None:
        database.set_config('service_name_backfill_done', marker)
    database.set_config('service_name_backfill_last_id', 15)
    database.maintain_service_name_backfill_index()
    assert _index(database) == (True,)
    database.maintain_service_name_backfill_index()
    assert _index(database) == (True,)
    assert database.get_config('service_name_backfill_done') == marker
    assert database.get_config('service_name_backfill_last_id') == 15


def test_completed_index_retired_not_recreated_by_bootstrap_then_reset_rebuilds(persistence_db):
    database = persistence_db
    database.maintain_service_name_backfill_index()
    assert _index(database) == (True,)
    database.set_config('service_name_backfill_done', True)
    database.set_config('service_name_backfill_last_id', 45)
    database.maintain_service_name_backfill_index()
    assert _index(database) is None
    with database.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute((Path(__file__).resolve().parents[2] / 'init.sql').read_text())
    assert _index(database) is None  # Schema startup must not recreate it.
    database.maintain_service_name_backfill_index()
    assert _index(database) is None
    database.set_config('service_name_backfill_done', False)
    database.maintain_service_name_backfill_index()
    assert _index(database) == (True,)
    assert database.get_config('service_name_backfill_last_id') == 45


def test_interrupted_service_index_build_recovered(persistence_db):
    database = persistence_db
    with database.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO logs(timestamp,log_type,dst_port,raw_log) VALUES"
                        "(NOW(),'firewall',53,''),(NOW(),'firewall',53,'')")
    conn = psycopg2.connect(**database.conn_params)
    conn.autocommit = True
    try:
        with conn.cursor() as cur:
            with pytest.raises(psycopg2.errors.UniqueViolation):
                cur.execute('CREATE UNIQUE INDEX CONCURRENTLY idx_logs_fw_service_name_null_id '
                            'ON logs(dst_port)')
    finally:
        conn.close()
    assert _index(database) == (False,)
    database.maintain_service_name_backfill_index()
    assert _index(database) == (True,)
    assert _count(database)[0] == 2


def test_concurrent_maintenance_cannot_race_marker_reset(persistence_db):
    database = persistence_db
    database.maintain_service_name_backfill_index()
    database.set_config('service_name_backfill_done', True)
    holding = psycopg2.connect(**database.conn_params)
    holding.autocommit = True
    try:
        with holding.cursor() as cur:
            cur.execute('SELECT pg_advisory_lock(%s)', [database._SERVICE_NAME_INDEX_LOCK])
        # A competing maintenance session skips, and cannot remove the index.
        database.maintain_service_name_backfill_index()
        assert _index(database) == (True,)
        began = time.perf_counter()
        with pytest.raises(psycopg2.errors.LockNotAvailable):
            database.set_config('service_name_backfill_done', False)
        assert time.perf_counter() - began < 1
        assert database.get_config('service_name_backfill_done') is True
        with holding.cursor() as cur:
            cur.execute('SELECT pg_advisory_unlock(%s)', [database._SERVICE_NAME_INDEX_LOCK])
        database.set_config('service_name_backfill_done', False)
        database.maintain_service_name_backfill_index()
        assert _index(database) == (True,)
        assert database.get_config('service_name_backfill_done') is False
    finally:
        holding.close()


def test_marker_does_not_wait_on_real_concurrent_index_snapshot(persistence_db):
    database = persistence_db
    writer = psycopg2.connect(**database.conn_params)
    maintenance = threading.Thread(target=database.maintain_service_name_backfill_index)
    try:
        with writer.cursor() as cur:
            cur.execute("INSERT INTO logs(timestamp,log_type,dst_port,raw_log) "
                        "VALUES(NOW(),'firewall',53,'synthetic unfinished write')")
        maintenance.start()
        deadline = time.monotonic() + 5
        phase = None
        while time.monotonic() < deadline:
            with database.get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT phase FROM pg_stat_progress_create_index "
                                "WHERE relid='logs'::regclass")
                    row = cur.fetchone()
                    phase = row[0] if row else None
            if phase == 'waiting for writers before build':
                break
            time.sleep(0.01)
        assert phase == 'waiting for writers before build'
        began = time.perf_counter()
        with pytest.raises(psycopg2.errors.LockNotAvailable):
            database.set_config('service_name_backfill_done', True)
        assert time.perf_counter() - began < 1
        assert database.get_config('service_name_backfill_done') is None
        writer.commit()
        maintenance.join(timeout=5)
        assert not maintenance.is_alive()
        assert _index(database) == (True,)
        database.set_config('service_name_backfill_done', True)
        database.maintain_service_name_backfill_index()
        assert _index(database) is None
        assert _count(database)[0] == 1
    finally:
        writer.rollback()
        writer.close()
        maintenance.join(timeout=10)


def test_failed_drop_preserves_done_marker_and_retries(persistence_db, monkeypatch):
    database = persistence_db
    database.maintain_service_name_backfill_index()
    database.set_config('service_name_backfill_done', True)
    real_connect = psycopg2.connect

    def unavailable(**kwargs):
        raise psycopg2.OperationalError('synthetic maintenance outage')

    monkeypatch.setattr(psycopg2, 'connect', unavailable)
    database.maintain_service_name_backfill_index()
    monkeypatch.setattr(psycopg2, 'connect', real_connect)
    assert _index(database) == (True,)
    assert database.get_config('service_name_backfill_done') is True
    database.maintain_service_name_backfill_index()
    assert _index(database) is None
