"""Opt-in upgrade/replay verification using synthetic data and a disposable PG.

Requirements: an explicit loopback UNIFI_TEST_DB_DSN, Docker container name in
UNIFI_TEST_PG_CONTAINER, and optional UNIFI_TEST_DOCKER_CONTEXT (default: default).
The container must publish its PostgreSQL port on the same loopback endpoint.
Use a disposable container whose database role can create databases. Never
point these variables at a production service. No application DB settings are
read. The fixture creates and removes only random upgrade_*_tests databases.

Run from the repository root with PYTHONPATH=receiver. The old schema is loaded
from the locally available v3.7.2 Git tag; dump/restore use that container's own
matching PostgreSQL tools, so host client installation is unnecessary.
"""

from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
from types import ModuleType, SimpleNamespace
from uuid import uuid4

import psycopg2
from psycopg2 import sql
import pytest

from cef_backfill import run_backfill
from db import Database
from ingest_queue import RetrySpool


SYNTHETIC_BLOCKED = (
    'Oct 28 12:34:56 synthetic-gateway CEF:0|Ubiquiti|UniFi Network|10.0.0|201|'
    'Threat Detected and Blocked|7|src=203.0.113.10 dst=10.20.0.4 proto=TCP '
    'spt=1234 dpt=443 act=blocked UNIFIrisk=medium '
    'UNIFIipsSignature=Synthetic migration detection UNIFIipsSignatureId=900001 '
    'UNIFIutcTime=2024-01-02T03:04:05Z'
)
SYNTHETIC_ALLOWED = (
    'Oct 28 12:35:56 synthetic-gateway CEF:0|Ubiquiti|UniFi Network|10.0.0|201|'
    'Threat Detected|5|src=2001:db8::10 dst=fd00::4 proto=UDP spt=1234 '
    'dpt=53 act=allowed UNIFIipsSignature=Synthetic allowed detection'
)
ORIGINAL_FIELDS = 'id, timestamp, log_type, raw_log, threat_score, src_device_name'


def _docker(container, *args, input_data=None):
    command = ['docker', '--context', os.environ.get('UNIFI_TEST_DOCKER_CONTEXT', 'default'),
               'exec']
    if input_data is not None:
        command.append('-i')
    command.extend([container, *args])
    return subprocess.run(command, input=input_data, capture_output=True, check=True,
                          timeout=60).stdout


def _read_rows(db, fields=ORIGINAL_FIELDS):
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(f'SELECT {fields} FROM logs ORDER BY id')
            return cur.fetchall()


def _row(raw_log, **changes):
    return {'timestamp': datetime(2026, 10, 28, tzinfo=timezone.utc),
            'log_type': 'firewall', 'source': 'syslog', 'raw_log': raw_log,
            'ingest_id': str(uuid4()), **changes}


@pytest.fixture(scope='module')
def upgrade_clone():
    dsn = os.environ.get('UNIFI_TEST_DB_DSN')
    container = os.environ.get('UNIFI_TEST_PG_CONTAINER')
    if not dsn or not container:
        pytest.skip('Set explicit disposable UNIFI_TEST_DB_DSN and UNIFI_TEST_PG_CONTAINER')
    params = psycopg2.extensions.parse_dsn(dsn)
    if params.get('host') not in ('127.0.0.1', 'localhost', '::1'):
        pytest.fail('Upgrade integration DSN must use an explicit loopback host')
    context = os.environ.get('UNIFI_TEST_DOCKER_CONTEXT', 'default')
    inspect = subprocess.run(
        ['docker', '--context', context, 'inspect', '--format', '{{json .NetworkSettings.Ports}}', container],
        capture_output=True, check=True, timeout=15,
    )
    mappings = json.loads(inspect.stdout).get('5432/tcp') or []
    if not any(item['HostIp'] in ('127.0.0.1', '::1')
               and item['HostPort'] == params.get('port', '5432') for item in mappings):
        pytest.fail('Disposable container loopback PostgreSQL port does not match integration DSN')
    repository = Path(__file__).resolve().parents[2]
    old_source = subprocess.run(['git', 'show', 'v3.7.2:receiver/db.py'], cwd=repository,
                                capture_output=True, check=True, timeout=15).stdout
    module_name = '_synthetic_upgrade_v372_' + uuid4().hex
    old_module = ModuleType(module_name)
    old_module.__file__ = 'v3.7.2:receiver/db.py'
    sys.modules[module_name] = old_module
    exec(compile(old_source, old_module.__file__, 'exec'), old_module.__dict__)
    prefix = 'upgrade_' + uuid4().hex
    source_name, clone_name = prefix + '_source_tests', prefix + '_clone_tests'
    created, old_db, current_db = [], None, None
    admin = psycopg2.connect(**params)
    admin.autocommit = True
    try:
        for name in (source_name, clone_name):
            with admin.cursor() as cur:
                cur.execute(sql.SQL('CREATE DATABASE {}').format(sql.Identifier(name)))
            created.append(name)
        old_db = old_module.Database({**params, 'dbname': source_name}, min_conn=1, max_conn=2)
        old_db.connect()
        original_time = datetime(2025, 1, 15, 3, 4, 5, tzinfo=timezone.utc)
        for log_type, raw_log, threat, device in (
            ('system', SYNTHETIC_BLOCKED, 91, 'Synthetic historical client'),
            ('unknown', SYNTHETIC_ALLOWED, 17, None),
            ('system', 'ordinary synthetic system message', None, None),
            ('firewall', 'ordinary synthetic firewall message', 80, 'Synthetic firewall client'),
            ('system', 'CEF:broken synthetic message', None, None),
        ):
            old_db.insert_log({'timestamp': original_time, 'log_type': log_type,
                'raw_log': raw_log, 'threat_score': threat, 'src_device_name': device})
        original = _read_rows(old_db)
        assert len(original) == 5
        old_db.close()
        old_db = None
        dump = _docker(container, 'pg_dump', '-U', params['user'], '--format=custom',
                       '--no-owner', '--no-privileges', source_name)
        assert dump.startswith(b'PGDMP')
        _docker(container, 'pg_restore', '-U', params['user'], '--dbname', clone_name,
                '--no-owner', '--no-privileges', '--exit-on-error', input_data=dump)
        # Observe the restored old schema before current code can migrate it.
        with psycopg2.connect(**{**params, 'dbname': clone_name}) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT column_name FROM information_schema.columns WHERE table_name='logs'")
                old_columns = {row[0] for row in cur.fetchall()}
                cur.execute(f'SELECT {ORIGINAL_FIELDS} FROM logs ORDER BY id')
                restored = cur.fetchall()
        assert 'event_source' not in old_columns and 'ingest_id' not in old_columns
        assert restored == original
        current_db = Database({**params, 'dbname': clone_name}, min_conn=1, max_conn=3)
        current_db.connect()
        current_db.ensure_post_boot_indexes()
        yield SimpleNamespace(db=current_db, original=original, dump_bytes=len(dump))
    finally:
        if old_db is not None:
            old_db.close()
        if current_db is not None:
            current_db.close()
        for name in reversed(created):
            with admin.cursor() as cur:
                cur.execute(sql.SQL('DROP DATABASE {} WITH (FORCE)').format(sql.Identifier(name)))
        admin.close()
        sys.modules.pop(module_name, None)


def test_dump_restore_upgrade_and_cef_backfill_are_lossless_and_idempotent(upgrade_clone):
    db = upgrade_clone.db
    assert _read_rows(db) == upgrade_clone.original
    # A second migration must preserve restored IDs and original evidence too.
    db._ensure_schema()
    assert _read_rows(db) == upgrade_clone.original
    with db.get_conn() as conn:
        dry = run_backfill(conn, batch_size=2, max_batches=10)
    assert dry['scanned'] == 5 and dry['matched'] == 2 and dry['updated'] == 0
    assert _read_rows(db) == upgrade_clone.original
    with db.get_conn() as conn:
        first = run_backfill(conn, apply=True, batch_size=2, max_batches=10)
    assert first['updated'] == 2 and first['complete'] is True
    repaired = _read_rows(db)
    assert len(repaired) == 5
    assert [row[0] for row in repaired] == [row[0] for row in upgrade_clone.original]
    assert [(row[3], row[4], row[5]) for row in repaired] == [
        (row[3], row[4], row[5]) for row in upgrade_clone.original]
    assert repaired[0][1] == datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    assert repaired[1][1] == upgrade_clone.original[1][1]  # no explicit UTC in CEF
    assert repaired[2:] == upgrade_clone.original[2:]
    with db.get_conn() as conn:
        second = run_backfill(conn, apply=True, batch_size=2, max_batches=10)
        with conn.cursor() as cur:
            cur.execute('SELECT event_source, rule_action, ips_signature_id FROM logs ORDER BY id LIMIT 2')
            assert cur.fetchall() == [('unifi_ips', 'block', '900001'), ('unifi_ips', 'allow', None)]
    assert second['matched'] == 0 and second['updated'] == 0
    assert _read_rows(db) == repaired


def test_actual_insert_counts_dedupe_across_pages_and_isolate_bad_rows(upgrade_clone):
    db = upgrade_clone.db
    rows = [_row('synthetic batch ' + str(index)) for index in range(1250)]
    result = db.insert_logs_batch(rows + [rows[37]])
    assert (result.inserted, result.duplicates, result.dropped, result.retryable) == (1250, 1, 0, [])
    replay = db.insert_logs_batch(rows)
    assert (replay.inserted, replay.duplicates, replay.dropped, replay.retryable) == (0, 1250, 0, [])
    batch = [_row('valid before invalid'), _row('bad inet', src_ip='not-an-ip'),
             _row('bad integer', src_port='not-a-port'), _row('bad NUL \x00 raw'),
             _row('bad NUL array', threat_categories=['synthetic\x00category']),
             _row('valid after invalid')]
    isolated = db.insert_logs_batch(batch)
    assert (isolated.inserted, isolated.duplicates, isolated.dropped, isolated.retryable) == (2, 0, 4, [])
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT raw_log FROM logs WHERE ingest_id = ANY(%s::uuid[]) ORDER BY raw_log',
                        [[row['ingest_id'] for row in batch]])
            assert cur.fetchall() == [('valid after invalid',), ('valid before invalid',)]


def test_one_invalid_row_does_not_force_per_row_commits(upgrade_clone, monkeypatch):
    db = upgrade_clone.db
    original = db.get_conn
    transactions = {'commits': 0, 'rollbacks': 0}

    @contextmanager
    def counted_connection():
        try:
            with original() as conn:
                yield conn
        except Exception:
            transactions['rollbacks'] += 1
            raise
        else:
            transactions['commits'] += 1

    rows = [_row(f'synthetic isolation {index}') for index in range(200)]
    rows[97]['src_ip'] = 'synthetic-invalid-address'
    monkeypatch.setattr(db, 'get_conn', counted_connection)
    result = db.insert_logs_batch(rows + [rows[33]])
    assert (result.inserted, result.duplicates, result.dropped, result.retryable) == (199, 1, 1, [])
    assert transactions == {'commits': 1, 'rollbacks': 1}


def test_bad_later_values_page_rolls_back_earlier_pages_before_isolation(upgrade_clone):
    db = upgrade_clone.db
    rows = [_row(f'synthetic paged isolation {index}') for index in range(1100)]
    rows[1098]['src_ip'] = 'synthetic-invalid-address'
    result = db.insert_logs_batch(rows + [rows[10], rows[1050]])
    assert (result.inserted, result.duplicates, result.dropped, result.retryable) == (1099, 2, 1, [])
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT COUNT(*) FROM logs WHERE ingest_id = ANY(%s::uuid[])',
                        [[row['ingest_id'] for row in rows]])
            assert cur.fetchone()[0] == 1099


@pytest.mark.parametrize('after_commit', [False, True])
def test_isolated_batch_commit_failure_never_acknowledges_rows(upgrade_clone, monkeypatch, after_commit):
    db = upgrade_clone.db
    original = db.get_conn
    calls = 0

    @contextmanager
    def failing_connection():
        nonlocal calls
        calls += 1
        current_call = calls
        with original() as conn:
            yield conn
            if current_call == 2 and not after_commit:
                raise psycopg2.OperationalError('synthetic failure before commit')
        if current_call == 2 and after_commit:
            raise psycopg2.OperationalError('synthetic lost commit acknowledgement')

    rows = [_row('synthetic isolation before'),
            _row('synthetic invalid inet', src_ip='invalid-address'),
            _row('synthetic isolation after')]
    monkeypatch.setattr(db, 'get_conn', failing_connection)
    result = db.insert_logs_batch(rows)
    assert (result.inserted, result.duplicates, result.dropped) == (0, 0, 0)
    assert result.retryable == rows
    monkeypatch.setattr(db, 'get_conn', original)
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT COUNT(*) FROM logs WHERE ingest_id = ANY(%s::uuid[])',
                        [[row['ingest_id'] for row in rows]])
            assert cur.fetchone()[0] == (2 if after_commit else 0)
    replay = db.insert_logs_batch(rows)
    assert (replay.inserted, replay.duplicates, replay.dropped, replay.retryable) == (
        0 if after_commit else 2, 2 if after_commit else 0, 1, [])


def test_transient_failure_during_isolation_rolls_back_valid_segments(upgrade_clone):
    db = upgrade_clone.db
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute('''CREATE FUNCTION synthetic_isolation_retry() RETURNS trigger AS $$
                BEGIN
                    IF NEW.raw_log = 'synthetic isolation serialization' THEN
                        RAISE EXCEPTION 'synthetic retry' USING ERRCODE='40001';
                    END IF;
                    RETURN NEW;
                END; $$ LANGUAGE plpgsql''')
            cur.execute('''CREATE TRIGGER synthetic_isolation_retry BEFORE INSERT ON logs
                FOR EACH ROW EXECUTE FUNCTION synthetic_isolation_retry()''')
    rows = [_row('synthetic isolation valid prefix'),
            _row('synthetic isolation bad inet', src_ip='invalid-address'),
            _row('synthetic isolation serialization')]
    try:
        result = db.insert_logs_batch(rows)
        assert (result.inserted, result.duplicates, result.dropped) == (0, 0, 0)
        assert result.retryable == rows
        with db.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute('SELECT COUNT(*) FROM logs WHERE ingest_id = ANY(%s::uuid[])',
                            [[row['ingest_id'] for row in rows]])
                assert cur.fetchone()[0] == 0
    finally:
        with db.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute('DROP TRIGGER synthetic_isolation_retry ON logs')
                cur.execute('DROP FUNCTION synthetic_isolation_retry()')
    replay = db.insert_logs_batch(rows)
    assert (replay.inserted, replay.duplicates, replay.dropped, replay.retryable) == (2, 0, 1, [])


def test_abuse_detail_patch_skips_unchanged_rows_without_usage_type(upgrade_clone):
    db = upgrade_clone.db
    ips = ['203.0.113.200', '203.0.113.201']
    rows = []
    for ip, side in zip(ips, ('src_ip', 'dst_ip')):
        for categories in (None, [], ['existing synthetic category']):
            rows.append(_row('synthetic metadata patch', **{
                side: ip, 'rule_action': 'block', 'threat_score': 42,
                'threat_categories': categories,
            }))
        rows.append(_row('synthetic allowed metadata remains unchanged', **{
            side: ip, 'rule_action': 'allow', 'threat_score': 42,
        }))
        db.upsert_threat(ip, {'threat_score': 42, 'threat_categories': ['synthetic threat category'],
                             'abuse_total_reports': 3, 'abuse_is_tor': False})
    assert db.insert_logs_batch(rows).inserted == 8
    assert db.patch_abuse_fields_for_ips(ips, ips) == 0  # excluded gateways/WANs
    assert db.patch_abuse_fields_for_ips(ips, []) == 6
    assert db.patch_abuse_fields_for_ips(ips, []) == 0
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute('''SELECT rule_action, abuse_usage_type, abuse_total_reports,
                                  abuse_is_tor, threat_categories
                           FROM logs WHERE ingest_id = ANY(%s::uuid[]) ORDER BY id''',
                        [[row['ingest_id'] for row in rows]])
            values = cur.fetchall()
    assert values == [
        ('block', None, 3, False, ['synthetic threat category']),
        ('block', None, 3, False, ['synthetic threat category']),
        ('block', None, 3, False, ['existing synthetic category']),
        ('allow', None, None, None, None),
    ] * 2
    # Changed data must still patch, including zero and false values. Repeating
    # that patch must not rewrite the same heap/index records again.
    for ip in ips:
        db.upsert_threat(ip, {'threat_score': 42, 'threat_categories': ['synthetic threat category'],
                             'abuse_total_reports': 0, 'abuse_is_tor': True})
    assert db.patch_abuse_fields_for_ips(ips, []) == 6
    assert db.patch_abuse_fields_for_ips(ips, []) == 0


def test_postgres_retryable_failure_does_not_acknowledge_uncommitted_rows(upgrade_clone):
    db = upgrade_clone.db
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute('''CREATE FUNCTION synthetic_ingest_retry() RETURNS trigger AS $$
                BEGIN
                    IF NEW.raw_log = 'synthetic serialization failure' THEN
                        RAISE EXCEPTION 'synthetic retry' USING ERRCODE='40001';
                    END IF;
                    RETURN NEW;
                END; $$ LANGUAGE plpgsql''')
            cur.execute('''CREATE TRIGGER synthetic_ingest_retry BEFORE INSERT ON logs
                FOR EACH ROW EXECUTE FUNCTION synthetic_ingest_retry()''')
    rows = [_row('synthetic before retry'), _row('synthetic serialization failure')]
    try:
        result = db.insert_logs_batch(rows)
        assert (result.inserted, result.duplicates, result.dropped) == (0, 0, 0)
        assert result.retryable == rows
        with db.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute('SELECT COUNT(*) FROM logs WHERE ingest_id = ANY(%s::uuid[])',
                            [[row['ingest_id'] for row in rows]])
                assert cur.fetchone()[0] == 0
    finally:
        with db.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute('DROP TRIGGER synthetic_ingest_retry ON logs')
                cur.execute('DROP FUNCTION synthetic_ingest_retry()')
    retry = db.insert_logs_batch(rows)
    assert (retry.inserted, retry.duplicates, retry.dropped, retry.retryable) == (2, 0, 0, [])


def test_crash_after_pg_commit_before_spool_ack_replays_without_duplicate_rows(upgrade_clone, tmp_path):
    db = upgrade_clone.db
    path = str(tmp_path / 'synthetic-retry.sqlite3')
    spool = RetrySpool(path)
    rows = [_row('synthetic crash replay ' + str(index)) for index in range(2)]
    try:
        assert spool.stage(rows)[1] == 0
        first = db.insert_logs_batch(spool.due(50))
        assert first.inserted == 2
    finally:
        spool.close()  # crash boundary: intentionally omit local acknowledgement
    spool = RetrySpool(path)
    try:
        replay_rows = spool.due(50)
        replay = db.insert_logs_batch(replay_rows)
        assert (replay.inserted, replay.duplicates, replay.dropped, replay.retryable) == (0, 2, 0, [])
        spool.acknowledge(replay_rows, replay.retryable)
        assert spool.snapshot()['rows'] == 0
        with db.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute('SELECT COUNT(*) FROM logs WHERE ingest_id = ANY(%s::uuid[])',
                            [[row['ingest_id'] for row in rows]])
                assert cur.fetchone()[0] == 2
    finally:
        spool.close()


def test_insert_forces_durable_commit_without_changing_pooled_session_default(upgrade_clone):
    db = upgrade_clone.db
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute('SHOW synchronous_commit')
            original_default = cur.fetchone()[0]
            cur.execute('SET synchronous_commit = off')
            cur.execute('''CREATE FUNCTION synthetic_require_durable_commit() RETURNS trigger AS $$
                BEGIN
                    IF current_setting('synchronous_commit') <> 'on' THEN
                        RAISE EXCEPTION 'synthetic durability requirement' USING ERRCODE='23514';
                    END IF;
                    RETURN NEW;
                END; $$ LANGUAGE plpgsql''')
            cur.execute('''CREATE TRIGGER synthetic_require_durable_commit BEFORE INSERT ON logs
                FOR EACH ROW EXECUTE FUNCTION synthetic_require_durable_commit()''')
    try:
        result = db.insert_logs_batch([_row('synthetic durable commit')])
        assert (result.inserted, result.duplicates, result.dropped, result.retryable) == (1, 0, 0, [])
        with db.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute('SHOW synchronous_commit')
                assert cur.fetchone()[0] == 'off'  # the insertion override was transaction-local
    finally:
        with db.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute('DROP TRIGGER synthetic_require_durable_commit ON logs')
                cur.execute('DROP FUNCTION synthetic_require_durable_commit()')
                cur.execute("SELECT set_config('synchronous_commit', %s, false)", [original_default])
