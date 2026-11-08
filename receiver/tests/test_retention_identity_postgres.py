"""Opt-in integration checks against a disposable local PostgreSQL database.

Set UNIFI_TEST_DB_DSN explicitly. Tests reject non-loopback hosts and database
names without a `_tests` suffix, and create/drop only their own random database.
No application DB environment variables are consulted for the connection.
"""

from datetime import datetime, timedelta, timezone
import importlib
import os
import sys
from unittest.mock import MagicMock, patch
from uuid import uuid4

import psycopg2
from psycopg2 import sql
from psycopg2.extras import RealDictCursor
import pytest

from db import Database
import retention


@pytest.fixture(scope='module')
def pg_db():
    dsn = os.environ.get('UNIFI_TEST_DB_DSN')
    if not dsn:
        pytest.skip('Set UNIFI_TEST_DB_DSN for disposable local PostgreSQL integration checks')
    params = psycopg2.extensions.parse_dsn(dsn)
    if params.get('host') not in ('127.0.0.1', 'localhost', '::1') or not params.get('dbname', '').endswith('_tests'):
        pytest.fail('Integration DSN must use a loopback host and a database ending in _tests')
    test_database = 'retention_identity_' + uuid4().hex + '_tests'
    admin = psycopg2.connect(**params)
    admin.autocommit = True
    with admin.cursor() as cur:
        cur.execute(sql.SQL('CREATE DATABASE {}').format(sql.Identifier(test_database)))
    db = Database({**params, 'dbname': test_database}, min_conn=1, max_conn=3)
    try:
        db.connect()
        yield db
    finally:
        db.close()
        with admin.cursor() as cur:
            cur.execute(sql.SQL('DROP DATABASE {}').format(sql.Identifier(test_database)))
        admin.close()


@pytest.fixture
def clean_db(pg_db):
    with pg_db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute('TRUNCATE logs, unifi_clients, unifi_devices, ip_threats, retention_daily_summaries RESTART IDENTITY')
            cur.execute('DELETE FROM system_config WHERE key = %s', [retention.POLICY_KEY])
    return pg_db


@pytest.fixture
def isolated_routes(monkeypatch):
    for name in ('routes.logs', 'routes.stats'):
        monkeypatch.delitem(sys.modules, name, raising=False)
    monkeypatch.setitem(sys.modules, 'deps', MagicMock())
    return importlib.import_module('routes.logs'), importlib.import_module('routes.stats')


def insert_events(db, rows):
    now = datetime.now(timezone.utc)
    for row in rows:
        row = dict(row)
        age = row.pop('age', 90)
        db.insert_log({'timestamp': now - timedelta(days=age), 'log_type': 'firewall',
                       'source': 'syslog', 'raw_log': '<134> fixture', **row})


def count_rows(db, table):
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql.SQL('SELECT COUNT(*) FROM {}').format(sql.Identifier(table)))
            return cur.fetchone()[0]


def test_policy_respects_security_even_for_allow_and_summarizes_once(clean_db, tmp_path):
    db = clean_db
    archive_dir = tmp_path.resolve()
    archive_dir.chmod(0o700)
    policy = retention.validate_policy({
        'enabled': True, 'security_days': 180, 'firewall_allow_days': 30,
        'type_days': {'dhcp': 365}, 'batch_size': 2,
        'summaries_enabled': True, 'archives_enabled': True,
        'archive_directory': str(archive_dir),
    })
    db.set_config(retention.POLICY_KEY, policy)
    insert_events(db, [
        {'rule_action': 'allow'},
        {'rule_action': 'allow', 'event_source': 'unifi_ips', 'ips_signature': 'Retain me'},
        {'rule_action': 'block'},
        {'age': 20, 'log_type': 'dns', 'source': 'pihole'},
        {'age': 70, 'log_type': 'dhcp'},
        {'age': 70, 'log_type': 'system'},
    ])
    result = db.run_retention_cleanup(60, 10)
    assert result['status'] == 'complete', result
    assert result['deleted_so_far'] == 4
    assert result['dns_deleted'] == 1
    assert result['non_dns_deleted'] == 3
    assert count_rows(db, 'logs') == 2
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT SUM(event_count) FROM retention_daily_summaries')
            assert cur.fetchone()[0] == 4
            cur.execute("SELECT event_count FROM retention_daily_summaries WHERE source = 'pihole'")
            assert cur.fetchone()[0] == 1
            cur.execute("SELECT COUNT(*) FROM logs WHERE event_source = 'unifi_ips'")
            assert cur.fetchone()[0] == 1
    files = list(archive_dir.iterdir())
    assert files
    again = db.run_retention_cleanup(60, 10)
    assert again['deleted_so_far'] == 0
    assert sorted(archive_dir.iterdir()) == sorted(files)
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT SUM(event_count) FROM retention_daily_summaries')
            assert cur.fetchone()[0] == 4


def test_archive_written_then_database_rollback_retries_without_double_counts(clean_db, tmp_path):
    db = clean_db
    archive_dir = tmp_path.resolve()
    archive_dir.chmod(0o700)
    policy = retention.validate_policy({'enabled': True, 'summaries_enabled': True,
        'archives_enabled': True, 'archive_directory': str(archive_dir)})
    db.set_config(retention.POLICY_KEY, policy)
    insert_events(db, [{'rule_action': 'block'}])
    original = retention._write_summaries

    def fail_after_summary(cur, rows, group_by_rule):
        original(cur, rows, group_by_rule)
        raise RuntimeError('simulated process failure before DELETE/COMMIT')

    with patch.object(retention, '_write_summaries', side_effect=fail_after_summary):
        failed = db.run_retention_cleanup(60, 10)
    assert failed['status'] == 'failed'
    assert count_rows(db, 'logs') == 1
    assert count_rows(db, 'retention_daily_summaries') == 0
    files = list(archive_dir.iterdir())
    assert len(files) == 1
    retry = db.run_retention_cleanup(60, 10)
    assert retry['status'] == 'complete'
    assert retry['deleted_so_far'] == 1
    assert retry['archives_written'] == 0
    assert list(archive_dir.iterdir()) == files
    assert count_rows(db, 'logs') == 0
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT SUM(event_count) FROM retention_daily_summaries')
            assert cur.fetchone()[0] == 1


def test_archive_disk_budget_keeps_raw_rows_and_summary_unmodified(clean_db, tmp_path):
    db = clean_db
    path = tmp_path.resolve()
    path.chmod(0o700)
    policy = retention.validate_policy({'enabled': True, 'summaries_enabled': True,
        'archives_enabled': True, 'archive_directory': str(path), 'archive_max_files': 1})
    (path / 'existing.jsonl.gz').write_bytes(b'existing archive')
    db.set_config(retention.POLICY_KEY, policy)
    insert_events(db, [{'rule_action': 'block'}])
    result = db.run_retention_cleanup(60, 10)
    assert result['status'] == 'failed'
    assert count_rows(db, 'logs') == 1
    assert count_rows(db, 'retention_daily_summaries') == 0
    assert (path / 'existing.jsonl.gz').read_bytes() == b'existing archive'


def test_source_names_follow_ip_and_suppress_known_router_misattribution(clean_db, isolated_routes):
    db = clean_db
    logs, _ = isolated_routes
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO unifi_devices(mac, ip, device_name) VALUES ('aa:bb:cc:dd:ee:ff', '10.20.0.1', 'Gateway')")
            cur.execute("INSERT INTO unifi_clients(mac, ip, device_name, last_seen) VALUES ('00:11:22:33:44:55', '10.20.0.20', 'Laptop', NOW())")
    insert_events(db, [
        {'src_ip': '203.0.113.50', 'mac_address': 'aa:bb:cc:dd:ee:ff', 'src_device_name': 'Gateway'},
        {'src_ip': '10.20.0.20', 'mac_address': 'aa:bb:cc:dd:ee:ff', 'src_device_name': 'Gateway'},
        {'src_ip': '10.20.0.21', 'mac_address': '00:11:22:33:44:66', 'src_device_name': 'Historical printer'},
    ])
    with db.get_conn() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(logs._LOG_DETAIL_SQL + ' ORDER BY l.id', [[], []])
            rows = cur.fetchall()
    assert len(rows) == 3
    assert rows[0]['src_device_name'] is None
    assert rows[1]['src_device_name'] == 'Laptop'
    assert rows[2]['src_device_name'] == 'Historical printer'
    # Display suppression leaves the stored evidence untouched.
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT src_device_name FROM logs ORDER BY id LIMIT 1')
            assert cur.fetchone()[0] == 'Gateway'


def test_outbound_threat_is_attributed_to_remote_destination(clean_db, isolated_routes):
    db = clean_db
    _, stats = isolated_routes
    insert_events(db, [{'age': 0, 'src_ip': '10.20.0.20', 'dst_ip': '203.0.113.50',
                        'remote_ip': '203.0.113.50', 'direction': 'outbound', 'threat_score': 90}])
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO ip_threats (ip, threat_score, threat_categories) VALUES ('203.0.113.50', 90, ARRAY['malware'])")
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            rows = stats._query_top_threat_ips(cur, datetime.now(timezone.utc) - timedelta(days=1), ['0.0.0.0'])
    assert len(rows) == 1
    assert rows[0]['ip'] == '203.0.113.50'
    assert rows[0]['threat_categories'] == ['malware']
    assert rows[0]['count'] == 1
