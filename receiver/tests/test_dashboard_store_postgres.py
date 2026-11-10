"""Transactional dashboard projection checks on disposable PostgreSQL.

TEST_POSTGRES_DSN must name an explicitly disposable loopback database. Each
test owns a separate schema, including its raw events, projection and triggers.
No application connection settings or network services are used.
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import threading
import time
from uuid import uuid4

import psycopg2
from psycopg2 import pool, sql
from psycopg2.extras import RealDictCursor
import pytest

from db import Database
import dashboard_store as store
from dashboard_source import choose_dashboard_source, projection_scope
from field_filters import append_exclusions


NOW = datetime(2026, 1, 12, 12, 34, 56, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def _enable_dashboard_projection(monkeypatch):
    monkeypatch.setenv('DASHBOARD_ANALYTICS_ENABLED', 'true')
    monkeypatch.setenv('DASHBOARD_ANALYTICS_BACKFILL_ENABLED', 'true')


class StoreFixture:
    def __init__(self, params):
        self.params = params
        self.connections = []
        self.control = None
        self.database = Database(conn_params=params, min_conn=1, max_conn=4)
        self.database.pool = pool.ThreadedConnectionPool(1, 4, **params)

    def connect(self):
        connection = psycopg2.connect(**self.params)
        self.connections.append(connection)
        return connection

    def control_connection(self):
        if self.control is None:
            self.control = self.connect()
        return self.control

    def execute(self, statement, args=None, *, connection=None):
        connection = connection or self.control_connection()
        with connection.cursor() as cursor:
            cursor.execute(statement, args)
            rows = cursor.fetchall() if cursor.description else None
        connection.commit()
        return rows

    def install(self):
        connection = self.control_connection()
        store.install_schema(connection)
        connection.commit()

    def state(self, connection=None):
        connection = connection or self.control_connection()
        with connection.cursor() as cursor:
            state = store.snapshot_state(cursor)
        connection.commit()
        return state

    def backfill(self, *, batch_size=2, connection=None):
        connection = connection or self.control_connection()
        return store.backfill_step(connection, batch_size=batch_size, now=NOW)

    def finish(self, *, batch_size=2, max_steps=200):
        for _ in range(max_steps):
            if self.state()['complete']:
                return
            self.backfill(batch_size=batch_size)
        pytest.fail('bounded synthetic backfill did not reach complete coverage')

    def add(self, *, connection=None, **values):
        row = dict(timestamp=NOW - timedelta(minutes=10), log_type='firewall',
                   direction='outbound', rule_action='allow',
                   src_ip='192.0.2.10', dst_ip='198.51.100.20',
                   remote_ip='198.51.100.20', src_port=40000, dst_port=443,
                   protocol='tcp', service_name='Example service',
                   rule_name='Example rule', rule_desc='Example description',
                   hostname='example-gateway', interface_in='example-in',
                   interface_out='example-out', geo_country='ZZ',
                   asn_name='Example ASN', raw_log='Synthetic event')
        row.update(values)
        statement = sql.SQL('INSERT INTO logs ({}) VALUES ({}) RETURNING id').format(
            sql.SQL(',').join(map(sql.Identifier, row)),
            sql.SQL(',').join(sql.Placeholder() for _ in row),
        )
        return self.execute(statement, list(row.values()), connection=connection)[0][0]

    def assert_matches_raw(self):
        connection = self.control_connection()
        with connection.cursor() as cursor:
            cursor.execute('SELECT id,to_jsonb(logs) FROM logs ORDER BY id')
            raw = dict(cursor.fetchall())
            cursor.execute('SELECT id,to_jsonb(dashboard_events) FROM dashboard_events ORDER BY id')
            projected = dict(cursor.fetchall())
        connection.commit()
        assert projected.keys() == raw.keys()
        for ident, row in projected.items():
            original = raw[ident]
            for column, value in row.items():
                if column in original:
                    assert value == original[column], (ident, column)
            is_ips = (original.get('event_source') in ('unifi_ips', 'ips')
                      or original.get('ips_signature_id') is not None)
            message = original.get('raw_log') or ''
            is_cef = (not is_ips and 'CEF:' in message and (
                '|Threat' in message or 'UNIFIipsSignature' in message
                or 'unifipolicytype=ids/ips' in message.lower()))
            assert row['security_ips'] is is_ips
            assert row['security_cef'] is is_cef


@pytest.fixture
def dashboard_store_db():
    dsn = os.environ.get('TEST_POSTGRES_DSN')
    if not dsn:
        pytest.skip('set TEST_POSTGRES_DSN for disposable PostgreSQL checks')
    params = psycopg2.extensions.parse_dsn(dsn)
    if params.get('host') not in ('127.0.0.1', 'localhost', '::1'):
        pytest.fail('Dashboard store tests require an explicit loopback host')
    schema = 'dashboard_store_' + uuid4().hex
    admin = psycopg2.connect(dsn)
    admin.autocommit = True
    with admin.cursor() as cursor:
        cursor.execute(sql.SQL('CREATE SCHEMA {}').format(sql.Identifier(schema)))
    params['options'] = params.get('options', '') + f' -c search_path={schema} -c timezone=UTC'
    fixture = StoreFixture(params)
    try:
        fixture.execute((Path(__file__).resolve().parents[2] / 'init.sql').read_text())
        fixture.execute('''ALTER TABLE logs
            ADD COLUMN remote_ip INET, ADD COLUMN ingest_id UUID,
            ADD COLUMN source TEXT, ADD COLUMN event_source TEXT,
            ADD COLUMN event_id TEXT, ADD COLUMN event_name TEXT,
            ADD COLUMN ips_signature TEXT, ADD COLUMN ips_signature_id TEXT,
            ADD COLUMN ips_severity SMALLINT, ADD COLUMN ips_risk TEXT''')
        fixture.execute('CREATE UNIQUE INDEX idx_logs_ingest_id ON logs(ingest_id) '
                        'WHERE ingest_id IS NOT NULL')
        yield fixture
    finally:
        fixture.database.close()
        for connection in fixture.connections:
            connection.close()
        with admin.cursor() as cursor:
            cursor.execute(sql.SQL('DROP SCHEMA {} CASCADE').format(sql.Identifier(schema)))
        admin.close()


@pytest.mark.parametrize('value', ['0', 'false', 'no', 'off', ' FALSE '])
def test_dashboard_store_can_be_explicitly_disabled(value):
    assert store.enabled({'DASHBOARD_ANALYTICS_ENABLED': value}) is False


def test_dashboard_store_requires_explicit_opt_in():
    assert store.enabled({}) is False
    assert store.enabled({'DASHBOARD_ANALYTICS_ENABLED': 'true'}) is True


def test_historical_copy_defaults_on_and_accepts_an_independent_pause():
    assert store.backfill_enabled({}) is True
    for value in ('0', 'false', 'no', 'off', ' FALSE '):
        assert store.backfill_enabled({'DASHBOARD_ANALYTICS_BACKFILL_ENABLED': value}) is False
    for value in ('1', 'true', 'yes', 'on', ' TRUE '):
        assert store.backfill_enabled({'DASHBOARD_ANALYTICS_BACKFILL_ENABLED': value}) is True
    assert store.backfill_enabled({'DASHBOARD_ANALYTICS_ENABLED': 'false'}) is True


def test_worker_pauses_when_collection_health_cannot_be_read():
    def unavailable():
        raise RuntimeError('Synthetic unavailable collection status')

    assert store._pause_requested(None) is False
    assert store._pause_requested(lambda: False) is False
    assert store._pause_requested(lambda: True) is True
    assert store._pause_requested(unavailable) is True


def test_uninstalled_store_has_no_usable_coverage(dashboard_store_db):
    fixture = dashboard_store_db
    assert fixture.state() is None
    fixture.add()
    fixture.install()
    state = fixture.state()
    assert state['schema_version'] == 1
    assert not state['complete']
    assert state['coverage_from'] is None
    assert state['status'] in ('pending', 'backfill')
    assert fixture.execute('SELECT count(*) FROM dashboard_events')[0][0] == 0


def test_repeated_install_preserves_live_rows_and_backfill_progress(dashboard_store_db):
    fixture = dashboard_store_db
    fixture.add(timestamp=NOW - timedelta(hours=2))
    fixture.add(timestamp=NOW - timedelta(minutes=5))
    fixture.install()
    fixture.backfill(batch_size=1)
    before = fixture.state()
    projected = fixture.execute('SELECT id FROM dashboard_events ORDER BY id')
    fixture.install()
    after = fixture.state()
    assert after['epoch'] == before['epoch']
    for name in ('coverage_from', 'band_lower', 'band_upper', 'cursor_timestamp', 'cursor_id'):
        assert after[name] == before[name]
    assert fixture.execute('SELECT id FROM dashboard_events ORDER BY id') == projected
    fixture.finish(batch_size=1)
    fixture.assert_matches_raw()


def test_insert_and_duplicate_replay_project_only_actual_rows(dashboard_store_db):
    fixture = dashboard_store_db
    fixture.install()
    event = dict(timestamp=NOW, log_type='firewall', raw_log='Synthetic durable event',
                 ingest_id=str(uuid4()), src_ip='2001:db8::12/64', rule_action='block')
    first = fixture.database.insert_logs_batch([event, dict(event)])
    second = fixture.database.insert_logs_batch([dict(event, raw_log='Replay changes nothing')])
    assert first.inserted == 1 and first.duplicates == 1
    assert second.inserted == 0 and second.duplicates == 1
    assert fixture.execute('SELECT count(*) FROM logs')[0][0] == 1
    fixture.assert_matches_raw()


def test_rollback_does_not_publish_projection_rows(dashboard_store_db):
    fixture = dashboard_store_db
    fixture.install()
    connection = fixture.connect()
    with connection.cursor() as cursor:
        cursor.execute("INSERT INTO logs(timestamp,log_type,raw_log) VALUES(%s,'system','Uncommitted')", [NOW])
        cursor.execute('SELECT count(*) FROM dashboard_events')
        assert cursor.fetchone()[0] == 1
    connection.rollback()
    assert fixture.execute('SELECT count(*) FROM logs')[0][0] == 0
    assert fixture.execute('SELECT count(*) FROM dashboard_events')[0][0] == 0


def test_bulk_statement_transitions_preserve_every_actual_row(dashboard_store_db):
    fixture = dashboard_store_db
    fixture.install()
    fixture.execute('''INSERT INTO logs(timestamp,log_type,rule_action,raw_log,ingest_id)
        SELECT %s,'firewall',CASE WHEN i %% 2=0 THEN 'block' ELSE 'allow' END,
               'Synthetic bulk event',md5('example-bulk-'||i)::uuid
        FROM generate_series(1,7) AS i''', [NOW])
    fixture.assert_matches_raw()
    fixture.execute("UPDATE logs SET id=id+1000,service_name='Bulk update',threat_score=81,timestamp=timestamp-interval '3 hours'")
    fixture.assert_matches_raw()
    fixture.execute('DELETE FROM logs WHERE id IN (SELECT id FROM logs ORDER BY id LIMIT 3)')
    fixture.assert_matches_raw()


def test_failed_store_install_rolls_back_without_blocking_raw_writes(dashboard_store_db):
    fixture = dashboard_store_db
    params = dict(fixture.params)
    params['options'] += ' -c default_transaction_read_only=on'
    assert store.ensure_dashboard_store(params) is False
    assert fixture.state() is None
    fixture.add(raw_log='Raw ingestion remains available')
    assert fixture.execute('SELECT count(*) FROM logs')[0][0] == 1


def test_concurrent_install_is_idempotent(dashboard_store_db):
    fixture = dashboard_store_db
    fixture.add()
    with ThreadPoolExecutor(max_workers=2) as executor:
        installed = list(executor.map(store.ensure_dashboard_store, [fixture.params, fixture.params]))
    # The optional installer may decline the advisory lock while its peer
    # installs. A later retry must be idempotent and retain one valid store.
    assert any(installed)
    assert store.ensure_dashboard_store(fixture.params) is True
    fixture.add(raw_log='Inserted after both installers')
    fixture.finish()
    fixture.assert_matches_raw()


def test_disabled_interval_rebuilds_missed_rows_before_reusing_coverage(dashboard_store_db, monkeypatch):
    fixture = dashboard_store_db
    fixture.install()
    changed = fixture.add()
    deleted = fixture.add(raw_log='Deleted during disabled interval')
    fixture.finish()
    before = fixture.state()
    monkeypatch.setenv('DASHBOARD_ANALYTICS_ENABLED', 'false')
    assert store.ensure_dashboard_store(fixture.params) is True
    disabled = fixture.state()
    assert disabled['status'] == 'disabled'
    assert disabled['triggers_enabled'] is False
    fixture.execute("UPDATE logs SET service_name='Changed while disabled' WHERE id=%s", [changed])
    fixture.execute('DELETE FROM logs WHERE id=%s', [deleted])
    fixture.add(raw_log='Inserted while disabled')
    monkeypatch.setenv('DASHBOARD_ANALYTICS_ENABLED', 'true')
    assert store.ensure_dashboard_store(fixture.params) is True
    reset = fixture.state()
    assert reset['epoch'] > before['epoch']
    assert not reset['complete'] and reset['coverage_from'] is None
    fixture.finish()
    fixture.assert_matches_raw()


def test_missing_trigger_invalidates_old_coverage_before_repair(dashboard_store_db):
    fixture = dashboard_store_db
    fixture.install()
    fixture.add()
    fixture.finish()
    before = fixture.state()
    fixture.execute('DROP TRIGGER dashboard_store_insert ON logs')
    assert fixture.state()['triggers_enabled'] is False
    fixture.add(raw_log='Missed by the removed trigger')
    fixture.install()
    assert fixture.state()['epoch'] > before['epoch']
    assert not fixture.state()['complete']
    fixture.finish()
    fixture.assert_matches_raw()


def test_missing_projection_does_not_reuse_previous_complete_coverage(dashboard_store_db):
    fixture = dashboard_store_db
    fixture.install()
    fixture.add()
    fixture.finish()
    before = fixture.state()
    fixture.execute('DROP TABLE dashboard_events')
    assert not fixture.state()['healthy']
    fixture.install()
    reset = fixture.state()
    assert reset['epoch'] > before['epoch']
    assert not reset['complete'] and reset['coverage_from'] is None
    fixture.finish()
    fixture.assert_matches_raw()


def test_projection_without_metadata_is_not_trusted_or_overwritten(dashboard_store_db):
    fixture = dashboard_store_db
    fixture.install()
    changed = fixture.add()
    removed = fixture.add(raw_log='Removed after metadata was lost')
    fixture.finish()
    previous = fixture.execute('SELECT id,to_jsonb(dashboard_events) FROM dashboard_events ORDER BY id')
    fixture.execute('ALTER TABLE logs DISABLE TRIGGER USER')
    fixture.execute('DROP TABLE dashboard_store_state')
    fixture.execute("UPDATE logs SET service_name='New authoritative value' WHERE id=%s", [changed])
    fixture.execute('DELETE FROM logs WHERE id=%s', [removed])
    assert fixture.state() is None
    assert store.ensure_dashboard_store(fixture.params) is False
    assert fixture.state() is None
    assert fixture.execute('SELECT id,to_jsonb(dashboard_events) FROM dashboard_events ORDER BY id') == previous
    fixture.add(raw_log='Raw writes remain available after failed ownership check')
    assert fixture.execute('SELECT count(*) FROM logs')[0][0] == 2


def test_unlogged_projection_or_missing_time_index_is_not_healthy(dashboard_store_db):
    fixture = dashboard_store_db
    fixture.install()
    assert fixture.state()['healthy']
    fixture.execute('DROP INDEX idx_dashboard_events_time')
    assert not fixture.state()['healthy']
    fixture.install()
    assert fixture.state()['healthy']
    fixture.execute('ALTER TABLE dashboard_events SET UNLOGGED')
    assert not fixture.state()['healthy']


def test_missing_primary_index_disables_projection_writes_for_raw_fallback(dashboard_store_db):
    fixture = dashboard_store_db
    fixture.install()
    fixture.add()
    fixture.finish()
    fixture.execute('ALTER TABLE dashboard_events DROP CONSTRAINT dashboard_events_pkey')
    assert not fixture.state()['healthy']
    assert store.ensure_dashboard_store(fixture.params) is False
    state = fixture.state()
    assert state['triggers_enabled'] is False
    assert state['status'] == 'disabled' and not state['complete']
    fixture.add(raw_log='Raw ingestion survives a damaged projection index')
    assert fixture.execute('SELECT count(*) FROM logs')[0][0] == 2


@pytest.mark.parametrize('populated', [False, True])
def test_same_named_wrong_primary_key_is_not_trusted(dashboard_store_db, populated):
    fixture = dashboard_store_db
    fixture.install()
    if populated:
        fixture.add()
        fixture.finish()
    fixture.execute('ALTER TABLE dashboard_events DROP CONSTRAINT dashboard_events_pkey')
    fixture.execute('ALTER TABLE dashboard_events ADD CONSTRAINT dashboard_events_pkey '
                    'PRIMARY KEY (timestamp,id)')
    assert not fixture.state()['healthy']
    # Empty owned schemas can be repaired without touching historical events.
    # A populated wrong key is ambiguous damage and must fail safely to raw.
    assert store.ensure_dashboard_store(fixture.params) is (not populated)
    state = fixture.state()
    if populated:
        assert not state['triggers_enabled'] and state['status'] == 'disabled'
    else:
        assert state['healthy']
    fixture.add(raw_log='Authoritative insert after primary-key validation')
    if populated:
        assert fixture.execute('SELECT count(*) FROM logs')[0][0] == 2
        assert fixture.execute('SELECT count(*) FROM dashboard_events')[0][0] == 1
    else:
        fixture.finish()
        fixture.assert_matches_raw()


@pytest.mark.parametrize('definition', [
    'ON dashboard_events(timestamp,id)',
    'ON dashboard_events(timestamp DESC,id DESC) WHERE log_type=\'firewall\'',
    'ON dashboard_events(timestamp DESC)',
    'ON dashboard_events USING brin(timestamp)',
    'ON dashboard_events(timestamp DESC,id DESC) INCLUDE(hostname)',
    'UNIQUE ON dashboard_events(timestamp DESC,id DESC)',
])
def test_wrong_chronological_index_is_rebuilt_without_reusing_its_name_as_health(
        dashboard_store_db, definition):
    fixture = dashboard_store_db
    fixture.add()
    fixture.install()
    fixture.finish()
    before = fixture.state()
    fixture.execute('DROP INDEX idx_dashboard_events_time')
    # All definitions here are valid indexes with the expected owned name;
    # validity alone does not establish the required chronological access path.
    if definition.startswith('UNIQUE '):
        statement = 'CREATE UNIQUE INDEX idx_dashboard_events_time ' + definition[7:]
    else:
        statement = 'CREATE INDEX idx_dashboard_events_time ' + definition
    fixture.execute(statement)
    assert not fixture.state()['healthy']
    assert store.ensure_dashboard_store(fixture.params) is True
    after = fixture.state()
    assert after['healthy'] and after['complete']
    assert after['epoch'] == before['epoch']
    fixture.assert_matches_raw()


@pytest.mark.parametrize('alteration', [
    'ALTER COLUMN hostname TYPE varchar(64)',
    'ALTER COLUMN service_name TYPE varchar(128)',
    'ALTER COLUMN security_ips DROP NOT NULL',
    'ALTER COLUMN timestamp DROP NOT NULL',
    'ADD COLUMN unrelated_extra integer',
])
def test_projection_schema_drift_disables_derived_writes(dashboard_store_db, alteration):
    fixture = dashboard_store_db
    fixture.install()
    fixture.add()
    fixture.finish()
    fixture.execute('ALTER TABLE dashboard_events ' + alteration)
    assert not fixture.state()['healthy']
    assert store.ensure_dashboard_store(fixture.params) is False
    state = fixture.state()
    assert not state['complete'] and not state['triggers_enabled']
    fixture.add(raw_log='Raw insert survives incompatible derived schema')
    assert fixture.execute('SELECT count(*) FROM logs')[0][0] == 2


def test_snapshot_health_is_identical_with_real_dict_cursor(dashboard_store_db):
    fixture = dashboard_store_db
    fixture.install()
    fixture.add()
    fixture.finish()
    expected = fixture.state()
    connection = fixture.connect()
    with connection.cursor(cursor_factory=RealDictCursor) as cursor:
        actual = store.snapshot_state(cursor)
    connection.commit()
    assert actual == expected
    assert actual['healthy'] is True
    fixture.execute('DROP INDEX idx_dashboard_events_time')
    with connection.cursor(cursor_factory=RealDictCursor) as cursor:
        assert store.snapshot_state(cursor)['healthy'] is False
    connection.commit()


@pytest.mark.parametrize('timestamp', ['-infinity', 'infinity'])
def test_nonfinite_historical_timestamp_retains_raw_fallback_until_fixed(
        dashboard_store_db, timestamp):
    fixture = dashboard_store_db
    ident = fixture.add(timestamp=timestamp)
    fixture.add()
    fixture.install()
    assert fixture.backfill(batch_size=1) == {
        'status': 'unsupported', 'rows': 0, 'reason': 'nonfinite_timestamp'}
    state = fixture.state()
    assert not state['complete'] and state['coverage_from'] is None
    assert state['cursor_timestamp'] is None and state['initial_max_id'] is None
    assert state['status'] == 'unsupported' and state['last_error'] == 'nonfinite_timestamp'
    reader = fixture.connect()
    with reader.cursor() as cursor:
        assert choose_dashboard_source(cursor, NOW - timedelta(hours=1), None)[0] == 'logs'
    reader.rollback()
    fixture.execute('UPDATE logs SET timestamp=%s WHERE id=%s',
                    [NOW - timedelta(minutes=5), ident])
    fixture.finish(batch_size=1)
    assert fixture.state()['status'] == 'ready'
    assert fixture.state()['last_error'] is None
    fixture.assert_matches_raw()


def test_positive_infinity_appearing_after_initialization_cannot_publish_a_cursor(
        dashboard_store_db):
    fixture = dashboard_store_db
    ident = fixture.add()
    fixture.install()
    fixture.backfill(batch_size=1)
    fixture.execute("UPDATE logs SET timestamp='infinity'::timestamptz WHERE id=%s", [ident])
    result = fixture.backfill(batch_size=1)
    assert result['status'] == 'unsupported'
    state = fixture.state()
    assert state['cursor_timestamp'] is None and state['coverage_from'] is None
    assert not state['complete']
    fixture.execute('UPDATE logs SET timestamp=%s WHERE id=%s', [NOW, ident])
    fixture.finish(batch_size=1)
    fixture.assert_matches_raw()


def test_index_name_collision_is_not_dropped_during_optional_repair(dashboard_store_db):
    fixture = dashboard_store_db
    fixture.install()
    fixture.add()
    fixture.finish()
    fixture.execute('DROP INDEX idx_dashboard_events_time')
    fixture.execute('CREATE TABLE unrelated_analytics(value integer)')
    fixture.execute('CREATE INDEX idx_dashboard_events_time ON unrelated_analytics(value)')
    assert store.ensure_dashboard_store(fixture.params) is False
    assert not fixture.state()['healthy']
    assert fixture.execute("SELECT indrelid='unrelated_analytics'::regclass FROM pg_index WHERE indexrelid='idx_dashboard_events_time'::regclass")[0][0]
    fixture.add(raw_log='Raw ingestion continues after an index-name collision')
    assert fixture.execute('SELECT count(*) FROM logs')[0][0] == 2


def test_malformed_batch_savepoint_rollback_keeps_exact_projection(dashboard_store_db):
    fixture = dashboard_store_db
    fixture.install()
    valid = dict(timestamp=NOW, log_type='system', raw_log='Valid event', ingest_id=str(uuid4()))
    invalid = dict(timestamp=NOW, log_type='system', raw_log='Invalid NUL\x00event', ingest_id=str(uuid4()))
    result = fixture.database.insert_logs_batch([valid, invalid, dict(valid)])
    assert result.inserted == 1
    assert result.duplicates == 1
    assert result.dropped == 1
    fixture.assert_matches_raw()


def test_later_insert_page_failure_rolls_back_earlier_projection_page(dashboard_store_db):
    fixture = dashboard_store_db
    fixture.install()
    events = [dict(timestamp=NOW, log_type='system', raw_log='Synthetic paged event',
                   ingest_id=str(uuid4())) for _ in range(1002)]
    # The production insertion helper pages at 1000. The first page's AFTER
    # trigger runs before this later page fails its raw NOT NULL constraint.
    events[1000]['timestamp'] = None
    result = fixture.database.insert_logs_batch(events)
    assert result.inserted == 1001 and result.dropped == 1
    assert result.duplicates == 0 and not result.retryable
    fixture.assert_matches_raw()


@pytest.mark.parametrize('source,signature,message,expected', [
    ('unifi_ips', None, 'Synthetic parsed security', (True, False)),
    ('ips', None, 'Synthetic legacy security', (True, False)),
    (None, '990001', 'Synthetic signature-only security', (True, False)),
    (None, None, 'CEF:0|Example|Gateway|1|Threat example|5|', (False, True)),
    ('system', None, 'CEF:0|Example|Gateway|1|ordinary|5|UNIFIipsSignature=example', (False, True)),
    (None, None, 'CEF:0|Example|Gateway|1|ordinary|5|unifipolicytype=ids/ips', (False, True)),
    ('unifi_ips', None, 'CEF:0|Example|Gateway|1|Threat example|5|', (True, False)),
    (None, None, 'Ordinary non-security message', (False, False)),
])
def test_security_classification_survives_raw_message_omission(
        dashboard_store_db, source, signature, message, expected):
    fixture = dashboard_store_db
    fixture.install()
    ident = fixture.add(event_source=source, ips_signature_id=signature, raw_log=message)
    assert fixture.execute('SELECT security_ips,security_cef FROM dashboard_events WHERE id=%s', [ident])[0] == expected
    columns = fixture.execute("SELECT attname FROM pg_attribute WHERE attrelid='dashboard_events'::regclass AND attnum>0 AND NOT attisdropped")
    assert 'raw_log' not in {row[0] for row in columns}
    fixture.assert_matches_raw()


def test_projected_exclusions_match_raw_null_and_security_semantics(dashboard_store_db):
    fixture = dashboard_store_db
    fixture.install()
    fixture.add(service_name='Literal_%_service', threat_score=12)
    fixture.add(log_type='system', direction=None, rule_action=None, src_ip=None,
                dst_ip=None, remote_ip=None, src_port=None, dst_port=None,
                protocol=None, service_name=None, rule_name=None, hostname=None,
                geo_country=None, asn_name=None, interface_in=None, interface_out=None)
    fixture.add(src_ip='2001:db8::10', dst_ip='2001:db8:1::20',
                remote_ip='2001:db8:1::20', src_port=53000, dst_port=53,
                protocol='UDP', direction='inbound', rule_action='block',
                service_name='Different service', threat_score=90)
    protected = {
        fixture.add(event_source='unifi_ips', ips_severity=5, raw_log='Parsed security'),
        fixture.add(raw_log='CEF:0|Example|Example|1|1|Threat synthetic|7|'),
        fixture.add(ips_signature_id='990001', raw_log='Signature-only security'),
    }
    fixture.add(raw_log='CEF:0|Example|Example|1|2|Ordinary event|1|')
    fixture.finish()
    examples = {
        'src_ip': '192.0.2.0/24', 'dst_ip': '198.51.100.20', 'ip': '2001:db8::/32',
        'remote_ip': '198.51.100.20', 'src_port': '40000', 'dst_port': '53,443',
        'port': '40000', 'protocol': 'TCP', 'log_type': 'firewall',
        'direction': 'outbound', 'rule_action': 'allow', 'country': 'ZZ',
        'service': 'Literal_%_service', 'interface': 'example-in',
        'interface_in': 'example-in', 'interface_out': 'example-out',
        'event_source': 'unifi_ips', 'source': 'syslog', 'ips_risk': 'high',
        'ips_signature_id': '990001', 'security_event': 'ips,unparsed_cef',
        'rule_name_exact': 'Example rule', 'hostname': 'gateway',
        'hostname_exact': 'example-gateway', 'asn': 'Example',
        'threat_score': '50-100', 'ips_severity': '3-8',
    }
    cutoff = NOW - timedelta(hours=1)
    for field, value in examples.items():
        for operator in ('include', 'exclude', 'present', 'missing'):
            groups = [{'conditions': [{'field': field, 'operator': operator, 'value': value}]}]
            raw_where, raw_params = append_exclusions('timestamp >= %s', [cutoff], groups)
            derived_where, derived_params = projection_scope(cutoff, groups)
            raw = fixture.execute('SELECT id FROM logs WHERE ' + raw_where + ' ORDER BY id', raw_params)
            derived = fixture.execute('SELECT id FROM dashboard_events WHERE ' + derived_where
                                      + ' ORDER BY id', derived_params)
            assert derived == raw, (field, operator)
            assert protected <= {row[0] for row in derived}, (field, operator)
    broad = [{'conditions': [{'field': 'log_type', 'operator': 'present'}]}]
    where, params = projection_scope(cutoff, broad)
    assert {row[0] for row in fixture.execute('SELECT id FROM dashboard_events WHERE ' + where,
                                             params)} == protected


def test_updates_refresh_metadata_timestamp_identity_and_security(dashboard_store_db):
    fixture = dashboard_store_db
    fixture.install()
    ident = fixture.add(timestamp=NOW + timedelta(hours=5), src_ip='192.0.2.129/24')
    fixture.execute('''UPDATE logs SET timestamp=%s,log_type='dns',direction=NULL,
        src_ip='2001:db8::2/64',dst_ip='198.51.100.8/28',remote_ip='198.51.100.8/28',
        geo_country='XY',geo_city='Changed city',geo_lat=12.125,geo_lon=-14.5,
        asn_name='Changed ASN',threat_score=99,threat_categories=ARRAY['example-category'],
        rdns='changed.example.test',service_name='Changed service',dns_query='changed.example.test',
        rule_name='Changed rule',rule_desc='Changed description',rule_action='block',
        hostname='changed-gateway',src_device_name='Changed source',dst_device_name='Changed destination',
        interface_in='changed-in',interface_out='changed-out',event_source=NULL,
        ips_signature_id=NULL,raw_log='CEF:0|Example|Gateway|1|Threat example|5|'
        WHERE id=%s''', [NOW - timedelta(days=5), ident])
    fixture.assert_matches_raw()
    fixture.execute("UPDATE logs SET timestamp=%s,event_source='unifi_ips',raw_log='Parsed now' WHERE id=%s",
                    [NOW + timedelta(days=2), ident])
    fixture.assert_matches_raw()
    fixture.execute('UPDATE logs SET id=%s WHERE id=%s', [ident + 1000, ident])
    fixture.assert_matches_raw()


def test_delete_retention_style_purge_and_truncate_are_atomic(dashboard_store_db):
    fixture = dashboard_store_db
    fixture.install()
    for index in range(6):
        fixture.add(timestamp=NOW - timedelta(days=index), log_type='dns' if index % 2 else 'firewall')
    fixture.execute("DELETE FROM logs WHERE id IN (SELECT id FROM logs WHERE log_type='dns' ORDER BY id LIMIT 2)")
    fixture.assert_matches_raw()
    connection = fixture.connect()
    with connection.cursor() as cursor:
        cursor.execute('DELETE FROM logs WHERE timestamp < %s', [NOW - timedelta(days=2)])
    connection.rollback()
    fixture.assert_matches_raw()
    before_epoch = fixture.state()['epoch']
    fixture.execute('TRUNCATE logs RESTART IDENTITY')
    assert fixture.execute('SELECT count(*) FROM dashboard_events')[0][0] == 0
    state = fixture.state()
    assert state['epoch'] > before_epoch
    assert state['coverage_from'] is None and not state['complete']
    assert state['initial_max_id'] is None
    fixture.add(timestamp=NOW + timedelta(days=1))
    fixture.finish()
    fixture.assert_matches_raw()


def test_truncate_rollback_restores_rows_and_coverage_epoch(dashboard_store_db):
    fixture = dashboard_store_db
    fixture.install()
    fixture.add()
    fixture.finish()
    before = fixture.state()
    connection = fixture.connect()
    with connection.cursor() as cursor:
        cursor.execute('TRUNCATE logs RESTART IDENTITY')
        assert store.snapshot_state(cursor)['epoch'] > before['epoch']
        cursor.execute('SELECT count(*) FROM dashboard_events')
        assert cursor.fetchone()[0] == 0
    connection.rollback()
    after = fixture.state()
    assert after['epoch'] == before['epoch']
    assert after['complete'] == before['complete']
    assert after['coverage_from'] == before['coverage_from']
    fixture.assert_matches_raw()


def test_empty_store_can_become_ready_and_then_project_new_late_events(dashboard_store_db):
    fixture = dashboard_store_db
    fixture.install()
    fixture.finish()
    assert fixture.state()['complete']
    fixture.add(timestamp=NOW - timedelta(days=30), raw_log='New historical event')
    fixture.add(timestamp=NOW + timedelta(days=30), raw_log='New future event')
    fixture.assert_matches_raw()


def test_backfill_handles_id_gaps_equal_timestamps_late_and_future_rows(dashboard_store_db):
    fixture = dashboard_store_db
    stamps = [NOW - timedelta(hours=4), NOW - timedelta(hours=2),
              NOW - timedelta(minutes=3), NOW - timedelta(minutes=3),
              NOW + timedelta(days=1), NOW - timedelta(hours=3)]
    identifiers = [fixture.add(timestamp=stamp) for stamp in stamps]
    fixture.execute('DELETE FROM logs WHERE id=%s', [identifiers[1]])
    fixture.install()
    fixture.backfill(batch_size=1)
    # New, backdated rows are maintained immediately even if the historical
    # scan has not reached that band or their IDs exceed its initial bound.
    fixture.add(timestamp=NOW - timedelta(days=10), raw_log='Late arrival')
    fixture.finish(batch_size=1)
    fixture.assert_matches_raw()
    assert fixture.state()['complete']


def test_backfill_resumes_on_a_new_connection_from_persisted_cursor(dashboard_store_db):
    fixture = dashboard_store_db
    for index in range(5):
        fixture.add(timestamp=NOW - timedelta(minutes=index + 1))
    fixture.add(timestamp=NOW - timedelta(hours=2))
    fixture.install()
    first = fixture.connect()
    fixture.backfill(batch_size=1, connection=first)
    fixture.backfill(batch_size=1, connection=first)
    state = fixture.state()
    assert not state['complete']
    assert state['initial_max_id'] is not None
    assert state['cursor_id'] is not None
    first.close()
    replacement = fixture.connect()
    fixture.backfill(batch_size=1, connection=replacement)
    assert fixture.state()['initial_max_id'] == state['initial_max_id']
    fixture.finish(batch_size=1)
    fixture.assert_matches_raw()


def _wait_for_lock(fixture, backend_pid, *, advisory=False, timeout=5):
    connection = fixture.connect()
    connection.autocommit = True
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with connection.cursor() as cursor:
            cursor.execute('SELECT wait_event_type,wait_event FROM pg_stat_activity WHERE pid=%s',
                           [backend_pid])
            row = cursor.fetchone()
        if row and row[0] == 'Lock' and (not advisory or row[1] == 'advisory'):
            return row
        time.sleep(0.01)
    pytest.fail('synthetic database operation did not reach the expected lock')


def test_timestamp_move_during_raw_lock_wait_cannot_skip_other_events(dashboard_store_db):
    fixture = dashboard_store_db
    hour = NOW.replace(minute=0, second=0, microsecond=0)
    identifiers = [fixture.add(timestamp=hour + timedelta(minutes=minute))
                   for minute in (1, 2, 3)]
    fixture.install()
    fixture.backfill(batch_size=1)  # Initialize the horizon without copying.
    before = fixture.state()
    updating, scanning = fixture.connect(), fixture.connect()
    with updating.cursor() as cursor:
        cursor.execute('UPDATE logs SET timestamp=%s WHERE id=%s',
                       [hour + timedelta(minutes=10), identifiers[0]])
    with ThreadPoolExecutor(max_workers=1) as executor:
        batch = executor.submit(fixture.backfill, batch_size=1, connection=scanning)
        try:
            # The first candidate was ordered at 12:01 in the scan snapshot.
            # Moving it while FOR SHARE waits must abort that whole snapshot,
            # rather than publish a 12:10 cursor and miss 12:02 and 12:03.
            _wait_for_lock(fixture, scanning.get_backend_pid())
            updating.commit()
        finally:
            updating.rollback()
        assert batch.result(timeout=5) == {'status': 'retry', 'rows': 0}
    after = fixture.state()
    for name in ('cursor_timestamp', 'cursor_id', 'coverage_from', 'rows_scanned'):
        assert after[name] == before[name]
    assert not after['complete']
    for expected_id in identifiers[1:]:
        fixture.backfill(batch_size=1)
        assert fixture.execute('SELECT id FROM dashboard_events WHERE id=%s',
                               [expected_id]) == [(expected_id,)]
        assert fixture.state()['coverage_from'] is None
    fixture.finish(batch_size=1)
    fixture.assert_matches_raw()
    assert fixture.state()['complete']


@pytest.mark.parametrize('mutation', ['update', 'delete', 'truncate'])
def test_backfill_row_lock_serializes_concurrent_mutation_without_resurrection(
        dashboard_store_db, mutation):
    fixture = dashboard_store_db
    ident = fixture.add(timestamp=NOW - timedelta(minutes=5))
    fixture.install()
    fixture.backfill(batch_size=1)
    lock_key = int(uuid4().hex[:7], 16)
    fixture.execute(f'''CREATE FUNCTION synthetic_projection_gate() RETURNS trigger
        LANGUAGE plpgsql AS $$ BEGIN
            PERFORM pg_advisory_xact_lock(74103,{lock_key});
            RETURN NEW;
        END $$''')
    fixture.execute('''CREATE TRIGGER synthetic_projection_gate BEFORE INSERT ON dashboard_events
        FOR EACH ROW EXECUTE FUNCTION synthetic_projection_gate()''')
    gate = fixture.connect()
    with gate.cursor() as cursor:
        cursor.execute('SELECT pg_advisory_lock(74103,%s)', [lock_key])
    gate.commit()
    scanning = fixture.connect()
    writing = fixture.connect()
    writer_started = threading.Event()

    def mutate():
        writer_started.set()
        with writing.cursor() as cursor:
            if mutation == 'update':
                cursor.execute("UPDATE logs SET service_name='Changed after scan',threat_score=91 WHERE id=%s", [ident])
            elif mutation == 'delete':
                cursor.execute('DELETE FROM logs WHERE id=%s', [ident])
            else:
                cursor.execute('TRUNCATE logs RESTART IDENTITY')
        writing.commit()

    with ThreadPoolExecutor(max_workers=2) as executor:
        worker = executor.submit(fixture.backfill, batch_size=1, connection=scanning)
        try:
            _wait_for_lock(fixture, scanning.get_backend_pid(), advisory=True)
            writer = executor.submit(mutate)
            assert writer_started.wait(2)
            event = _wait_for_lock(fixture, writing.get_backend_pid())
            # It must wait on the raw row, not merely on the synthetic
            # projection trigger: otherwise an old scan could resurrect it.
            assert event[1] in (('relation',) if mutation == 'truncate' else ('transactionid', 'tuple'))
            assert not writer.done()
        finally:
            with gate.cursor() as cursor:
                cursor.execute('SELECT pg_advisory_unlock(74103,%s)', [lock_key])
            gate.commit()
        worker.result(timeout=10)
        writer.result(timeout=10)
    fixture.finish()
    fixture.assert_matches_raw()


def test_snapshot_does_not_see_coverage_from_a_later_backfill_commit(dashboard_store_db):
    fixture = dashboard_store_db
    fixture.add(timestamp=NOW - timedelta(minutes=5))
    fixture.install()
    reader = fixture.connect()
    with reader.cursor() as cursor:
        cursor.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
        before = store.snapshot_state(cursor)
        cursor.execute('SELECT count(*) FROM dashboard_events')
        assert cursor.fetchone()[0] == 0
    fixture.finish()
    assert fixture.state()['complete']
    with reader.cursor() as cursor:
        assert store.snapshot_state(cursor) == before
        cursor.execute('SELECT count(*) FROM dashboard_events')
        assert cursor.fetchone()[0] == 0
    reader.commit()
    with reader.cursor() as cursor:
        assert store.snapshot_state(cursor)['complete']
        cursor.execute('SELECT count(*) FROM dashboard_events')
        assert cursor.fetchone()[0] == 1
    reader.commit()


def test_old_backfill_state_cannot_publish_across_truncate_epoch(dashboard_store_db, monkeypatch):
    fixture = dashboard_store_db
    fixture.add(timestamp=NOW - timedelta(minutes=5), raw_log='Before epoch reset')
    fixture.install()
    fixture.backfill(batch_size=1)
    scanning = fixture.connect()
    captured, release = threading.Event(), threading.Event()
    snapshot = store.snapshot_state

    def pause_after_state_read(cursor):
        state = snapshot(cursor)
        if cursor.connection is scanning:
            captured.set()
            assert release.wait(5)
        return state

    monkeypatch.setattr(store, 'snapshot_state', pause_after_state_read)
    with ThreadPoolExecutor(max_workers=1) as executor:
        worker = executor.submit(fixture.backfill, batch_size=1, connection=scanning)
        try:
            assert captured.wait(3)
            fixture.execute('TRUNCATE logs RESTART IDENTITY')
            fixture.add(timestamp=NOW - timedelta(minutes=5), raw_log='After epoch reset')
            reset = fixture.state()
        finally:
            release.set()
        result = worker.result(timeout=10)
    assert result['status'] == 'retry'
    after = fixture.state()
    assert after['epoch'] == reset['epoch']
    assert after['initial_max_id'] is None
    assert after['coverage_from'] is None and not after['complete']
    fixture.finish()
    fixture.assert_matches_raw()


def test_snapshot_pairs_projection_rows_with_committed_live_updates(dashboard_store_db):
    fixture = dashboard_store_db
    fixture.install()
    ident = fixture.add(threat_score=10)
    reader = fixture.connect()
    with reader.cursor() as cursor:
        cursor.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
        cursor.execute('SELECT threat_score FROM dashboard_events WHERE id=%s', [ident])
        assert cursor.fetchone()[0] == 10
    fixture.execute('UPDATE logs SET threat_score=99 WHERE id=%s', [ident])
    with reader.cursor() as cursor:
        cursor.execute('SELECT threat_score FROM logs WHERE id=%s', [ident])
        assert cursor.fetchone()[0] == 10
        cursor.execute('SELECT threat_score FROM dashboard_events WHERE id=%s', [ident])
        assert cursor.fetchone()[0] == 10
    reader.commit()
    fixture.assert_matches_raw()


def test_backfill_does_not_block_new_backdated_ingestion(dashboard_store_db):
    fixture = dashboard_store_db
    old_id = fixture.add(timestamp=NOW - timedelta(minutes=5))
    fixture.install()
    fixture.backfill(batch_size=1)
    lock_key = int(uuid4().hex[:7], 16)
    fixture.execute(f'''CREATE FUNCTION synthetic_old_projection_gate() RETURNS trigger
        LANGUAGE plpgsql AS $$ BEGIN
            IF NEW.id={old_id} THEN
                PERFORM pg_advisory_xact_lock(74104,{lock_key});
            END IF;
            RETURN NEW;
        END $$''')
    fixture.execute('''CREATE TRIGGER synthetic_old_projection_gate BEFORE INSERT ON dashboard_events
        FOR EACH ROW EXECUTE FUNCTION synthetic_old_projection_gate()''')
    gate = fixture.connect()
    with gate.cursor() as cursor:
        cursor.execute('SELECT pg_advisory_lock(74104,%s)', [lock_key])
    gate.commit()
    scanning = fixture.connect()
    with ThreadPoolExecutor(max_workers=1) as executor:
        worker = executor.submit(fixture.backfill, batch_size=1, connection=scanning)
        try:
            _wait_for_lock(fixture, scanning.get_backend_pid(), advisory=True)
            new_id = fixture.add(timestamp=NOW - timedelta(days=3), raw_log='Live backdated ingest')
            assert new_id > old_id
            assert fixture.execute('SELECT count(*) FROM dashboard_events WHERE id=%s', [new_id])[0][0] == 1
        finally:
            with gate.cursor() as cursor:
                cursor.execute('SELECT pg_advisory_unlock(74104,%s)', [lock_key])
            gate.commit()
        worker.result(timeout=10)
    fixture.finish()
    fixture.assert_matches_raw()


def test_coverage_advances_only_after_the_entire_band_is_backfilled(dashboard_store_db):
    fixture = dashboard_store_db
    for index in range(5):
        fixture.add(timestamp=NOW - timedelta(minutes=index + 1))
    fixture.add(timestamp=NOW - timedelta(hours=3))
    fixture.install()
    fixture.backfill(batch_size=1)
    fixture.backfill(batch_size=1)
    state = fixture.state()
    assert not state['complete']
    assert state['coverage_from'] is None
    fixture.finish(batch_size=1)
    fixture.assert_matches_raw()
    assert fixture.state()['complete']


class _FastStop(threading.Event):
    """Advance scheduling waits without changing the actual database work."""

    def __init__(self):
        super().__init__()
        self.waited = []

    def wait(self, timeout=None):
        self.waited.append(timeout)
        return super().wait(min(timeout, 0.01) if timeout is not None else timeout)


def _wait_until(predicate, *, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.01)
    pytest.fail('bounded synthetic worker did not reach its expected state')


def _stop_worker(thread, stop, connections):
    stop.set()
    thread.join(timeout=3)
    if thread.is_alive():
        for connection in connections:
            if connection is not None and not connection.closed:
                try:
                    connection.cancel()
                except psycopg2.Error:
                    pass  # The worker may have closed it concurrently.
        thread.join(timeout=3)
    assert not thread.is_alive()


def test_paused_historical_copy_installs_capture_without_advancing_history(
        dashboard_store_db, monkeypatch):
    fixture = dashboard_store_db
    changed = fixture.add()
    fixture.add(raw_log='History left for a later copy')
    monkeypatch.setenv('DASHBOARD_ANALYTICS_BACKFILL_ENABLED', 'false')
    stop, connections, copied = _FastStop(), [], []
    original = store.backfill_step

    def record_copy(*args, **kwargs):
        copied.append(True)
        return original(*args, **kwargs)

    monkeypatch.setattr(store, 'backfill_step', record_copy)
    worker = threading.Thread(target=store.run_dashboard_store_worker,
                              args=(fixture.params, stop),
                              kwargs={'connection_callback': connections.append})
    worker.start()
    try:
        _wait_until(lambda: stop.waited.count(2) >= 2)
        before = fixture.state()
        assert before['healthy'] and before['triggers_enabled']
        assert before['status'] == 'pending' and not before['complete']
        assert before['initial_max_id'] is None and before['cursor_id'] is None
        assert fixture.execute('SELECT count(*) FROM dashboard_events')[0][0] == 0
        assert not fixture.execute('SELECT pg_try_advisory_lock(%s,%s)',
                                   list(store.WORKER_LOCK))[0][0]
        live = fixture.add(timestamp=NOW - timedelta(days=30), raw_log='Live backdated capture')
        assert fixture.execute('SELECT id FROM dashboard_events') == [(live,)]
        fixture.execute('UPDATE logs SET threat_score=81 WHERE id=%s', [changed])
        assert fixture.execute('SELECT threat_score FROM dashboard_events WHERE id=%s',
                               [changed]) == [(81,)]
        fixture.execute('DELETE FROM logs WHERE id=%s', [live])
        assert fixture.execute('SELECT id FROM dashboard_events') == [(changed,)]
        _wait_until(lambda: stop.waited.count(2) >= 3)
        assert fixture.state() == before
        assert not copied
    finally:
        _stop_worker(worker, stop, connections)
    assert connections[-1] is None
    assert all(connection is None or connection.closed for connection in connections)


def test_paused_historical_copy_keeps_existing_covered_reads_on_projection(
        dashboard_store_db, monkeypatch):
    fixture = dashboard_store_db
    current = fixture.add(timestamp=NOW - timedelta(minutes=5))
    fixture.add(timestamp=NOW - timedelta(hours=4))
    fixture.install()
    fixture.backfill()
    assert fixture.backfill()['status'] == 'band_complete'
    before = fixture.state()
    assert before['coverage_from'] is not None and not before['complete']
    monkeypatch.setenv('DASHBOARD_ANALYTICS_BACKFILL_ENABLED', 'false')
    stop, connections = _FastStop(), []
    worker = threading.Thread(target=store.run_dashboard_store_worker,
                              args=(fixture.params, stop),
                              kwargs={'connection_callback': connections.append})
    worker.start()
    try:
        _wait_until(lambda: stop.waited.count(2) >= 2)
        assert fixture.state() == before
        reader = fixture.connect()
        with reader.cursor() as cursor:
            relation, (where, params) = choose_dashboard_source(cursor, before['coverage_from'], None)
            assert relation == 'dashboard_events'
            cursor.execute(f'SELECT id FROM {relation} WHERE {where}', params)
            assert cursor.fetchall() == [(current,)]
        reader.rollback()
        with reader.cursor() as cursor:
            relation, _ = choose_dashboard_source(
                cursor, before['coverage_from'] - timedelta(hours=1), None)
            assert relation == 'logs'
        reader.rollback()
        assert fixture.state() == before
    finally:
        _stop_worker(worker, stop, connections)


def test_historical_copy_resumes_the_saved_cursor_without_rebuilding(
        dashboard_store_db, monkeypatch):
    fixture = dashboard_store_db
    anchor = datetime.now(timezone.utc)
    for minute in (1, 2, 3, 4):
        fixture.add(timestamp=anchor - timedelta(minutes=minute))
    fixture.install()
    fixture.backfill(batch_size=1)
    fixture.backfill(batch_size=1)
    before = fixture.state()
    facts_before = fixture.execute('SELECT id FROM dashboard_events ORDER BY id')
    assert before['cursor_id'] is not None and not before['complete']
    monkeypatch.setenv('DASHBOARD_ANALYTICS_BACKFILL_ENABLED', 'false')
    stop, connections = _FastStop(), []
    worker = threading.Thread(target=store.run_dashboard_store_worker,
                              args=(fixture.params, stop),
                              kwargs={'connection_callback': connections.append})
    worker.start()
    try:
        _wait_until(lambda: stop.waited.count(2) >= 2)
        assert fixture.state() == before
        assert fixture.execute('SELECT id FROM dashboard_events ORDER BY id') == facts_before
    finally:
        _stop_worker(worker, stop, connections)
    # Model a container restart with the independent copy setting restored.
    monkeypatch.setenv('DASHBOARD_ANALYTICS_BACKFILL_ENABLED', 'true')
    original, first_state = store.backfill_step, []
    observer = fixture.connect()

    def record_first_state(connection, *args, **kwargs):
        if not first_state:
            first_state.append(fixture.state(connection=observer))
        return original(connection, *args, **kwargs)

    monkeypatch.setattr(store, 'backfill_step', record_first_state)
    stop, connections = _FastStop(), []
    worker = threading.Thread(target=store.run_dashboard_store_worker,
                              args=(fixture.params, stop),
                              kwargs={'connection_callback': connections.append})
    worker.start()
    try:
        _wait_until(lambda: bool(fixture.state()['complete']))
        assert first_state == [before]
        assert fixture.state()['epoch'] == before['epoch']
        fixture.assert_matches_raw()
    finally:
        _stop_worker(worker, stop, connections)


def test_overall_disable_still_disables_capture_when_historical_copy_is_paused(
        dashboard_store_db, monkeypatch):
    fixture = dashboard_store_db
    fixture.install()
    fixture.add()
    fixture.finish()
    before = fixture.state()
    monkeypatch.setenv('DASHBOARD_ANALYTICS_ENABLED', 'false')
    monkeypatch.setenv('DASHBOARD_ANALYTICS_BACKFILL_ENABLED', 'false')
    stop, connections = _FastStop(), []
    worker = threading.Thread(target=store.run_dashboard_store_worker,
                              args=(fixture.params, stop),
                              kwargs={'connection_callback': connections.append,
                                      'pause_callback': lambda: True})
    worker.start()
    try:
        worker.join(timeout=5)
        assert not worker.is_alive()
        state = fixture.state()
        assert state['status'] == 'disabled' and not state['triggers_enabled']
        assert state['epoch'] > before['epoch']
        assert state['coverage_from'] is None and not state['complete']
        fixture.add(raw_log='Raw capture remains available after overall disable')
        assert fixture.execute('SELECT count(*) FROM logs')[0][0] == 2
        assert fixture.execute('SELECT count(*) FROM dashboard_events')[0][0] == 1
    finally:
        _stop_worker(worker, stop, connections)


def test_stopping_paused_historical_copy_interrupts_wait_and_closes_owner(
        dashboard_store_db, monkeypatch):
    fixture = dashboard_store_db
    fixture.add()
    monkeypatch.setenv('DASHBOARD_ANALYTICS_BACKFILL_ENABLED', 'false')

    class ObservedStop(threading.Event):
        waiting = threading.Event()

        def wait(self, timeout=None):
            if timeout == 2:
                self.waiting.set()
            return super().wait(timeout)

    stop, connections = ObservedStop(), []
    worker = threading.Thread(target=store.run_dashboard_store_worker,
                              args=(fixture.params, stop),
                              kwargs={'connection_callback': connections.append})
    worker.start()
    try:
        assert stop.waiting.wait(timeout=5)
        assert not fixture.execute('SELECT pg_try_advisory_lock(%s,%s)',
                                   list(store.WORKER_LOCK))[0][0]
        stop.set()
        worker.join(timeout=1)
        assert not worker.is_alive()
    finally:
        _stop_worker(worker, stop, connections)
    assert connections[-1] is None
    assert all(connection is None or connection.closed for connection in connections)
    assert fixture.execute('SELECT pg_try_advisory_lock(%s,%s)', list(store.WORKER_LOCK))[0][0]


def test_worker_pauses_retries_setup_and_releases_its_connection(dashboard_store_db, monkeypatch):
    fixture = dashboard_store_db
    fixture.add(timestamp=datetime.now(timezone.utc) - timedelta(minutes=5))
    stop, pause = _FastStop(), threading.Event()
    pause.set()
    connections, attempts = [], []
    ensure = store.ensure_dashboard_store

    def initially_unavailable(params, **kwargs):
        attempts.append(True)
        return False if len(attempts) == 1 else ensure(params, **kwargs)

    monkeypatch.setattr(store, 'ensure_dashboard_store', initially_unavailable)
    worker = threading.Thread(target=store.run_dashboard_store_worker,
                              args=(fixture.params, stop),
                              kwargs={'connection_callback': connections.append,
                                      'pause_callback': pause.is_set})
    worker.start()
    try:
        _wait_until(lambda: bool(stop.waited))
        assert not attempts
        assert fixture.state() is None
        pause.clear()
        _wait_until(lambda: bool((fixture.state() or {}).get('complete')))
        assert len(attempts) >= 2
        assert 30 in stop.waited  # The failed optional setup was retried.
        fixture.assert_matches_raw()
    finally:
        _stop_worker(worker, stop, connections)
    assert connections[-1] is None
    assert all(connection is None or connection.closed for connection in connections)
    assert fixture.execute('SELECT pg_try_advisory_lock(%s,%s)', list(store.WORKER_LOCK))[0][0]


def test_disabled_worker_retries_a_failed_disable_before_exiting(dashboard_store_db, monkeypatch):
    fixture = dashboard_store_db
    fixture.install()
    fixture.add()
    fixture.finish()
    monkeypatch.setenv('DASHBOARD_ANALYTICS_ENABLED', 'false')
    stop, connections, attempts = _FastStop(), [], []
    ensure = store.ensure_dashboard_store

    def initially_unavailable(params, **kwargs):
        attempts.append(True)
        return False if len(attempts) == 1 else ensure(params, **kwargs)

    monkeypatch.setattr(store, 'ensure_dashboard_store', initially_unavailable)
    worker = threading.Thread(target=store.run_dashboard_store_worker,
                              args=(fixture.params, stop),
                              kwargs={'connection_callback': connections.append})
    worker.start()
    try:
        worker.join(timeout=5)
        assert not worker.is_alive()
        assert len(attempts) == 2
        assert 2 in stop.waited
        state = fixture.state()
        assert state['status'] == 'disabled'
        assert not state['triggers_enabled'] and not state['complete']
        fixture.add(raw_log='Inserted after the worker disabled its triggers')
        assert fixture.execute('SELECT count(*) FROM logs')[0][0] == 2
        assert fixture.execute('SELECT count(*) FROM dashboard_events')[0][0] == 1
    finally:
        _stop_worker(worker, stop, connections)
    assert connections[-1] is None
    assert all(connection is None or connection.closed for connection in connections)


@pytest.mark.parametrize('phase', ['schema', 'index_repair'])
def test_setup_ddl_connection_is_registered_and_cancellable(dashboard_store_db, phase):
    fixture = dashboard_store_db
    ident = fixture.add()
    if phase == 'index_repair':
        fixture.install()
        fixture.finish()
        fixture.execute('DROP INDEX idx_dashboard_events_time')
    blocking = fixture.connect()
    with blocking.cursor() as cursor:
        if phase == 'schema':
            cursor.execute('LOCK TABLE logs IN ACCESS EXCLUSIVE MODE')
        else:
            # This uncommitted projection write lets the install inspection
            # finish but blocks CREATE INDEX CONCURRENTLY on its writer wait.
            cursor.execute('UPDATE dashboard_events SET service_name=service_name WHERE id=%s',
                           [ident])
    stop, connections = threading.Event(), []
    with ThreadPoolExecutor(max_workers=1) as executor:
        setup = executor.submit(store.ensure_dashboard_store, fixture.params,
                                connection_callback=connections.append, stop_event=stop)
        try:
            _wait_until(lambda: any(connection is not None and not connection.closed
                                   for connection in connections))
            if phase == 'index_repair':
                _wait_until(lambda: len([connection for connection in connections
                                         if connection is not None]) >= 2)
            active = [connection for connection in connections
                      if connection is not None and not connection.closed][-1]
            _wait_for_lock(fixture, active.get_backend_pid())
            stop.set()
            active.cancel()
            assert setup.result(timeout=3) is False
        finally:
            stop.set()
            blocking.rollback()
    assert connections[-1] is None
    assert all(connection is None or connection.closed for connection in connections)
    fixture.add(raw_log='Raw ingestion after cancelled optional schema work')
    assert fixture.execute('SELECT count(*) FROM logs')[0][0] == 2
    if phase == 'schema':
        assert fixture.state() is None
    else:
        assert not fixture.state()['healthy']
        fixture.assert_matches_raw()


@pytest.mark.parametrize('operation', [store.ensure_dashboard_store, store._repair_time_index])
def test_stopped_setup_does_not_open_a_database_connection(dashboard_store_db, operation):
    stop, connections = threading.Event(), []
    stop.set()
    assert operation(dashboard_store_db.params, connection_callback=connections.append,
                     stop_event=stop) is False
    assert not connections


def test_projection_reader_prevents_repair_from_truncating_its_snapshot(
        dashboard_store_db, monkeypatch):
    fixture = dashboard_store_db
    for _ in range(3):
        fixture.add()
    fixture.install()
    fixture.finish()
    reader, connections = fixture.connect(), []
    with reader.cursor() as cursor:
        relation, (where, params) = choose_dashboard_source(
            cursor, NOW - timedelta(hours=1), None)
        assert relation == 'dashboard_events'
        monkeypatch.setenv('DASHBOARD_ANALYTICS_ENABLED', 'false')
        assert store.ensure_dashboard_store(fixture.params) is True
        monkeypatch.setenv('DASHBOARD_ANALYTICS_ENABLED', 'true')
        with ThreadPoolExecutor(max_workers=1) as executor:
            repair = executor.submit(store.ensure_dashboard_store, fixture.params,
                                     connection_callback=connections.append)
            try:
                _wait_until(lambda: any(connection is not None and not connection.closed
                                       for connection in connections))
                active = [connection for connection in connections
                          if connection is not None and not connection.closed][-1]
                _wait_for_lock(fixture, active.get_backend_pid())
                # Prove the repair is blocked at the derived TRUNCATE, not a
                # later trigger DDL statement. Raw ACCESS SHARE alone would
                # not protect this already-selected projection snapshot.
                pending = fixture.execute('''SELECT c.relname,l.mode FROM pg_locks l
                    JOIN pg_class c ON c.oid=l.relation
                    WHERE l.pid=%s AND NOT l.granted''', [active.get_backend_pid()])
                assert ('dashboard_events', 'AccessExclusiveLock') in pending
                assert repair.result(timeout=3) is False
                cursor.execute(f'SELECT count(*) FROM {relation} WHERE {where}', params)
                assert cursor.fetchone()[0] == 3
            finally:
                reader.rollback()
    assert all(connection is None or connection.closed for connection in connections)
    assert store.ensure_dashboard_store(fixture.params) is True
    assert not fixture.state()['complete']
    fixture.finish()
    fixture.assert_matches_raw()


def test_ready_worker_notices_truncate_and_rebuilds_without_restart(dashboard_store_db):
    fixture = dashboard_store_db
    fixture.add(timestamp=datetime.now(timezone.utc) - timedelta(minutes=5))
    stop, connections = _FastStop(), []
    worker = threading.Thread(target=store.run_dashboard_store_worker,
                              args=(fixture.params, stop),
                              kwargs={'connection_callback': connections.append})
    worker.start()
    try:
        _wait_until(lambda: bool((fixture.state() or {}).get('complete')))
        before = fixture.state()
        fixture.execute('TRUNCATE logs RESTART IDENTITY')
        fixture.add(timestamp=datetime.now(timezone.utc) - timedelta(minutes=5),
                    raw_log='New generation after ready-state truncate')
        _wait_until(lambda: bool((fixture.state() or {}).get('complete')))
        assert fixture.state()['epoch'] > before['epoch']
        fixture.assert_matches_raw()
    finally:
        _stop_worker(worker, stop, connections)
