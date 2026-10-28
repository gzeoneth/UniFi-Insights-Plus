"""Security classification and query plans on disposable PostgreSQL fixtures."""
import os

import pytest

from field_filters import compile_exclusions, compile_filters
from security_predicates import SECURITY_INDEXES


@pytest.fixture
def pg_security_rows():
    dsn = os.environ.get('TEST_POSTGRES_DSN')
    if not dsn:
        pytest.skip('set TEST_POSTGRES_DSN for disposable PostgreSQL checks')
    import psycopg2
    connection = psycopg2.connect(dsn)
    with connection.cursor() as cursor:
        cursor.execute('''CREATE TEMP TABLE logs (
            id bigint PRIMARY KEY, timestamp timestamptz NOT NULL,
            event_source text, ips_signature_id text, raw_log text,
            rule_name text)''')
        cursor.execute('''INSERT INTO logs
            SELECT i, '2026-01-02T00:00:00Z'::timestamptz,
                   NULL, NULL, 'Ordinary synthetic event', 'Routine traffic'
            FROM generate_series(100, 50100) i''')
        cursor.executemany('''INSERT INTO logs
            VALUES (%s, '2026-01-02T00:00:00Z', %s, %s, %s, 'Routine traffic')''', [
            (1, 'unifi_ips', None, None),
            (2, 'ips', None, None),
            (3, None, '900001', None),
            (4, 'other', '900002', 'CEF:0|Example|Threat Detected|'),
            (5, None, None, 'CEF:0|Example|Threat Detected|'),
            (6, 'system', None, 'CEF:0|Example|UNIFIipsSignature=Example'),
            (7, 'system', None, 'CEF:0|Example|unifipolicytype=ids/ips'),
            (8, None, None, 'CEF:0|Example|Ordinary status'),
            (9, None, None, None),
            (10, None, None, 'Threat Detected without CEF marker'),
        ])
        cursor.execute('CREATE INDEX idx_logs_timestamp ON logs(timestamp DESC)')
        cursor.execute('CREATE INDEX idx_old_ips ON logs(timestamp DESC) '
                       "WHERE event_source='unifi_ips'")
        for index in SECURITY_INDEXES:
            # Temporary-table indexes cannot be built concurrently. The
            # identical predicate/key is exercised; concurrency has separate
            # migration lifecycle tests.
            cursor.execute(index['sql'].replace(' CONCURRENTLY', ''))
        cursor.execute('ANALYZE logs')
    try:
        yield connection
    finally:
        connection.close()


def _query(connection, rules, *, explain=False):
    conditions, params = compile_filters(rules)
    sql = 'SELECT id FROM logs WHERE timestamp >= %s AND ' + ' AND '.join(conditions)
    sql += ' ORDER BY timestamp DESC, id DESC LIMIT 1001'
    if explain:
        sql = 'EXPLAIN (FORMAT JSON) ' + sql
    with connection.cursor() as cursor:
        cursor.execute(sql, ['2026-01-01T00:00:00Z', *params])
        return cursor.fetchall()


def _security(value, operator='include'):
    return [{'field': 'security_event', 'operator': operator, 'value': value}]


@pytest.mark.parametrize('value,expected,index_name', [
    ('ips', [4, 3, 2, 1], 'idx_logs_security_ips_time'),
    ('unparsed_cef', [7, 6, 5], 'idx_logs_security_cef_time'),
])
def test_rare_security_queries_use_complete_partial_indexes(pg_security_rows, value, expected, index_name):
    assert [row[0] for row in _query(pg_security_rows, _security(value))] == expected
    plan = _query(pg_security_rows, _security(value), explain=True)[0][0][0]['Plan']
    def index_names(node):
        return [node.get('Index Name')] + [name for child in node.get('Plans', []) for name in index_names(child)]
    assert index_name in index_names(plan)


def test_security_nulls_negation_and_exclusions_preserve_semantics(pg_security_rows):
    with pg_security_rows.cursor() as cursor:
        for operator, expected in [('present', list(range(1, 8))), ('missing', [8, 9, 10]),
                                   ('exclude', [5, 6, 7, 8, 9, 10])]:
            conditions, params = compile_filters(_security('ips', operator))
            cursor.execute('SELECT id FROM logs WHERE id < 100 AND ' +
                           ' AND '.join(conditions) + ' ORDER BY id', params)
            assert [row[0] for row in cursor.fetchall()] == expected
        conditions, params = compile_exclusions([{'conditions': [
            {'field': 'rule_name_exact', 'operator': 'include', 'value': 'Routine traffic'}]}])
        cursor.execute('SELECT id FROM logs WHERE ' + ' AND '.join(conditions) + ' ORDER BY id', params)
        assert [row[0] for row in cursor.fetchall()] == list(range(1, 8))


def test_updated_legacy_row_leaves_candidate_index(pg_security_rows):
    with pg_security_rows.cursor() as cursor:
        cursor.execute("UPDATE logs SET event_source='unifi_ips', ips_signature_id='900003' WHERE id=5")
    assert [row[0] for row in _query(pg_security_rows, _security('ips'))] == [5, 4, 3, 2, 1]
    assert [row[0] for row in _query(pg_security_rows, _security('unparsed_cef'))] == [7, 6]


def test_concurrent_upgrade_recovers_invalid_index_in_nondefault_schema():
    """A failed concurrent build is repaired without relying on public/search_path."""
    dsn = os.environ.get('TEST_POSTGRES_DSN')
    if not dsn:
        pytest.skip('set TEST_POSTGRES_DSN for disposable PostgreSQL checks')
    import uuid
    import psycopg2
    from psycopg2 import sql
    from psycopg2.extensions import parse_dsn
    from db import Database
    from security_predicates import PARSED_IPS_SQL
    schema = 'security_upgrade_' + uuid.uuid4().hex
    connection = psycopg2.connect(dsn)
    connection.autocommit = True
    try:
        with connection.cursor() as cursor:
            cursor.execute(sql.SQL('CREATE SCHEMA {}').format(sql.Identifier(schema)))
            cursor.execute(sql.SQL('SET search_path TO {}').format(sql.Identifier(schema)))
            cursor.execute('''CREATE TABLE logs (id bigint, timestamp timestamptz,
                event_source text, ips_signature_id text, raw_log text)''')
            # Deliberately duplicate keys to leave an unusable concurrent index.
            cursor.execute("INSERT INTO logs VALUES (1, '2026-01-01', 'unifi_ips', NULL, ''),"
                           "(1, '2026-01-01', 'unifi_ips', NULL, '')")
            with pytest.raises(psycopg2.errors.UniqueViolation):
                cursor.execute('CREATE UNIQUE INDEX CONCURRENTLY idx_logs_security_ips_time '
                               'ON logs(timestamp DESC,id DESC) WHERE ' + PARSED_IPS_SQL)
            cursor.execute("SELECT indisvalid FROM pg_index WHERE indexrelid='idx_logs_security_ips_time'::regclass")
            assert cursor.fetchone() == (False,)
        params = parse_dsn(dsn)
        params['options'] = params.get('options', '') + f' -c search_path={schema}'
        database = Database(conn_params=params)
        database._POST_BOOT_INDEXES = SECURITY_INDEXES
        database._POST_BOOT_DROPS = []
        database.ensure_post_boot_indexes()
        with connection.cursor() as cursor:
            cursor.execute("SELECT c.relname,i.indisvalid,i.indisunique FROM pg_index i "
                           "JOIN pg_class c ON c.oid=i.indexrelid WHERE i.indrelid='logs'::regclass")
            assert set(cursor.fetchall()) == {(index['name'], True, False) for index in SECURITY_INDEXES}
        database.ensure_post_boot_indexes()  # Valid indexes survive an idempotent rerun.
    finally:
        with connection.cursor() as cursor:
            cursor.execute(sql.SQL('DROP SCHEMA IF EXISTS {} CASCADE').format(sql.Identifier(schema)))
        connection.close()
