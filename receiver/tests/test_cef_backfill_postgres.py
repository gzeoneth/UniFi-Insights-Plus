"""Optional PostgreSQL verification of the explicit CEF repair path."""

import os
from datetime import datetime, timezone

import pytest

from cef_backfill import BACKFILL_COLUMNS, run_backfill


def test_cef_backfill_on_postgres_preserves_row_and_reputation():
    dsn = os.environ.get('TEST_POSTGRES_DSN')
    if not dsn:
        pytest.skip('set TEST_POSTGRES_DSN for disposable PostgreSQL integration tests')
    import psycopg2
    connection = psycopg2.connect(dsn)
    types = {'src_ip': 'INET', 'dst_ip': 'INET', 'src_port': 'INTEGER',
             'dst_port': 'INTEGER', 'ips_severity': 'SMALLINT'}
    fields = ', '.join(column + ' ' + types.get(column, 'TEXT') for column in BACKFILL_COLUMNS)
    raw = ('Oct 28 12:34:56 example-gateway CEF:0|Ubiquiti|UniFi Network|10.0.0|201|'
           'Threat Detected and Blocked|7|src=2001:db8::1 dst=10.20.0.4 proto=TCP '
           'spt=1234 dpt=443 act=blocked UNIFIrisk=medium '
           'UNIFIipsSignature=Synthetic detection UNIFIutcTime=2024-01-02T03:04:05Z')
    try:
        with connection.cursor() as cursor:
            cursor.execute(f'''CREATE TEMP TABLE logs (id BIGSERIAL PRIMARY KEY,
                timestamp TIMESTAMPTZ, raw_log TEXT, threat_score INTEGER, {fields})''')
            cursor.execute("INSERT INTO logs (timestamp, raw_log, log_type, threat_score) VALUES (NOW(), %s, 'system', 91)", [raw])
        connection.commit()
        assert run_backfill(connection)['matched'] == 1
        with connection.cursor() as cursor:
            cursor.execute('SELECT event_source FROM logs')
            assert cursor.fetchone() == (None,)
        assert run_backfill(connection, apply=True)['updated'] == 1
        assert run_backfill(connection, apply=True)['updated'] == 0
        with connection.cursor() as cursor:
            cursor.execute('SELECT id, host(src_ip), dst_port, timestamp, threat_score, raw_log FROM logs')
            assert cursor.fetchall() == [(1, '2001:db8::1', 443,
                datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc), 91, raw)]
    finally:
        connection.close()
