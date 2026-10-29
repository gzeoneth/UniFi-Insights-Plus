"""Exercise backfill transactions against a real in-memory SQL table.

SQLite supplies transactions and UPDATE guards here; the tiny adapter only
translates PostgreSQL placeholders and POSITION syntax. Deployment validation
still needs PostgreSQL, including its INET/MACADDR type validation.
"""

import sqlite3
from unittest.mock import MagicMock

import pytest

from cef_backfill import BACKFILL_COLUMNS, main, run_backfill


def event(*, extension='', event_id='201', name='Threat Detected and Blocked'):
    return (f'Oct 28 12:34:56 example-gateway CEF:0|Ubiquiti|UniFi Network|10.0.0|'
            f'{event_id}|{name}|7|src=203.0.113.20 dst=10.20.0.4 act=blocked {extension}')


class Cursor:
    def __init__(self, connection):
        self.connection = connection
        self.cursor = connection.sql.cursor()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.cursor.close()

    def execute(self, query, params=()):
        if 'UPDATE logs SET' in query and self.connection.fail_updates_after is not None:
            if self.connection.updates == self.connection.fail_updates_after:
                raise RuntimeError('synthetic database failure')
            self.connection.updates += 1
        query = query.replace('%s', '?').replace("POSITION('CEF:' IN raw_log)", "instr(raw_log, 'CEF:')")
        # sqlite's implicit datetime adapter is deprecated; explicit ISO text
        # also lets tests verify the timestamp value without timezone loss.
        params = [value.isoformat() if hasattr(value, 'isoformat') else value for value in params]
        return self.cursor.execute(query, params)

    def fetchone(self):
        return self.cursor.fetchone()

    def fetchall(self):
        return self.cursor.fetchall()

    @property
    def rowcount(self):
        return self.cursor.rowcount


class Connection:
    def __init__(self):
        self.sql = sqlite3.connect(':memory:')
        self.fail_updates_after = None
        self.updates = 0
        fields = ', '.join(column + ' TEXT' for column in BACKFILL_COLUMNS)
        self.sql.execute(f'''CREATE TABLE logs (
            id INTEGER PRIMARY KEY, raw_log TEXT NOT NULL, timestamp TEXT NOT NULL,
            created_at TEXT, threat_score INTEGER, threat_categories TEXT,
            mac_address TEXT, ingest_id TEXT, {fields})''')

    def cursor(self):
        return Cursor(self)

    def commit(self):
        self.sql.commit()

    def rollback(self):
        self.sql.rollback()

    def add(self, row_id, raw, log_type='system', event_source=None):
        self.sql.execute('''INSERT INTO logs
            (id, raw_log, timestamp, created_at, threat_score, threat_categories,
             mac_address, ingest_id, log_type, event_source)
            VALUES (?, ?, '2022-10-28T04:34:56+00:00', 'original-created', 91,
                    'original-reputation', '02:00:00:00:00:ff', 'original-ingest-id', ?, ?)''',
            (row_id, raw, log_type, event_source))
        self.commit()


@pytest.fixture
def database():
    connection = Connection()
    yield connection
    connection.sql.close()


def test_default_dry_run_does_not_change_any_row(database):
    database.add(1, event())
    before = database.sql.execute('SELECT * FROM logs').fetchall()
    result = run_backfill(database)
    assert result['matched'] == 1
    assert result['updated'] == 0
    assert result['apply'] is False
    assert database.sql.execute('SELECT * FROM logs').fetchall() == before


def test_apply_updates_same_row_once_and_preserves_raw_and_reputation(database):
    raw = event()
    database.add(1, raw)
    result = run_backfill(database, apply=True)
    assert result['updated'] == 1
    row = database.sql.execute('''SELECT id, raw_log, timestamp, created_at, threat_score,
        threat_categories, mac_address, ingest_id, source, event_source, ips_severity,
        log_type, rule_action FROM logs''').fetchone()
    assert row == (1, raw, '2022-10-28T04:34:56+00:00', 'original-created', 91,
                   'original-reputation', '02:00:00:00:00:ff', 'original-ingest-id',
                   'syslog', 'unifi_ips', '7', 'firewall', 'block')
    assert run_backfill(database, apply=True)['updated'] == 0
    assert database.sql.execute('SELECT COUNT(*) FROM logs').fetchone()[0] == 1


def test_only_explicit_cef_time_replaces_historical_timestamp(database):
    database.add(1, event(extension='UNIFIutcTime=2020-01-02T03:04:05.123Z'))
    database.add(2, event(extension='UNIFIutcTime=invalid'))
    run_backfill(database, apply=True)
    dates = database.sql.execute('SELECT timestamp FROM logs ORDER BY id').fetchall()
    assert dates == [('2020-01-02T03:04:05.123000+00:00',), ('2022-10-28T04:34:56+00:00',)]


def test_bounded_resume_has_stable_upper_id_and_does_not_chase_new_ingestion(database):
    for row_id in range(1, 6):
        database.add(row_id, event())
    progress = []
    first = run_backfill(database, apply=True, batch_size=2, max_batches=1, progress=progress.append)
    assert first['scanned'] == first['updated'] == 2
    assert first['after_id'] == 2
    assert first['through_id'] == 5
    assert first['complete'] is False
    assert progress == [first]
    database.add(6, event())
    resumed = run_backfill(database, apply=True, after_id=first['after_id'],
                           through_id=first['through_id'], batch_size=2, max_batches=3)
    assert resumed['updated'] == 3
    assert resumed['complete'] is True
    assert database.sql.execute('SELECT event_source FROM logs WHERE id = 6').fetchone() == (None,)


def test_other_events_and_already_classified_rows_remain_untouched(database):
    database.add(1, event(event_id='546', name='Config Modified'))
    database.add(2, event(), log_type='firewall')
    database.add(3, event(), event_source='another_source')
    database.add(4, 'CEF:malformed')
    database.add(5, 'Oct 28 12:34:56 host normal system event')
    before = database.sql.execute('SELECT * FROM logs').fetchall()
    result = run_backfill(database, apply=True, batch_size=1, max_batches=10)
    assert result['matched'] == result['updated'] == 0
    assert result['scanned'] == 5
    assert result['complete'] is True
    assert database.sql.execute('SELECT * FROM logs').fetchall() == before


def test_failed_batch_rolls_back_and_prior_committed_cursor_remains_resumable(database):
    for row_id in range(1, 5):
        database.add(row_id, event())
    database.fail_updates_after = 3
    progress = []
    with pytest.raises(RuntimeError, match='synthetic database failure'):
        run_backfill(database, apply=True, batch_size=2, progress=progress.append)
    assert len(progress) == 1
    assert progress[0]['after_id'] == 2
    assert database.sql.execute('SELECT id FROM logs WHERE event_source IS NOT NULL').fetchall() == [(1,), (2,)]
    database.fail_updates_after = None
    result = run_backfill(database, apply=True, after_id=2, through_id=4)
    assert result['updated'] == 2


@pytest.mark.parametrize('options', [
    {'batch_size': 0}, {'batch_size': 5001}, {'max_batches': 0},
    {'after_id': -1}, {'after_id': 5, 'through_id': 4},
])
def test_bad_limits_rejected_before_any_query(database, options):
    with pytest.raises(ValueError):
        run_backfill(database, **options)


def test_cli_default_uses_read_only_connection_and_does_not_migrate(monkeypatch):
    import psycopg2
    import db
    connection = MagicMock()
    connection.cursor.return_value.__enter__.return_value.fetchone.return_value = (0,)
    connection.cursor.return_value.__enter__.return_value.fetchall.return_value = []
    monkeypatch.setattr(psycopg2, 'connect', MagicMock(return_value=connection))
    monkeypatch.setattr(db.Database, 'connect', MagicMock(side_effect=AssertionError('must not migrate')))
    assert main([]) == 0
    connection.set_session.assert_called_once_with(readonly=True)
    connection.close.assert_called_once()
