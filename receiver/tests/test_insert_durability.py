"""Adapter validation and WAL durability at the spool acknowledgement boundary."""

from contextlib import contextmanager
from unittest.mock import MagicMock

import psycopg2
import pytest

from db import Database


@pytest.mark.parametrize('log', [
    {'raw_log': 'Synthetic event\x00'},
    {'raw_log': 'Synthetic event', 'ips_signature': 'Synthetic\x00signature'},
    {'raw_log': 'Synthetic event', 'threat_categories': ['clean', 'invalid\x00category']},
])
def test_nul_is_classified_as_bad_data_before_any_database_operation(log):
    cursor = MagicMock()
    database = Database.__new__(Database)
    with pytest.raises(psycopg2.DataError, match='NUL'):
        database._execute_log_insert(cursor, [log])
    cursor.execute.assert_not_called()


def test_insert_requires_synchronous_commit_before_writing(monkeypatch):
    cursor = MagicMock()
    database = Database.__new__(Database)
    def insert(cur, sql, rows, **kwargs):
        assert cur.execute.call_args.args == ('SET LOCAL synchronous_commit = on',)
        assert kwargs['page_size'] == 1000
        return [(1,)]
    monkeypatch.setattr('db.extras.execute_values', insert)
    assert database._execute_log_insert(cursor, [{'raw_log': 'Synthetic event'}]) == 1


@pytest.mark.parametrize('failing_statement', ['SAVEPOINT', 'ROLLBACK TO', 'RELEASE'])
def test_savepoint_failure_retries_entire_batch(monkeypatch, failing_statement):
    database = Database.__new__(Database)
    cursor = MagicMock()
    connection = MagicMock()
    connection.cursor.return_value.__enter__.return_value = cursor

    @contextmanager
    def connection_scope():
        yield connection

    calls = 0

    def insert(cur, rows):
        nonlocal calls
        calls += 1
        raise psycopg2.DataError('synthetic invalid row')

    def execute(statement):
        if statement.startswith(failing_statement):
            raise psycopg2.OperationalError('synthetic savepoint failure')

    monkeypatch.setattr(database, 'get_conn', connection_scope)
    monkeypatch.setattr(database, '_execute_log_insert', insert)
    cursor.execute.side_effect = execute
    rows = [{'raw_log': 'synthetic first'}, {'raw_log': 'synthetic second'}]
    result = database.insert_logs_batch(rows)
    assert (result.inserted, result.duplicates, result.dropped) == (0, 0, 0)
    assert result.retryable == rows
