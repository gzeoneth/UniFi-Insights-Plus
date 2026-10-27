"""Adapter validation and WAL durability at the spool acknowledgement boundary."""

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
        return [(1,)]
    monkeypatch.setattr('db.extras.execute_values', insert)
    assert database._execute_log_insert(cursor, [{'raw_log': 'Synthetic event'}]) == 1
