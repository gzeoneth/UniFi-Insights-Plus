"""Tests for estimate_log_count() and Database.get_stats() (issue #103).

The total must come from the pg_class.reltuples estimate, never from a
full-table COUNT(*) over logs.
"""
from unittest.mock import MagicMock

from db import Database, estimate_log_count


def _mock_db(fetchone=(1234,), fetchall=(('firewall', 7),)):
    db = MagicMock()
    cur = MagicMock()
    cur.fetchone.return_value = fetchone
    cur.fetchall.return_value = list(fetchall)
    conn = db.get_conn.return_value.__enter__.return_value
    conn.cursor.return_value.__enter__.return_value = cur
    return db, cur


def _executed_sql(cur):
    return [' '.join(c.args[0].split()) for c in cur.execute.call_args_list]


def test_total_uses_reltuples_estimate():
    db, cur = _mock_db()
    Database.get_stats(db)
    sql = _executed_sql(cur)
    assert any('reltuples' in s and 'pg_class' in s for s in sql)
    # The hourly per-type breakdown (time-bounded) keeps its COUNT(*);
    # only the unbounded total must be gone.
    assert not any(s.startswith('SELECT COUNT(*) FROM logs') for s in sql)


def test_returns_estimate_and_hourly_breakdown():
    db, _ = _mock_db(fetchone=(1234,), fetchall=(('firewall', 7), ('dns', 3)))
    assert Database.get_stats(db) == {
        'total': 1234,
        'last_hour': {'firewall': 7, 'dns': 3},
    }


def test_total_zero_when_catalog_row_missing():
    db, _ = _mock_db(fetchone=None, fetchall=())
    assert Database.get_stats(db) == {'total': 0, 'last_hour': {}}


def test_estimate_log_count_reads_reltuples():
    cur = MagicMock()
    cur.fetchone.return_value = (987,)
    assert estimate_log_count(cur) == 987
    sql = _executed_sql(cur)
    assert len(sql) == 1
    assert 'reltuples' in sql[0] and 'pg_class' in sql[0]


def test_estimate_log_count_zero_without_catalog_row():
    cur = MagicMock()
    cur.fetchone.return_value = None
    assert estimate_log_count(cur) == 0
