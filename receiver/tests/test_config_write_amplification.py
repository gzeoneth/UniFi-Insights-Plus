"""Unchanged JSON configuration must not create another heap row version.

Opt-in SQL checks use only an explicit loopback TEST_POSTGRES_DSN and a random
temporary schema. No application database credentials are used.
"""

from uuid import uuid4

import os
import psycopg2
from psycopg2 import pool, sql
import pytest

from db import Database
from read_cache import ReadCache


@pytest.fixture
def config_database():
    dsn = os.environ.get('TEST_POSTGRES_DSN')
    if not dsn:
        pytest.skip('Set TEST_POSTGRES_DSN to a disposable local PostgreSQL')
    params = psycopg2.extensions.parse_dsn(dsn)
    if params.get('host') not in ('127.0.0.1', 'localhost', '::1'):
        pytest.fail('Configuration integration test requires a loopback host')
    schema = 'config_write_test_' + uuid4().hex
    admin = psycopg2.connect(**params)
    admin.autocommit = True
    db = Database.__new__(Database)
    db.pool = None
    try:
        with admin.cursor() as cur:
            cur.execute(sql.SQL('CREATE SCHEMA {}').format(sql.Identifier(schema)))
            cur.execute(sql.SQL('CREATE TABLE {}.system_config '
                '(key TEXT PRIMARY KEY, value JSONB, updated_at TIMESTAMPTZ NOT NULL)')
                .format(sql.Identifier(schema)))
        db.pool = pool.ThreadedConnectionPool(1, 2, **{
            **params, 'options': '-c search_path=' + schema,
        })
        db._display_config_cache = ReadCache()
        yield db
    finally:
        if db.pool:
            db.close()
        with admin.cursor() as cur:
            cur.execute(sql.SQL('DROP SCHEMA IF EXISTS {} CASCADE')
                        .format(sql.Identifier(schema)))
        admin.close()


def version(db):
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT value, updated_at, xmin::text, ctid::text '
                        'FROM system_config WHERE key = %s', ['synthetic_config'])
            return cur.fetchone()


def test_identical_json_polls_preserve_heap_version_and_modification_time(config_database):
    db = config_database
    db.set_config('synthetic_config', {'b': [1, 2], 'a': 'example.invalid'})
    original = version(db)
    for _ in range(20):
        # JSONB compares values, including key-order-independent objects.
        db.set_config('synthetic_config', {'a': 'example.invalid', 'b': [1, 2]})
    assert version(db) == original
    db.set_config('synthetic_config', {'a': 'changed.example.invalid'})
    changed = version(db)
    assert changed[0] == {'a': 'changed.example.invalid'}
    assert changed[2:] != original[2:]
    assert changed[1] >= original[1]


def test_null_and_changed_value_are_not_mistaken_for_unchanged(config_database):
    db = config_database
    db.set_config('synthetic_config', None)
    original = version(db)
    db.set_config('synthetic_config', None)
    assert version(db) == original
    db.set_config('synthetic_config', False)
    assert version(db)[0] is False
    db.set_config('synthetic_config', None)
    assert version(db)[0] is None
    assert version(db)[2:] != original[2:]
