"""Metadata caches reduce reads without caching authorization or event results."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import threading
from unittest.mock import MagicMock

import pytest

from db import Database
from read_cache import ReadCache, ttl_cache


def test_keys_include_every_argument_and_defaults():
    calls = []

    @ttl_cache()
    def lookup(host, filters=None, window='1h', identity='viewer'):
        calls.append((host, filters, window, identity))
        return {'calls': len(calls)}

    assert lookup('192.0.2.1') == lookup(host='192.0.2.1', filters=None, window='1h')
    assert lookup('192.0.2.1', filters={'exclude': ['203.0.113.5']})['calls'] == 2
    assert lookup('192.0.2.1', window='24h')['calls'] == 3
    assert lookup('192.0.2.1', identity='another-viewer')['calls'] == 4
    assert lookup('192.0.2.2')['calls'] == 5
    lookup.cache_clear()
    assert lookup('192.0.2.1')['calls'] == 6


def test_cached_metadata_cannot_be_mutated_by_response_annotation():
    cache = ReadCache()
    original = {'nested': {'label': 'Example'}}
    first = cache.get_or_load('key', lambda: original)
    first['nested']['label'] = 'Changed'
    second = cache.get_or_load('key', lambda: pytest.fail('unexpected read'))
    assert second == {'nested': {'label': 'Example'}}
    second['nested']['label'] = 'Another change'
    assert cache.get_or_load('key', lambda: None)['nested']['label'] == 'Example'


def test_expired_results_and_loader_errors_are_not_served(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr('read_cache.time.monotonic', lambda: clock[0])
    cache = ReadCache(seconds=10)
    assert cache.get_or_load('k', lambda: 'old') == 'old'
    clock[0] = 10
    def failed():
        raise RuntimeError('read failed')
    with pytest.raises(RuntimeError, match='read failed'):
        cache.get_or_load('k', failed)
    assert cache.get_or_load('k', lambda: 'fresh') == 'fresh'


def test_none_is_cached_and_types_do_not_collide():
    calls = []
    @ttl_cache()
    def lookup(value):
        calls.append(value)
        return None
    lookup(True)
    lookup(True)
    lookup(1)
    assert calls == [True, 1]


def test_entry_and_byte_limits():
    cache = ReadCache(max_entries=2, max_bytes=1024)
    for key in ('a', 'b', 'c'):
        cache.get_or_load(key, lambda: 'value')
    assert list(cache._entries) == ['b', 'c']
    cache.get_or_load('b', lambda: None)
    cache.get_or_load('d', lambda: 'value')
    assert list(cache._entries) == ['b', 'd']
    # One large result is returned normally but must not occupy the cache.
    assert cache.get_or_load('huge', lambda: 'x' * 4096) == 'x' * 4096
    assert 'huge' not in cache._entries
    assert cache._bytes <= cache.max_bytes
    small = ReadCache(max_entries=100, max_bytes=1024)
    for i in range(100):
        small.get_or_load(str(i), lambda: {'payload': 'x' * 128})
    assert len(small._entries) < 100
    assert small._bytes <= 1024


def test_concurrent_same_key_loads_once_other_keys_do_not_wait():
    cache = ReadCache()
    entered, release = threading.Event(), threading.Event()
    calls = []
    def slow():
        calls.append('load')
        entered.set()
        assert release.wait(5)
        return {'value': 1}
    with ThreadPoolExecutor(max_workers=8) as pool:
        first = pool.submit(cache.get_or_load, 'same', slow)
        assert entered.wait(5)
        followers = [pool.submit(cache.get_or_load, 'same', slow) for _ in range(5)]
        try:
            unrelated = pool.submit(cache.get_or_load, 'other', lambda: 'independent')
            assert unrelated.result(timeout=2) == 'independent'
        finally:
            release.set()
        assert first.result(timeout=2) == {'value': 1}
        assert all(f.result(timeout=2) == {'value': 1} for f in followers)
    assert calls == ['load']


def test_invalidation_during_load_cannot_restore_old_snapshot():
    cache = ReadCache()
    entered, release = threading.Event(), threading.Event()
    def old_read():
        entered.set()
        assert release.wait(5)
        return 'old'
    with ThreadPoolExecutor(max_workers=2) as pool:
        old = pool.submit(cache.get_or_load, 'labels', old_read)
        assert entered.wait(5)
        try:
            cache.clear()
            new = pool.submit(cache.get_or_load, 'labels', lambda: 'new')
            assert new.result(timeout=2) == 'new'
        finally:
            release.set()
        assert old.result(timeout=2) == 'old'
    assert cache.get_or_load('labels', lambda: pytest.fail('cache lost new value')) == 'new'


def _database():
    database = Database(conn_params={'host': 'example.invalid'})
    cursor = MagicMock()
    cursor.fetchall.return_value = [('wan_ip_names', {'203.0.113.5': 'Example WAN'})]
    connection = MagicMock()
    connection.cursor.return_value.__enter__.return_value = cursor
    @contextmanager
    def get_conn():
        yield connection
        connection.commit()
    database.get_conn = get_conn
    return database, connection, cursor


def test_identity_snapshot_batches_reads_and_normal_config_is_uncached():
    database, _, cursor = _database()
    for _ in range(50):
        assert database.get_display_config()['wan_ip_names']['203.0.113.5'] == 'Example WAN'
    assert cursor.execute.call_count == 1
    assert cursor.execute.call_args.args[1] == [list(database._DISPLAY_CONFIG_KEYS)]
    database.get_config('auth_enabled')
    database.get_config('auth_enabled')
    assert cursor.execute.call_count == 3


def test_write_invalidates_labels_only_after_successful_commit():
    database, connection, cursor = _database()
    database.get_display_config()
    database.set_config('wan_ip_names', {'203.0.113.5': 'New example WAN'})
    cursor.fetchall.return_value = [('wan_ip_names', {'203.0.113.5': 'New example WAN'})]
    assert database.get_display_config()['wan_ip_names']['203.0.113.5'] == 'New example WAN'
    assert cursor.execute.call_count == 3  # read, write, fresh read
    database.set_config('unrelated', True)
    database.get_display_config()
    assert cursor.execute.call_count == 4  # unrelated write preserves label cache
    connection.commit.side_effect = RuntimeError('commit failed')
    with pytest.raises(RuntimeError):
        database.set_config('wan_ip_names', {})
    assert database.get_display_config()['wan_ip_names']['203.0.113.5'] == 'New example WAN'


def test_identity_snapshots_are_database_instance_scoped():
    first, _, _ = _database()
    second, _, cursor = _database()
    cursor.fetchall.return_value = []
    assert first.get_display_config()
    assert second.get_display_config() == {}


def test_external_updates_expire_without_serving_stale_on_failure(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr('read_cache.time.monotonic', lambda: clock[0])
    database, _, cursor = _database()
    database.get_display_config()
    cursor.fetchall.return_value = []
    clock[0] = 10.0
    assert database.get_display_config() == {}
    clock[0] = 20.0
    cursor.execute.side_effect = RuntimeError('database unavailable')
    with pytest.raises(RuntimeError):
        database.get_display_config()
