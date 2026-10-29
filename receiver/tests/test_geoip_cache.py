"""Bounded MMDB caching and reader replacement under concurrent ingestion."""
import threading
import time
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from geoip2.errors import AddressNotFoundError

from enrichment import GeoIPEnricher


def reader_pair(country='AU', organization='Example transit'):
    city = MagicMock()
    city.city.return_value = SimpleNamespace(
        country=SimpleNamespace(iso_code=country), city=SimpleNamespace(name='Example city'),
        location=SimpleNamespace(latitude=0.0, longitude=0.0))
    asn = MagicMock()
    asn.asn.return_value = SimpleNamespace(
        autonomous_system_number=64496, autonomous_system_organization=organization)
    return city, asn


@pytest.fixture
def geoip(tmp_path):
    enricher = GeoIPEnricher(str(tmp_path))
    enricher.city_reader, enricher.asn_reader = reader_pair()
    yield enricher
    enricher.close()


def install_readers(monkeypatch, pair):
    monkeypatch.setattr('enrichment.os.path.exists', lambda path: True)
    monkeypatch.setattr('geoip2.database.Reader', MagicMock(side_effect=pair))


def test_repeated_ipv4_and_ipv6_read_mmdb_once_and_return_independent_results(geoip):
    for ip in ('192.0.2.10', '2001:db8::10'):
        result = geoip.lookup(ip)
        assert result['geo_lat'] == result['geo_lon'] == 0.0
        result['geo_country'] = 'modified'
        for _ in range(100):
            assert geoip.lookup(ip)['geo_country'] == 'AU'
    assert geoip.city_reader.city.call_count == 2
    assert geoip.asn_reader.asn.call_count == 2


def test_cache_has_a_fixed_entry_bound_and_expires(geoip, monkeypatch):
    geoip.CACHE_MAX_ENTRIES = 4
    geoip._cache = geoip._new_cache()
    clock = [100.0]
    monkeypatch.setattr('enrichment.time.time', lambda: clock[0])
    for index in range(20):
        geoip.lookup(f'192.0.2.{index}')
        assert geoip._cache.size() <= 4
    geoip.city_reader.reset_mock()
    geoip.lookup('192.0.2.19')
    geoip.city_reader.city.assert_not_called()
    clock[0] += geoip.CACHE_TTL_SECONDS + 1
    geoip.lookup('192.0.2.19')
    geoip.city_reader.city.assert_called_once()


def test_database_misses_are_cached_but_transient_failures_are_not(geoip):
    geoip.city_reader.city.side_effect = AddressNotFoundError('No result')
    geoip.asn_reader.asn.side_effect = AddressNotFoundError('No result')
    assert geoip.lookup('192.0.2.10') == {}
    assert geoip.lookup('192.0.2.10') == {}
    geoip.city_reader.city.assert_called_once()
    geoip.city_reader.city.side_effect = RuntimeError('temporary read failure')
    assert geoip.lookup('192.0.2.11') == {}
    assert geoip.lookup('192.0.2.11') == {}
    assert geoip.city_reader.city.call_count == 3


def test_successful_reload_invalidates_positive_and_negative_results(geoip, monkeypatch):
    old_city, old_asn = geoip.city_reader, geoip.asn_reader
    assert geoip.lookup('192.0.2.10')['geo_country'] == 'AU'
    old_city.city.side_effect = AddressNotFoundError('No result')
    old_asn.asn.side_effect = AddressNotFoundError('No result')
    assert geoip.lookup('192.0.2.11') == {}
    new_pair = reader_pair(country='NZ')
    install_readers(monkeypatch, new_pair)
    geoip.reload()
    assert geoip.lookup('192.0.2.10')['geo_country'] == 'NZ'
    assert geoip.lookup('192.0.2.11')['geo_country'] == 'NZ'
    old_city.close.assert_called_once()
    old_asn.close.assert_called_once()


def test_failed_reload_keeps_working_readers_and_cache(geoip, monkeypatch):
    old_city, old_asn = geoip.city_reader, geoip.asn_reader
    result = geoip.lookup('192.0.2.10')
    candidate_city, _ = reader_pair(country='NZ')
    install_readers(monkeypatch, [candidate_city, ValueError('invalid replacement ASN')])
    geoip.reload()
    assert geoip.city_reader is old_city
    assert geoip.asn_reader is old_asn
    assert geoip.lookup('192.0.2.10') == result
    old_city.close.assert_not_called()
    old_asn.close.assert_not_called()
    candidate_city.close.assert_called_once()
    assert old_city.city.call_count == 1


def test_slow_open_does_not_hold_reader_or_cache_locks(geoip, monkeypatch):
    geoip.lookup('192.0.2.10')
    entered, release = threading.Event(), threading.Event()
    new_city, new_asn = reader_pair(country='NZ')
    def slow_open(path):
        if path.endswith('City.mmdb'):
            entered.set()
            assert release.wait(2)
            return new_city
        return new_asn
    monkeypatch.setattr('enrichment.os.path.exists', lambda path: True)
    monkeypatch.setattr('geoip2.database.Reader', slow_open)
    thread = threading.Thread(target=geoip.reload)
    thread.start()
    assert entered.wait(1)
    try:
        started = time.monotonic()
        assert geoip.lookup('192.0.2.10')['geo_country'] == 'AU'
        assert geoip.lookup('192.0.2.11')['geo_country'] == 'AU'
        assert time.monotonic() - started < 0.2
    finally:
        release.set()
        thread.join(2)
    assert not thread.is_alive()
    assert geoip.lookup('192.0.2.10')['geo_country'] == 'NZ'


def test_reader_is_not_closed_during_a_cold_lookup(geoip, monkeypatch):
    old_city, old_asn = geoip.city_reader, geoip.asn_reader
    entered, release, opened = threading.Event(), threading.Event(), threading.Event()
    city_response = old_city.city.return_value
    # Keep one hot address to prove cache hits do not wait for cold reads.
    geoip.lookup('192.0.2.10')
    def slow_read(ip):
        entered.set()
        assert release.wait(2)
        old_city.close.assert_not_called()
        return city_response
    old_city.city.side_effect = slow_read
    lookup_result = []
    lookup_thread = threading.Thread(target=lambda: lookup_result.append(geoip.lookup('192.0.2.11')))
    lookup_thread.start()
    assert entered.wait(1)
    pair = reader_pair(country='NZ')
    def open_reader(path):
        opened.set()
        return pair[0 if path.endswith('City.mmdb') else 1]
    monkeypatch.setattr('enrichment.os.path.exists', lambda path: True)
    monkeypatch.setattr('geoip2.database.Reader', open_reader)
    reload_thread = threading.Thread(target=geoip.reload)
    reload_thread.start()
    assert opened.wait(1)
    try:
        assert reload_thread.is_alive()
        started = time.monotonic()
        assert geoip.lookup('192.0.2.10')['geo_country'] == 'AU'
        assert time.monotonic() - started < 0.2
        old_city.close.assert_not_called()
        old_asn.close.assert_not_called()
    finally:
        release.set()
        lookup_thread.join(2)
        reload_thread.join(2)
    assert not lookup_thread.is_alive() and not reload_thread.is_alive()
    assert lookup_result[0]['geo_country'] == 'AU'
    old_city.close.assert_called_once()
    assert geoip.lookup('192.0.2.11')['geo_country'] == 'NZ'


def test_close_during_reload_does_not_reopen_or_leak_readers(geoip, monkeypatch):
    old_city, old_asn = geoip.city_reader, geoip.asn_reader
    entered, release = threading.Event(), threading.Event()
    new_city, new_asn = reader_pair(country='NZ')
    def slow_open(path):
        if path.endswith('City.mmdb'):
            entered.set()
            assert release.wait(2)
            return new_city
        return new_asn
    monkeypatch.setattr('enrichment.os.path.exists', lambda path: True)
    factory = MagicMock(side_effect=slow_open)
    monkeypatch.setattr('geoip2.database.Reader', factory)
    results = []
    thread = threading.Thread(target=lambda: results.append(geoip.reload()))
    thread.start()
    assert entered.wait(1)
    try:
        geoip.close()
        assert geoip.lookup('192.0.2.10') == {}
        old_city.close.assert_called_once()
        old_asn.close.assert_called_once()
    finally:
        release.set()
        thread.join(2)
    assert not thread.is_alive()
    assert results == [False]
    assert geoip.city_reader is None and geoip.asn_reader is None
    new_city.close.assert_called_once()
    new_asn.close.assert_called_once()
    factory.reset_mock()
    assert geoip.reload() is False
    factory.assert_not_called()


def test_missing_replacement_retains_the_loaded_database(geoip, monkeypatch):
    old_city, old_asn = geoip.city_reader, geoip.asn_reader
    assert geoip.lookup('192.0.2.10')['geo_country'] == 'AU'
    monkeypatch.setattr('enrichment.os.path.exists', lambda path: False)
    assert geoip.reload() is False
    assert geoip.city_reader is old_city
    assert geoip.asn_reader is old_asn
    assert geoip.lookup('192.0.2.10')['geo_country'] == 'AU'
    old_city.close.assert_not_called()
    old_asn.close.assert_not_called()


def test_close_does_not_wait_for_a_stalled_lookup_and_retires_once(geoip):
    old_city, old_asn = geoip.city_reader, geoip.asn_reader
    entered, release = threading.Event(), threading.Event()
    city_response = old_city.city.return_value
    assert geoip.lookup('192.0.2.10')['geo_country'] == 'AU'
    def slow_read(ip):
        entered.set()
        assert release.wait(2)
        old_city.close.assert_not_called()
        return city_response
    old_city.city.side_effect = slow_read
    results = []
    thread = threading.Thread(target=lambda: results.append(geoip.lookup('192.0.2.11')))
    thread.start()
    assert entered.wait(1)
    try:
        started = time.monotonic()
        geoip.close()
        assert time.monotonic() - started < 0.2
        worker = geoip._close_worker
        assert worker is not None
        geoip.close()
        assert geoip._close_worker is worker
        # Calls made after close neither serve a warm result nor wait on mmap.
        assert geoip.lookup('192.0.2.10') == {}
        assert geoip.lookup('192.0.2.12') == {}
        old_city.close.assert_not_called()
        old_asn.close.assert_not_called()
    finally:
        release.set()
        thread.join(2)
        geoip._close_worker.join(2)
    assert not thread.is_alive() and not worker.is_alive()
    assert results[0]['geo_country'] == 'AU'
    old_city.close.assert_called_once()
    old_asn.close.assert_called_once()
    assert geoip.city_reader is None and geoip.asn_reader is None
    assert geoip._cache.size() == 0
