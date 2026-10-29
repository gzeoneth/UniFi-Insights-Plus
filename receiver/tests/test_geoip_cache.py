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
    wait_retired(enricher)


def wait_for(predicate, timeout=2):
    deadline = time.monotonic() + timeout
    while not predicate() and time.monotonic() < deadline:
        time.sleep(0.001)
    assert predicate()


def wait_retired(geoip):
    with geoip._reader_condition:
        pending = list(geoip._retired_generations)
    assert all(generation.closed.wait(2) for generation in pending)


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
        wait_for(lambda: geoip.city_reader is pair[0])
        started = time.monotonic()
        assert geoip.lookup('192.0.2.10')['geo_country'] == 'NZ'
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
        wait_retired(geoip)
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
        worker.join(2)
    assert not thread.is_alive() and not worker.is_alive()
    assert results[0]['geo_country'] == 'AU'
    old_city.close.assert_called_once()
    old_asn.close.assert_called_once()
    assert geoip.city_reader is None and geoip.asn_reader is None
    assert geoip._cache.size() == 0


def test_unrelated_cold_lookup_does_not_wait_for_a_background_read(geoip):
    city = geoip.city_reader
    response = city.city.return_value
    entered, release = threading.Event(), threading.Event()
    result = []

    def read(ip):
        if ip == '192.0.2.10':
            entered.set()
            assert release.wait(2)
        return response

    city.city.side_effect = read
    background = threading.Thread(target=lambda: geoip.lookup('192.0.2.10'))
    foreground = threading.Thread(target=lambda: result.append(geoip.lookup('192.0.2.11')))
    background.start()
    assert entered.wait(1)
    try:
        foreground.start()
        foreground.join(0.5)
        assert not foreground.is_alive(), 'Unrelated intake lookup waited for background MMDB work'
        assert result[0]['geo_country'] == 'AU'
        assert background.is_alive()
    finally:
        release.set()
        background.join(2)
        foreground.join(2)


def test_old_read_uses_one_reader_pair_and_cannot_poison_new_cache(geoip, monkeypatch):
    old_city, old_asn = geoip.city_reader, geoip.asn_reader
    entered, release = threading.Event(), threading.Event()
    response = old_city.city.return_value
    result = []

    def read(ip):
        entered.set()
        assert release.wait(2)
        return response

    old_city.city.side_effect = read
    old_lookup = threading.Thread(target=lambda: result.append(geoip.lookup('192.0.2.10')))
    old_lookup.start()
    assert entered.wait(1)
    new_city, new_asn = reader_pair(country='NZ', organization='Replacement transit')
    install_readers(monkeypatch, (new_city, new_asn))
    reload_thread = threading.Thread(target=geoip.reload)
    reload_thread.start()
    try:
        wait_for(lambda: geoip.city_reader is new_city)
        # The same IP can use its replacement while an old lookup is pinned.
        fresh = geoip.lookup('192.0.2.10')
        assert fresh['geo_country'] == 'NZ'
        assert fresh['asn_name'] == 'Replacement transit'
        old_asn.close.assert_not_called()
    finally:
        release.set()
        old_lookup.join(2)
        reload_thread.join(2)
    assert not old_lookup.is_alive() and not reload_thread.is_alive()
    assert result[0]['geo_country'] == 'AU'
    assert result[0]['asn_name'] == 'Example transit'
    assert geoip.lookup('192.0.2.10') == fresh
    new_city.city.assert_called_once()
    new_asn.asn.assert_called_once()
    old_city.close.assert_called_once()
    old_asn.close.assert_called_once()


def test_reloads_and_shutdown_keep_retired_generations_bounded(geoip, monkeypatch):
    old_city, old_asn = geoip.city_reader, geoip.asn_reader
    entered, release = threading.Event(), threading.Event()
    response = old_city.city.return_value

    def read(ip):
        entered.set()
        assert release.wait(3)
        return response

    old_city.city.side_effect = read
    active = threading.Thread(target=lambda: geoip.lookup('192.0.2.10'))
    active.start()
    assert entered.wait(1)
    new_pair = reader_pair(country='NZ')
    install_readers(monkeypatch, new_pair)
    factory = __import__('geoip2.database', fromlist=['Reader']).Reader
    reloads = [threading.Thread(target=geoip.reload) for _ in range(12)]
    reloads[0].start()
    try:
        wait_for(lambda: geoip.city_reader is new_pair[0])
        worker = geoip._close_worker
        for thread in reloads[1:]:
            thread.start()
        assert geoip.lookup('192.0.2.11')['geo_country'] == 'NZ'
        assert factory.call_count == 2
        assert len(geoip._retired_generations) == 1
        started = time.monotonic()
        geoip.close()
        assert time.monotonic() - started < 0.2
        assert geoip._close_worker is worker
        assert len(geoip._retired_generations) <= 2
        # Even though the first generation is pinned, the unused replacement
        # can retire. No extra files or close threads accumulate.
        wait_for(lambda: new_pair[1].close.call_count == 1)
        assert factory.call_count == 2
        assert geoip.lookup('192.0.2.12') == {}
        old_city.close.assert_not_called()
    finally:
        release.set()
        active.join(2)
        for thread in reloads:
            thread.join(2)
        wait_retired(geoip)
    assert not active.is_alive() and all(not thread.is_alive() for thread in reloads)
    assert factory.call_count == 2
    old_city.close.assert_called_once()
    old_asn.close.assert_called_once()
    for reader in new_pair:
        reader.close.assert_called_once()


def test_slow_reader_close_never_blocks_shutdown_or_replacement_lookups(geoip, monkeypatch):
    old_city = geoip.city_reader
    entered, release = threading.Event(), threading.Event()

    def slow_close():
        entered.set()
        assert release.wait(3)

    old_city.close.side_effect = slow_close
    new_pair = reader_pair(country='NZ')
    install_readers(monkeypatch, new_pair)
    reload_thread = threading.Thread(target=geoip.reload)
    reload_thread.start()
    try:
        assert entered.wait(1)
        assert geoip.lookup('192.0.2.10')['geo_country'] == 'NZ'
        worker = geoip._close_worker
        started = time.monotonic()
        geoip.close()
        assert time.monotonic() - started < 0.2
        assert geoip._close_worker is worker
        assert len(geoip._retired_generations) == 2
        geoip.close()
        assert geoip._close_worker is worker
        assert geoip.lookup('192.0.2.11') == {}
        for reader in new_pair:
            reader.close.assert_not_called()
    finally:
        release.set()
        reload_thread.join(2)
        wait_retired(geoip)
    assert not reload_thread.is_alive()
    old_city.close.assert_called_once()
    for reader in new_pair:
        reader.close.assert_called_once()


def test_reader_and_close_errors_release_leases_and_keep_retirement_moving(geoip, monkeypatch):
    old_city, old_asn = geoip.city_reader, geoip.asn_reader
    old_city.city.side_effect = RuntimeError('synthetic unsupported lookup')
    old_asn.asn.side_effect = RuntimeError('synthetic unsupported lookup')
    old_city.close.side_effect = RuntimeError('synthetic failed close')
    assert geoip.lookup('192.0.2.10') == {}
    assert geoip._reader_generation.active == 0
    assert geoip._cache.size() == 0
    new_pair = reader_pair(country='NZ')
    install_readers(monkeypatch, new_pair)
    assert geoip.reload() is True
    old_city.close.assert_called_once()
    old_asn.close.assert_called_once()
    assert geoip.lookup('192.0.2.10')['geo_country'] == 'NZ'
