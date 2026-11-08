"""Quota exhaustion must not repeatedly query absent reputation records."""

from unittest.mock import MagicMock

import pytest

from enrichment import AbuseIPDBEnricher, Enricher


@pytest.fixture
def limited(monkeypatch):
    monkeypatch.setattr(AbuseIPDBEnricher, '_load_persisted_stats', lambda self: None)
    monkeypatch.setattr(AbuseIPDBEnricher, '_write_stats', lambda self: None)
    db = MagicMock()
    db.get_threat_cache.return_value = None
    provider = AbuseIPDBEnricher(api_key='synthetic-fixture', db=db)
    provider._rate_limit_remaining = 0
    provider._rate_limit_limit = 1000
    return provider, db


def test_repeated_quota_miss_reads_db_once_and_keeps_score_unknown(limited):
    provider, db = limited
    for _ in range(100):
        assert provider.lookup('203.0.113.5') == {}
    db.get_threat_cache.assert_called_once()
    assert provider.cache.get('203.0.113.5') is None
    db.upsert_threat.assert_not_called()


def test_quota_miss_expires_and_sees_new_persistent_reputation(limited, monkeypatch):
    provider, db = limited
    clock = [100.0]
    monkeypatch.setattr('enrichment.time.time', lambda: clock[0])
    assert provider.lookup('203.0.113.5') == {}
    db.get_threat_cache.return_value = {'threat_score': 70}
    clock[0] = 114.9
    assert provider.lookup('203.0.113.5') == {}
    clock[0] = 115.0
    assert provider.lookup('203.0.113.5') == {'threat_score': 70}
    assert db.get_threat_cache.call_count == 2


@pytest.mark.parametrize('state', ['quota_reset', 'budget_restored', 'budget_unknown'])
def test_renewed_budget_bypasses_delay_immediately(limited, monkeypatch, state):
    provider, db = limited
    monkeypatch.setattr('enrichment.time.time', lambda: 100.0)
    assert provider.lookup('203.0.113.5') == {}
    if state == 'quota_reset':
        provider._rate_limit_reset = 99
    elif state == 'budget_restored':
        provider._rate_limit_remaining = 1
    else:
        provider._rate_limit_remaining = None
    # A fresh DB result can be used even before another external API request.
    db.get_threat_cache.return_value = {'threat_score': 70}
    assert provider.lookup('203.0.113.5') == {'threat_score': 70}


def test_positive_memory_cache_wins_over_quota_miss(limited):
    provider, _ = limited
    assert provider.lookup('203.0.113.5') == {}
    provider.cache.set('203.0.113.5', {'threat_score': 80})
    assert provider.lookup('203.0.113.5') == {'threat_score': 80}


def test_cooldown_check_never_waits_for_provider_persistence_lock(limited):
    provider, _ = limited
    provider.lookup('203.0.113.5')
    provider._lock.acquire()
    try:
        # A busy provider may persist quota state while holding this lock.
        # Ingestion skips the optional optimization without waiting for I/O.
        assert provider.quota_miss_active('203.0.113.5') is False
    finally:
        provider._lock.release()
    assert provider.quota_miss_active('203.0.113.5') is True


def test_manual_bypass_refreshes_db_without_bypassing_provider_quota(limited, monkeypatch):
    provider, db = limited
    http = MagicMock(side_effect=AssertionError('quota must remain enforced'))
    monkeypatch.setattr('enrichment.requests.get', http)
    assert provider.lookup('203.0.113.5') == {}
    assert provider.lookup('203.0.113.5', bypass_cooldown=True) == {}
    assert db.get_threat_cache.call_count == 2
    http.assert_not_called()


def test_database_error_does_not_cache_an_unconfirmed_miss(limited):
    provider, db = limited
    db.get_threat_cache.side_effect = RuntimeError('database unavailable')
    for _ in range(2):
        assert provider.lookup('203.0.113.5') == {}
    assert db.get_threat_cache.call_count == 2
    assert not provider.quota_miss_active('203.0.113.5')


def test_active_429_pause_overrides_reset_until_pause_ends(limited, monkeypatch):
    provider, _ = limited
    clock = [100.0]
    monkeypatch.setattr('enrichment.time.time', lambda: clock[0])
    provider.lookup('203.0.113.5')
    provider._paused_until = 105.0
    provider._rate_limit_reset = 99.0
    assert provider.quota_miss_active('203.0.113.5')
    clock[0] = 106.0
    assert not provider.quota_miss_active('203.0.113.5')


def test_quota_miss_map_stays_bounded(limited):
    provider, db = limited
    for number in range(2000):
        provider.lookup(f'2001:db8::{number:x}')
    assert provider._quota_misses.size() <= 1024
    assert db.get_threat_cache.call_count == 2000


def test_deferred_ingest_does_no_io_or_queue_work_for_known_quota_miss(limited, monkeypatch):
    provider, _ = limited
    provider.lookup('203.0.113.5')
    monkeypatch.setattr('enrichment.GeoIPEnricher', MagicMock)
    monkeypatch.setattr('enrichment.is_public_ip', lambda ip: ip == '203.0.113.5')
    enricher = Enricher()
    try:
        enricher.abuseipdb = provider
        enricher._rdns_enabled = False
        enricher.geoip.lookup.return_value = {}
        provider._check_rate_limit = MagicMock(side_effect=AssertionError('may perform IO'))
        provider.lookup = MagicMock(side_effect=AssertionError('no repeated DB lookup'))
        result = enricher.enrich({'log_type': 'firewall', 'src_ip': '192.0.2.5',
                                 'dst_ip': '203.0.113.5', 'direction': 'outbound',
                                 'rule_action': 'block'}, defer_network=True)
        assert 'threat_score' not in result
        assert enricher._network_thread is None
    finally:
        enricher.close()
