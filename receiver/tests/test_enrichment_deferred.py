"""Network cache misses must never stall parsing or durable DB delivery."""
import threading
import time
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from enrichment import Enricher
import firewall_policy_matcher as matcher


@pytest.fixture
def enricher(monkeypatch):
    monkeypatch.setattr('enrichment.GeoIPEnricher', MagicMock)
    monkeypatch.setenv('ENRICHMENT_QUEUE_CAPACITY', '2')
    monkeypatch.setenv('ABUSEIPDB_API_KEY', '')
    e = Enricher()
    e.geoip.lookup.return_value = {'geo_country': 'AU'}
    yield e
    e.close()


def event(ip='8.8.8.8'):
    return {'log_type': 'firewall', 'src_ip': '10.20.0.5', 'dst_ip': ip,
            'direction': 'outbound', 'rule_action': 'block'}


def test_slow_dns_uses_one_bounded_worker_and_keeps_local_fields(enricher):
    entered, release = threading.Event(), threading.Event()
    def blocked_dns(ip):
        entered.set()
        release.wait(3)
        return {'rdns': 'cached.example'}
    enricher.rdns.lookup = MagicMock(side_effect=blocked_dns)
    enricher.abuseipdb.lookup = MagicMock(return_value={})
    start = time.monotonic()
    result = enricher.enrich(event(), defer_network=True)
    assert time.monotonic() - start < 0.2
    assert result['remote_ip'] == '8.8.8.8'
    assert result['geo_country'] == 'AU'
    assert entered.wait(1)
    try:
        for ip in ('1.1.1.1', '9.9.9.9', '8.8.4.4', '208.67.222.222'):
            enricher.enrich(event(ip), defer_network=True)
        stats = enricher.network_stats()
        assert stats['depth'] == 2
        assert stats['pending'] == 3  # one active plus two waiting
        assert stats['dropped'] == 2
        assert stats['worker_alive'] is True
        enricher.abuseipdb.lookup.assert_not_called()
        start = time.monotonic()
        enricher.close()
        assert time.monotonic() - start < 0.8
    finally:
        release.set()
        enricher._network_thread.join(1)


def test_hot_cache_enrichment_has_no_db_dns_or_http_io(enricher):
    enricher._db = MagicMock()
    enricher.rdns.lookup = MagicMock(side_effect=AssertionError('live DNS forbidden'))
    enricher.abuseipdb.lookup = MagicMock(side_effect=AssertionError('live HTTP forbidden'))
    enricher.rdns.cache.set('8.8.8.8', {'rdns': 'dns.google', 'expires_at': time.time() + 60})
    enricher.abuseipdb.cache.set('8.8.8.8', {'threat_score': 10})
    result = enricher.enrich(event(), defer_network=True)
    assert result['rdns'] == 'dns.google'
    assert result['threat_score'] == 10
    assert not enricher._db.mock_calls
    assert enricher._network_thread is None


def test_negative_rdns_cache_prevents_repeat_network_jobs(enricher):
    enricher.rdns.cache.set('8.8.8.8', {'rdns': None, 'expires_at': time.time() + 60})
    result = enricher.enrich(event(), defer_network=True)
    assert 'rdns' not in result
    assert enricher._network_thread is None


def test_cold_policy_cache_never_fetches_controller_when_cached_only():
    matcher.invalidate_cache()
    unifi = MagicMock()
    rule = matcher.parse_firewall_rule('WAN_LOCAL-2000', rule_desc='Block unauthorized')
    assert matcher.resolve_rule_action(rule, unifi, 'eth8', 'br0', cached_only=True) == 'block'
    assert not unifi.method_calls


def test_ips_action_is_not_overridden_by_matching_policy_name(enricher, monkeypatch):
    enricher.unifi = SimpleNamespace(enabled=True, resolve_name=MagicMock(return_value='client'))
    resolver = MagicMock(side_effect=AssertionError('IPS act must remain authoritative'))
    monkeypatch.setattr(matcher, 'resolve_rule_action', resolver)
    enricher._defer_network = MagicMock()
    parsed = event()
    parsed.update(event_source='unifi_ips', rule_name='WAN_LOCAL-2000', rule_action='allow')
    result = enricher.enrich(parsed, defer_network=True)
    assert result['rule_action'] == 'allow'
    assert result['src_device_name'] == 'client'
    resolver.assert_not_called()
