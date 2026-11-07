"""Pi-hole collection must not create extra workers or endpoint DNS floods."""

from copy import deepcopy
import importlib.util
import ipaddress
from pathlib import Path
import socket
import struct
import sys
import threading
import time
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import pihole_api
from pihole_api import PiHolePoller, _EndpointResolver


def query(identifier, **changes):
    record = {
        'id': identifier, 'time': 1700000000 + identifier / 1000,
        'domain': f'query-{identifier}.example.invalid', 'type': 'A',
        'status': 'FORWARDED', 'client': {'ip': '198.51.100.10', 'name': None},
        'reply': {'type': 'IP', 'time': 0.01},
    }
    record.update(changes)
    return record


class FakeDatabase:
    def __init__(self):
        self.config = {
            'pihole_host': 'https://dns-api.example.invalid',
            'pihole_password': 'synthetic-password', 'pihole_enabled': True,
            'pihole_enrichment': 'none', 'pihole_last_cursor': 0,
            'pihole_source_generation': 0,
        }
        self.commits = []
        self.calls = 0
        self.fail_at = None

    def get_config(self, key, default=None):
        return self.config.get(key, default)

    def set_config(self, key, value):
        self.config[key] = value

    def set_pihole_host(self, host):
        host = host.strip().rstrip('/')
        if host != self.config['pihole_host']:
            self.config.update(pihole_host=host, pihole_last_cursor=0,
                               pihole_source_generation=self.config['pihole_source_generation'] + 1)
        return self.config['pihole_source_generation']

    def insert_pihole_batch(self, logs, cursor, *, expected_host, expected_generation):
        self.calls += 1
        if self.calls == self.fail_at:
            raise RuntimeError('synthetic storage failure')
        if (expected_host != self.config['pihole_host'] or
                expected_generation != self.config['pihole_source_generation']):
            return None
        self.commits.append(deepcopy(logs))
        self.config['pihole_last_cursor'] = max(self.config['pihole_last_cursor'], cursor)
        return self.config['pihole_last_cursor']


@pytest.fixture
def collector(monkeypatch):
    for name in ('PIHOLE_HOST', 'PIHOLE_PASSWORD', 'PIHOLE_ENABLED',
                 'PIHOLE_POLL_INTERVAL', 'PIHOLE_DNS_SERVER'):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(pihole_api, 'decrypt_api_key', lambda value: value)
    poller = PiHolePoller(FakeDatabase())
    poller._api_get = Mock(return_value={'queries': []})
    yield poller
    poller.stop_polling()


def eventually(check, timeout=2):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if check():
            return
        time.sleep(0.005)
    assert check()


def test_api_settings_refresh_never_starts_collector(collector):
    collector._start_worker = Mock()
    collector.reload_config(restart_polling=False)
    collector._start_worker.assert_not_called()
    assert collector.enabled
    assert collector._poll_thread is None


def test_transient_reload_failure_retries_without_another_settings_save(collector):
    collector.RELOAD_RETRY_SECONDS = 0.01
    original = collector._db.get_config
    failure = [True]

    def read(key, default=None):
        if failure[0] and key == 'pihole_source_generation':
            failure[0] = False
            raise RuntimeError('synthetic transient database read')
        return original(key, default)

    collector._db.get_config = read
    collector.reload_config()
    eventually(lambda: collector._api_get.call_count == 1)
    assert collector._reload_pending is False
    assert collector._reload_retry is None


def test_stopping_cancels_pending_reload_retry(collector):
    collector.RELOAD_RETRY_SECONDS = 1
    collector._db.get_config = Mock(side_effect=RuntimeError('synthetic unavailable database'))
    collector.reload_config()
    assert collector._reload_retry is not None
    collector.stop_polling()
    assert collector._reload_retry is None
    assert collector._poll_thread is None
    collector._api_get.assert_not_called()


def test_null_reply_and_whitespace_config_are_imported_without_false_protocol(collector):
    collector._db.config['pihole_host'] = '  https://dns-api.example.invalid/  '
    collector.reload_config(restart_polling=False)
    assert collector.host == 'https://dns-api.example.invalid'
    collector._db.config['pihole_host'] = collector.host
    collector._api_get.return_value = {'queries': [query(1, reply=None)]}
    assert collector.poll(stop_event=threading.Event()) is True
    assert collector._db.commits[0][0]['protocol'] is None
    assert collector._db.commits[0][0]['dns_answer'] is None


def test_settings_route_uses_atomic_host_reset_and_settings_only_reload(collector, monkeypatch):
    signal = Mock()
    monkeypatch.setitem(sys.modules, 'deps', SimpleNamespace(
        enricher_db=collector._db, signal_receiver=signal, pihole_poller=collector))
    path = Path(__file__).parents[1] / 'routes' / 'pihole.py'
    spec = importlib.util.spec_from_file_location('synthetic_pihole_routes', path)
    route = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(route)
    collector.reload_config = Mock()
    route.update_pihole_settings({'host': 'https://new.example.invalid/',
                                  'dns_server': '2001:db8::53'})
    assert collector._db.config['pihole_source_generation'] == 1
    assert collector._db.config['pihole_dns_server'] == '2001:db8::53'
    collector.reload_config.assert_called_once_with(restart_polling=False)
    signal.assert_called_once()
    with pytest.raises(route.HTTPException):
        route.update_pihole_settings({'dns_server': 'proxy.example.invalid'})


def test_concurrent_polls_have_one_importer(collector):
    entered, release = threading.Event(), threading.Event()

    def fetch(*args, **kwargs):
        entered.set()
        assert release.wait(2)
        return {'queries': [query(1)]}

    collector._api_get = Mock(side_effect=fetch)
    worker = threading.Thread(target=collector.poll)
    worker.start()
    try:
        assert entered.wait(1)
        assert collector.poll() is False
        assert collector._api_get.call_count == 1
    finally:
        release.set()
        worker.join(2)
    assert not worker.is_alive()
    assert collector._db.calls == 1


def test_reload_cancels_old_generation_before_applying_host_and_starts_one_worker(collector):
    entered, release, fetched_new = threading.Event(), threading.Event(), threading.Event()
    active = 0
    peak = 0
    guard = threading.Lock()
    hosts = []

    def fetch(*args, **kwargs):
        nonlocal active, peak
        with guard:
            active += 1
            peak = max(peak, active)
        try:
            hosts.append(collector.host)
            if len(hosts) == 1:
                entered.set()
                assert release.wait(2)
                return {'queries': [query(1)]}
            fetched_new.set()
            return {'queries': [query(2)]}
        finally:
            with guard:
                active -= 1

    collector._api_get = Mock(side_effect=fetch)
    collector.start_polling()
    try:
        assert entered.wait(1)
        old_thread, old_event = collector._poll_thread, collector._poll_stop
        collector._db.set_pihole_host('https://new.example.invalid')
        collector.reload_config()
        collector.reload_config()
        assert collector._poll_thread is old_thread
        assert collector._poll_stop is old_event and old_event.is_set()
        assert collector.host == 'https://dns-api.example.invalid'
        release.set()
        assert fetched_new.wait(2)
        eventually(lambda: collector._last_cursor == 2)
        assert peak == 1
        assert [row['raw_log'] for batch in collector._db.commits for row in batch] == [
            pihole_api.json.dumps(query(2))]
        assert hosts == ['https://dns-api.example.invalid', 'https://new.example.invalid']
        assert collector._poll_stop is not old_event
    finally:
        release.set()


def test_repeated_starts_never_overlap_a_blocked_old_worker(collector):
    entered, release = threading.Event(), threading.Event()

    def fetch(*args, **kwargs):
        if not entered.is_set():
            entered.set()
            assert release.wait(2)
        return {'queries': []}

    collector._api_get = Mock(side_effect=fetch)
    collector.start_polling()
    try:
        assert entered.wait(1)
        thread = collector._poll_thread
        for _ in range(20):
            collector.start_polling()
            assert collector._poll_thread is thread
        assert collector._api_get.call_count == 1
        release.set()
        eventually(lambda: collector._api_get.call_count == 2)
    finally:
        release.set()


def test_chunks_commit_ascending_ids_and_failure_never_skips_uncommitted_rows(collector):
    collector.INSERT_BATCH_SIZE = 3
    collector._api_get.return_value = {'queries': [query(i) for i in range(8, 0, -1)]}
    collector._db.fail_at = 2
    assert collector.poll() is False
    assert collector._last_cursor == collector._db.config['pihole_last_cursor'] == 3
    assert len(collector._db.commits) == 1
    collector._db.fail_at = None
    assert collector.poll() is True
    ids = [pihole_api.json.loads(row['raw_log'])['id']
           for batch in collector._db.commits for row in batch]
    assert ids == list(range(1, 9))
    assert [len(batch) for batch in collector._db.commits] == [3, 3, 2]
    assert collector._last_cursor == 8


def test_stale_db_generation_never_advances_local_cursor(collector):
    collector._api_get.return_value = {'queries': [query(1)]}
    collector._db.config['pihole_source_generation'] = 1
    assert collector.poll() is False
    assert collector._last_cursor == 0
    assert not collector._db.commits


def test_none_imports_queries_without_any_dns_or_network_enrichment(collector, monkeypatch):
    collector._api_get.return_value = {'queries': [query(i) for i in range(1, 101)]}
    collector._enricher = SimpleNamespace(enrich=Mock())
    lookup, udp = Mock(), Mock()
    monkeypatch.setattr(socket, 'getaddrinfo', lookup)
    collector._udp_dns_query = udp
    assert collector.poll() is True
    lookup.assert_not_called()
    udp.assert_not_called()
    collector._enricher.enrich.assert_not_called()
    assert sum(map(len, collector._db.commits)) == 100


def test_one_endpoint_lookup_for_one_hundred_distinct_enrichment_domains(collector, monkeypatch):
    collector.enrichment_enabled = 'both'
    lookup = Mock(return_value=[(socket.AF_INET, socket.SOCK_DGRAM, 17, '', ('192.0.2.53', 53))])
    monkeypatch.setattr(socket, 'getaddrinfo', lookup)
    collector._udp_dns_query = Mock(return_value='203.0.113.20')
    records = [query(i) for i in range(1, 101)]
    resolved = collector._batch_resolve(records)
    assert len(resolved) == 100
    assert lookup.call_count == 1
    assert collector._udp_dns_query.call_count == 100
    collector._batch_resolve(records)
    assert lookup.call_count == 1
    assert collector._udp_dns_query.call_count == 100


def test_explicit_numeric_dns_endpoint_does_not_resolve_api_proxy(collector, monkeypatch):
    collector.enrichment_enabled = 'both'
    collector.dns_server = '2001:db8::53'
    lookup = Mock(side_effect=AssertionError('numeric resolver must not use endpoint DNS'))
    monkeypatch.setattr(socket, 'getaddrinfo', lookup)
    collector._udp_dns_query = Mock(return_value='203.0.113.20')
    collector._batch_resolve([query(1)])
    assert collector._udp_dns_query.call_args.args[:2] == ('2001:db8::53', 53)
    lookup.assert_not_called()


def test_dns_budget_limits_active_queries_without_dropping_imported_events(collector):
    collector.enrichment_enabled = 'both'
    collector.dns_server = '192.0.2.53'
    collector.DNS_QUERY_LIMIT = 3
    collector.INSERT_BATCH_SIZE = 5
    collector._udp_dns_query = Mock(return_value='203.0.113.20')
    collector._api_get.return_value = {'queries': [query(i) for i in range(1, 18)]}
    assert collector.poll() is True
    assert collector._udp_dns_query.call_count == 3
    assert sum(map(len, collector._db.commits)) == 17
    assert collector._last_cursor == 17


def test_original_answer_is_retained_and_current_lookup_is_not_original_evidence(collector, monkeypatch):
    collector.enrichment_enabled = 'both'
    original = query(1, reply={'type': 'IP', 'time': 0.01, 'ip': '203.0.113.10'}, protocol='TCP')
    collector._resolve_domain = Mock(return_value='203.0.113.20')
    assert collector._batch_resolve([original]) == {}
    collector._resolve_domain.assert_not_called()
    # Reserved fixtures simulate remote classification without using real public addresses.
    monkeypatch.setattr(pihole_api, '_is_private', lambda address: False)
    mapped = collector._map_query(original, {(original['domain'], 'A'): '203.0.113.20'})
    assert mapped['dns_answer'] == mapped['dst_ip'] == '203.0.113.10'
    assert mapped['protocol'] == 'TCP'
    no_answer = query(2)
    mapped = collector._map_query(no_answer, {(no_answer['domain'], 'A'): '203.0.113.20'})
    assert mapped['dns_answer'] is None
    assert mapped['dst_ip'] == mapped['remote_ip'] == '203.0.113.20'
    assert mapped['protocol'] is None


@pytest.mark.parametrize('answer', ['not-an-ip.example.invalid', '2001:db8::1', ''])
def test_answer_validation_never_uses_wrong_family_or_upstream_address(collector, answer):
    record = query(1, answer=answer, upstream='192.0.2.53', protocol='unknown')
    assert collector._original_answer(record) is None
    assert collector._map_query(record, {})['dns_answer'] is None


def test_endpoint_resolver_wait_is_bounded_and_only_one_lookup_can_be_inflight(monkeypatch):
    entered, release = threading.Event(), threading.Event()

    def lookup(*args, **kwargs):
        entered.set()
        assert release.wait(2)
        return [(socket.AF_INET, socket.SOCK_DGRAM, 17, '', ('192.0.2.53', 53))]

    call = Mock(side_effect=lookup)
    monkeypatch.setattr(socket, 'getaddrinfo', call)
    resolver = _EndpointResolver()
    try:
        started = time.monotonic()
        assert resolver.resolve('dns-api.example.invalid', timeout=0.03) is None
        assert entered.is_set()
        assert time.monotonic() - started < 0.3
        for _ in range(5):
            assert resolver.resolve('dns-api.example.invalid', timeout=0.005) is None
        assert resolver.resolve('other.example.invalid', timeout=0.005) is None
        assert call.call_count == 1
        release.set()
        eventually(lambda: resolver.resolve('dns-api.example.invalid', timeout=0.03) == '192.0.2.53')
        assert call.call_count == 1
    finally:
        release.set()


def test_udp_query_uses_numeric_endpoint_and_validates_response_identity(monkeypatch):
    class Socket:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def settimeout(self, value): pass
        def connect(self, endpoint): self.endpoint = endpoint
        def send(self, packet): self.packet = packet
        def recv(self, length):
            return (self.packet[:2] + struct.pack('!HHHHH', 0x8180, 1, 1, 0, 0)
                    + self.packet[12:] + b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4)
                    + ipaddress.ip_address('203.0.113.20').packed)

    sock = Socket()
    monkeypatch.setattr(socket, 'socket', Mock(return_value=sock))
    monkeypatch.setattr(socket, 'getaddrinfo', Mock(side_effect=AssertionError('unexpected DNS')))
    assert PiHolePoller._udp_dns_query('192.0.2.53', 53, 'answer.example.invalid', 1) == '203.0.113.20'
    original = sock.recv
    sock.recv = lambda length: b'\x00\x00' + original(length)[2:]
    monkeypatch.setattr('random.randint', lambda *args: 42)
    assert PiHolePoller._udp_dns_query('192.0.2.53', 53, 'answer.example.invalid', 1) is None
