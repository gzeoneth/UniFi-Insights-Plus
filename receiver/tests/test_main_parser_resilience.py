"""Tests for SyslogReceiver._handle_message resilience to malformed packets.

Security context: UDP/514 is bound to all interfaces (`::`) and accepts
packets from any source. Before this fix, an unhandled exception in
parse_log or enricher.enrich would crash the receiver thread, allowing a
one-packet remote DoS. The handler now wraps the critical section in
try/except and rate-limits the warning log so a sustained attack cannot
fill the disk with warnings. An enrich() failure keeps the parsed row and
stores it un-enriched.

Findings addressed:
- C4 (Gemini VULN-001) — malformed packet → receiver thread crash
"""

from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def receiver(monkeypatch):
    """Build a SyslogReceiver with heavy deps stubbed.

    Mirrors test_main_retention_scheduler.py's main_module fixture: deps.py
    runs wait_for_postgres() at import time, which blocks for 30 retries when
    no DB is reachable. We stub the offending modules in sys.modules before
    `import main`. We keep the REAL `parsers` module so test_malformed_timestamp
    exercises the actual datetime() crash path.
    """
    import sys
    for name in ('enrichment', 'backfill', 'blacklist',
                 'unifi_api', 'pihole_api', 'routes.auth', 'deps', 'db'):
        monkeypatch.setitem(sys.modules, name, MagicMock())

    monkeypatch.delitem(sys.modules, 'main', raising=False)
    from main import SyslogReceiver

    db = MagicMock()
    db.get_config = MagicMock(return_value=True)
    enricher = MagicMock()
    enricher.enrich = MagicMock(side_effect=lambda p: p)

    r = SyslogReceiver(db, enricher)
    r._disabled_log_types = set()
    return r


class TestHandleMessageResilience:
    """Regression coverage for the C4 / VULN-001 one-packet remote DoS.

    Each test forces an exception in a different layer of the parse pipeline
    (real parser timestamp ValueError, mocked parse_log, mocked enricher.enrich)
    and asserts the receiver swallows the exception, increments the matching
    counter (failed, parse_exceptions or enrich_exceptions), rate-limits its
    WARNING log, and keeps processing subsequent packets.
    """

    def test_malformed_timestamp_does_not_raise(self, receiver):
        # "Feb 99 99:99:99 host body" — passes the SYSLOG_HEADER regex but
        # the components are out of range. Before the fix, datetime() raised
        # ValueError and that propagated up out of _handle_message.
        data = b"Feb 99 99:99:99 host kernel: anything"
        # Must not raise.
        receiver._handle_message(data, ('1.2.3.4', 1234))
        # The malformed packet should be counted as 'failed' (parse_log
        # returns None when the timestamp is unparseable), not as an exception.
        assert receiver.stats['failed'] == 1
        assert receiver.stats['parse_exceptions'] == 0

    def test_parse_log_raising_is_swallowed(self, receiver, monkeypatch):
        # Defense-in-depth: even if parse_log itself raises an unexpected
        # exception (e.g. future regression in a downstream parser), the
        # handler must not propagate.
        import main as main_module
        monkeypatch.setattr(main_module, 'parse_log',
                            MagicMock(side_effect=RuntimeError("simulated parser bug")))

        data = b"Feb  8 16:43:49 host kernel: anything"
        receiver._handle_message(data, ('1.2.3.4', 1234))

        assert receiver.stats['parse_exceptions'] == 1
        # Receiver state is otherwise normal — batch is unaffected.
        assert receiver.batch == []

    def test_enrich_exception_keeps_row(self, receiver):
        # If enricher.enrich raises, the packet must not be dropped: the parsed
        # row is batched un-enriched and counted as enrich_exceptions, not
        # parse_exceptions.
        def _partial_then_raise(p):
            p['country'] = 'XX'  # partial mutation must not leak into the row
            raise RuntimeError("simulated enricher bug")

        receiver.enricher.enrich = MagicMock(side_effect=_partial_then_raise)

        # Use a syslog header the real parser accepts so we reach enrich().
        data = b"Feb  8 16:43:49 host kernel: [WAN_IN-B] IN=ppp0 OUT=br20 SRC=1.2.3.4 DST=10.0.0.5 PROTO=TCP SPT=1234 DPT=80"
        receiver._handle_message(data, ('1.2.3.4', 1234))

        assert receiver.stats['enrich_exceptions'] == 1
        assert receiver.stats['parse_exceptions'] == 0
        assert receiver.stats['parsed'] == 1
        assert len(receiver.batch) == 1
        row = receiver.batch[0]
        assert row['src_ip'] == '1.2.3.4'
        assert row['dst_ip'] == '10.0.0.5'
        assert 'country' not in row
        assert 'remote_ip' not in row

    def test_burst_of_bad_packets_logs_bounded_warnings(self, receiver, monkeypatch, caplog):
        # An attacker sending 1000 malformed packets must not produce 1000
        # WARNING log entries (which would fill the disk).
        import main as main_module
        monkeypatch.setattr(main_module, 'parse_log',
                            MagicMock(side_effect=RuntimeError("boom")))

        import logging
        with caplog.at_level(logging.WARNING, logger='receiver'):
            for _ in range(1000):
                receiver._handle_message(b"any payload", ('1.2.3.4', 1234))

        assert receiver.stats['parse_exceptions'] == 1000
        # Rate-limited: the 1st and every 100th (1, 100, 200, ..., 1000).
        warning_records = [r for r in caplog.records
                           if r.levelno >= logging.WARNING and r.name == 'receiver']
        assert len(warning_records) == 11, \
            f"expected 11 rate-limited warnings, got {len(warning_records)}"

    def test_normal_packet_after_bad_packet_still_works(self, receiver):
        # Send a malformed packet, then a normal one. State must not be
        # corrupted; the normal packet should be parsed and batched.
        bad = b"Feb 99 99:99:99 host kernel: junk"
        good = b"Feb  8 16:43:49 host kernel: [WAN_IN-B] IN=ppp0 OUT=br20 SRC=1.2.3.4 DST=10.0.0.5 PROTO=TCP SPT=1234 DPT=80"

        receiver._handle_message(bad, ('attacker', 1234))
        receiver._handle_message(good, ('gateway', 514))

        # The good packet should have been parsed and added to the batch.
        assert receiver.stats['failed'] == 1
        assert receiver.stats['parsed'] == 1
        assert len(receiver.batch) == 1

    def test_heartbeat_includes_exception_counters(self, receiver, caplog):
        import logging
        receiver.stats.update({'failed': 5, 'parse_exceptions': 2, 'enrich_exceptions': 3})
        receiver.last_heartbeat = 0  # force the heartbeat to fire

        with caplog.at_level(logging.DEBUG, logger='receiver'):
            receiver._maybe_log_heartbeat()

        heartbeat = [r.getMessage() for r in caplog.records if 'Heartbeat' in r.getMessage()]
        assert len(heartbeat) == 1
        assert 'failed=5' in heartbeat[0]
        assert 'parse_exc=2' in heartbeat[0]
        assert 'enrich_exc=3' in heartbeat[0]
