"""Tests for runtime network identity gating in main.py.

Covers:
- _use_log_identity_detection()
- _refresh_network_identity_from_logs(), including the reload of learned
  identity into the running receiver (parsers + enricher)

main.py imports routes.auth which triggers deps.py's PostgreSQL init.
We stub all heavy transitive dependencies before importing the functions
under test.
"""

import sys
from unittest.mock import MagicMock

import pytest

# Stub heavy transitive dependencies of main.py before import.
# Order matters: deps must be stubbed before routes.auth.
_stubs = (
    'schedule', 'enrichment', 'backfill', 'blacklist',
    'deps', 'routes', 'routes.auth',
)
_originals = {}
for _mod in _stubs:
    if _mod in sys.modules:
        _originals[_mod] = sys.modules[_mod]
    else:
        sys.modules[_mod] = MagicMock()

# Now safe to import the functions under test
from main import _use_log_identity_detection, _refresh_network_identity_from_logs

# Restore original module state so stubs don't leak to other test files
for _mod, _orig in _originals.items():
    sys.modules[_mod] = _orig
for _mod in _stubs:
    if _mod not in _originals:
        sys.modules.pop(_mod, None)


class TestUseLogIdentityDetection:

    def test_returns_true_when_unifi_disabled(self):
        db = MagicMock()
        db.get_config.return_value = False
        assert _use_log_identity_detection(db) is True

    def test_returns_false_when_unifi_enabled(self):
        db = MagicMock()
        db.get_config.return_value = True
        assert _use_log_identity_detection(db) is False

    def test_returns_true_when_config_missing(self):
        db = MagicMock()
        db.get_config.return_value = None
        assert _use_log_identity_detection(db) is True


class TestRefreshNetworkIdentityFromLogs:

    def test_noop_when_unifi_enabled(self):
        db = MagicMock()
        db.get_config.return_value = True
        _refresh_network_identity_from_logs(db)
        db.detect_wan_ip.assert_not_called()
        db.detect_gateway_ips.assert_not_called()

    def test_calls_detection_when_unifi_disabled(self):
        db = MagicMock()
        db.get_config.return_value = False
        _refresh_network_identity_from_logs(db)
        db.detect_wan_ip.assert_called_once()
        db.detect_gateway_ips.assert_called_once()

    def test_gate_failure_does_not_propagate(self):
        """unifi_enabled read failing (DB down) is logged, never raised."""
        db = MagicMock()
        db.get_config.side_effect = Exception("db down")
        _refresh_network_identity_from_logs(db)
        db.detect_wan_ip.assert_not_called()
        db.detect_gateway_ips.assert_not_called()

    def test_gateway_still_runs_when_wan_detection_fails(self):
        db = MagicMock()
        db.get_config.return_value = False
        db.detect_wan_ip.side_effect = Exception("WAN failed")
        _refresh_network_identity_from_logs(db)
        db.detect_gateway_ips.assert_called_once()


class TestRefreshReloadsLearnedIdentity:
    """Identity persisted by a detection run is pushed into parsers/enricher."""

    @pytest.fixture
    def parsers_mock(self, monkeypatch):
        mock = MagicMock()
        monkeypatch.setitem(_refresh_network_identity_from_logs.__globals__, 'parsers', mock)
        return mock

    @staticmethod
    def _db(config, wan_after=None, gateways_after=None):
        db = MagicMock()
        db.get_config.side_effect = lambda key, default=None: config.get(key, default)

        def detect_wan():
            if wan_after is not None:
                config['wan_ip_by_iface'] = wan_after

        def detect_gateways():
            if gateways_after is not None:
                config['gateway_ips'] = gateways_after

        db.detect_wan_ip.side_effect = detect_wan
        db.detect_gateway_ips.side_effect = detect_gateways
        return db

    def test_changed_wan_identity_reloads_parsers_and_enricher(self, parsers_mock):
        db = self._db({'wan_ip_by_iface': {'eth8': '1.1.1.1'}, 'gateway_ips': ['10.0.0.1']},
                      wan_after={'eth8': '2.2.2.2'})
        enricher = MagicMock()
        _refresh_network_identity_from_logs(db, enricher)
        parsers_mock.reload_config_from_db.assert_called_once_with(db)
        enricher.reload_config.assert_called_once()

    def test_changed_gateways_reload_parsers_and_enricher(self, parsers_mock):
        db = self._db({'wan_ip_by_iface': {'eth8': '1.1.1.1'}, 'gateway_ips': ['10.0.0.1']},
                      gateways_after=['10.0.0.1', '10.0.50.1'])
        enricher = MagicMock()
        _refresh_network_identity_from_logs(db, enricher)
        parsers_mock.reload_config_from_db.assert_called_once_with(db)
        enricher.reload_config.assert_called_once()

    def test_unchanged_identity_reloads_nothing(self, parsers_mock):
        db = self._db({'wan_ip_by_iface': {'eth8': '1.1.1.1'}, 'gateway_ips': ['10.0.0.1']})
        enricher = MagicMock()
        _refresh_network_identity_from_logs(db, enricher)
        parsers_mock.reload_config_from_db.assert_not_called()
        enricher.reload_config.assert_not_called()

    def test_changed_identity_without_enricher_reloads_parsers(self, parsers_mock):
        """Startup passes no enricher (it is built later and preloads from the DB)."""
        db = self._db({}, wan_after={'eth8': '2.2.2.2'})
        _refresh_network_identity_from_logs(db)
        parsers_mock.reload_config_from_db.assert_called_once_with(db)
