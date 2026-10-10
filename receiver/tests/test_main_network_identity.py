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
from types import SimpleNamespace
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


def _unifi(enabled):
    return SimpleNamespace(enabled=enabled)


class TestUseLogIdentityDetection:
    """One source: the running integration's effective enabled flag (env
    overrides, host and credentials included), not the raw DB flag."""

    def test_returns_true_when_unifi_disabled(self):
        assert _use_log_identity_detection(_unifi(False)) is True

    def test_returns_false_when_unifi_enabled(self):
        assert _use_log_identity_detection(_unifi(True)) is False

    def test_db_flag_is_not_consulted(self):
        """unifi_enabled left on in the DB but the integration cannot poll."""
        unifi_api = MagicMock()
        unifi_api.enabled = False
        unifi_api._db.get_config.return_value = True
        assert _use_log_identity_detection(unifi_api) is True


class TestRefreshNetworkIdentityFromLogs:

    def test_noop_when_unifi_enabled(self):
        db = MagicMock()
        _refresh_network_identity_from_logs(db, _unifi(True))
        db.detect_wan_ip.assert_not_called()
        db.detect_gateway_ips.assert_not_called()

    def test_calls_detection_when_unifi_disabled(self):
        db = MagicMock()
        _refresh_network_identity_from_logs(db, _unifi(False))
        db.detect_wan_ip.assert_called_once()
        db.detect_gateway_ips.assert_called_once()

    def test_db_errors_do_not_propagate(self):
        """Detector and config-read failures are logged, never raised."""
        db = MagicMock()
        db.get_config.side_effect = Exception("db down")
        db.detect_wan_ip.side_effect = Exception("db down")
        db.detect_gateway_ips.side_effect = Exception("db down")
        _refresh_network_identity_from_logs(db, _unifi(False))

    def test_gateway_still_runs_when_wan_detection_fails(self):
        db = MagicMock()
        db.detect_wan_ip.side_effect = Exception("WAN failed")
        _refresh_network_identity_from_logs(db, _unifi(False))
        db.detect_gateway_ips.assert_called_once()


class TestRefreshReloadsLearnedIdentity:
    """Identity persisted by a detection run is pushed into parsers/enricher.

    The receiver remembers the identity tuple it last loaded
    (_loaded_identity); a run reloads when the persisted tuple differs, and
    a failed read or reload leaves it unchanged so the next run retries.
    """

    KEYS = ('wan_ip_by_iface', 'wan_ips', 'wan_ip', 'gateway_ips')
    BASE = {'wan_ip_by_iface': {'eth8': '1.1.1.1'}, 'wan_ips': ['1.1.1.1'],
            'wan_ip': '1.1.1.1', 'gateway_ips': ['10.0.0.1']}

    @pytest.fixture
    def parsers_mock(self, monkeypatch):
        mock = MagicMock()
        monkeypatch.setitem(_refresh_network_identity_from_logs.__globals__, 'parsers', mock)
        return mock

    @pytest.fixture
    def loaded(self, monkeypatch):
        """Set the receiver's last-loaded identity; returns a reader for it."""
        g = _refresh_network_identity_from_logs.__globals__

        def set_loaded(config):
            value = None if config is None else tuple(config.get(k) for k in self.KEYS)
            monkeypatch.setitem(g, '_loaded_identity', value)
        set_loaded.current = lambda: g['_loaded_identity']
        return set_loaded

    @staticmethod
    def _db(config, **after):
        """Config-backed db; the WAN detector applies `after` to the config."""
        db = MagicMock()
        db.get_config.side_effect = lambda key, default=None: config.get(key, default)
        db.detect_wan_ip.side_effect = lambda: config.update(after)
        return db

    def test_unchanged_identity_reloads_nothing(self, parsers_mock, loaded):
        config = dict(self.BASE)
        loaded(config)
        enricher = MagicMock()
        _refresh_network_identity_from_logs(self._db(config), _unifi(False), enricher)
        parsers_mock.reload_config_from_db.assert_not_called()
        enricher.reload_config.assert_not_called()

    def test_changed_wan_map_reloads_parsers_and_enricher(self, parsers_mock, loaded):
        config = dict(self.BASE)
        loaded(config)
        db = self._db(config, wan_ip_by_iface={'eth8': '2.2.2.2'})
        enricher = MagicMock()
        _refresh_network_identity_from_logs(db, _unifi(False), enricher)
        parsers_mock.reload_config_from_db.assert_called_once_with(db)
        enricher.reload_config.assert_called_once()
        assert loaded.current()[0] == {'eth8': '2.2.2.2'}

    def test_wan_ip_only_change_reloads(self, parsers_mock, loaded):
        """detect_wan_ip can rewrite wan_ip/wan_ips without changing the map."""
        config = dict(self.BASE)
        loaded(config)
        db = self._db(config, wan_ip='3.3.3.3', wan_ips=['3.3.3.3'])
        enricher = MagicMock()
        _refresh_network_identity_from_logs(db, _unifi(False), enricher)
        parsers_mock.reload_config_from_db.assert_called_once_with(db)
        enricher.reload_config.assert_called_once()

    def test_changed_gateways_reload_parsers_and_enricher(self, parsers_mock, loaded):
        config = dict(self.BASE)
        loaded(config)
        db = MagicMock()
        db.get_config.side_effect = lambda key, default=None: config.get(key, default)
        db.detect_gateway_ips.side_effect = lambda: config.update(gateway_ips=['10.0.0.1', '10.0.50.1'])
        enricher = MagicMock()
        _refresh_network_identity_from_logs(db, _unifi(False), enricher)
        parsers_mock.reload_config_from_db.assert_called_once_with(db)
        enricher.reload_config.assert_called_once()

    def test_first_run_reloads_parsers_without_enricher(self, parsers_mock, loaded):
        """Startup: nothing loaded yet and no enricher (it is built later and
        preloads from the DB)."""
        loaded(None)
        db = self._db(dict(self.BASE))
        _refresh_network_identity_from_logs(db, _unifi(False))
        parsers_mock.reload_config_from_db.assert_called_once_with(db)

    def test_failed_read_retries_on_next_run(self, parsers_mock, loaded):
        config = dict(self.BASE)
        loaded(config)
        db = self._db(config, wan_ip_by_iface={'eth8': '2.2.2.2'})
        reads = {'fail': True}
        real_get = db.get_config.side_effect

        def get_config(key, default=None):
            if reads['fail']:
                raise Exception('db down')
            return real_get(key, default)

        db.get_config.side_effect = get_config
        _refresh_network_identity_from_logs(db, _unifi(False))
        parsers_mock.reload_config_from_db.assert_not_called()

        reads['fail'] = False  # same data, DB back
        _refresh_network_identity_from_logs(db, _unifi(False))
        parsers_mock.reload_config_from_db.assert_called_once_with(db)

    def test_failed_reload_retries_on_next_run(self, parsers_mock, loaded):
        config = dict(self.BASE)
        loaded(config)
        db = self._db(config, wan_ip_by_iface={'eth8': '2.2.2.2'})
        before = loaded.current()
        parsers_mock.reload_config_from_db.side_effect = [Exception('db down'), None]

        _refresh_network_identity_from_logs(db, _unifi(False))
        assert loaded.current() == before

        _refresh_network_identity_from_logs(db, _unifi(False))
        assert parsers_mock.reload_config_from_db.call_count == 2
        assert loaded.current()[0] == {'eth8': '2.2.2.2'}
