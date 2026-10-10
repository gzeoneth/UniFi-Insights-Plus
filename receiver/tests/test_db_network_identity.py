"""Tests for shared network identity extraction and persistence helpers.

Covers:
- extract_network_identity_from_net_config()
- Database.persist_network_identity()
- recent_firewall_cutoff() and the windowed detection/candidate queries
- Database.detect_wan_ip() / detect_gateway_ips() merge persistence (#103)
"""

from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from db import Database, recent_firewall_cutoff
from unifi_api import UniFiAPI


# ── Extractor tests ─────────────────────────────────────────────────────────

class TestExtractNetworkIdentity:
    """Tests for UniFiAPI.extract_network_identity_from_net_config()."""

    def test_extracts_wan_ip_by_iface(self):
        net_config = {
            'wan_interfaces': [
                {'physical_interface': 'eth0', 'wan_ip': '1.2.3.4'},
                {'physical_interface': 'eth1', 'wan_ip': '5.6.7.8'},
            ],
            'networks': [],
        }
        wan_ip_by_iface, _ = UniFiAPI.extract_network_identity_from_net_config(net_config)
        assert wan_ip_by_iface == {'eth0': '1.2.3.4', 'eth1': '5.6.7.8'}

    def test_skips_wan_without_physical_interface(self):
        net_config = {
            'wan_interfaces': [
                {'physical_interface': '', 'wan_ip': '1.2.3.4'},
                {'wan_ip': '5.6.7.8'},
            ],
            'networks': [],
        }
        wan_ip_by_iface, _ = UniFiAPI.extract_network_identity_from_net_config(net_config)
        assert wan_ip_by_iface == {}

    def test_skips_wan_without_ip(self):
        net_config = {
            'wan_interfaces': [
                {'physical_interface': 'eth0', 'wan_ip': None},
                {'physical_interface': 'eth1'},
            ],
            'networks': [],
        }
        wan_ip_by_iface, _ = UniFiAPI.extract_network_identity_from_net_config(net_config)
        assert wan_ip_by_iface == {}

    def test_extracts_gateway_ip_vlans(self):
        net_config = {
            'wan_interfaces': [],
            'networks': [
                {'ip_subnet': '192.168.1.1/24', 'vlan': 1, 'name': 'LAN'},
                {'ip_subnet': '10.0.50.1/24', 'vlan': 50, 'name': 'IoT'},
            ],
        }
        _, gateway_ip_vlans = UniFiAPI.extract_network_identity_from_net_config(net_config)
        assert gateway_ip_vlans == {
            '192.168.1.1': {'vlan': 1, 'name': 'LAN'},
            '10.0.50.1': {'vlan': 50, 'name': 'IoT'},
        }

    def test_skips_network_without_ip_subnet(self):
        net_config = {
            'wan_interfaces': [],
            'networks': [
                {'ip_subnet': '', 'vlan': 1, 'name': 'LAN'},
                {'vlan': 2, 'name': 'VLAN2'},
            ],
        }
        _, gateway_ip_vlans = UniFiAPI.extract_network_identity_from_net_config(net_config)
        assert gateway_ip_vlans == {}

    def test_empty_net_config(self):
        wan_ip_by_iface, gateway_ip_vlans = UniFiAPI.extract_network_identity_from_net_config({})
        assert wan_ip_by_iface == {}
        assert gateway_ip_vlans == {}

    def test_mixed_valid_and_invalid(self):
        net_config = {
            'wan_interfaces': [
                {'physical_interface': 'eth0', 'wan_ip': '1.2.3.4'},
                {'physical_interface': '', 'wan_ip': '9.9.9.9'},
                {'physical_interface': 'eth2'},
            ],
            'networks': [
                {'ip_subnet': '10.0.0.1/24', 'vlan': None, 'name': 'Default'},
                {'ip_subnet': '', 'vlan': 5, 'name': 'Empty'},
            ],
        }
        wan_ip_by_iface, gateway_ip_vlans = UniFiAPI.extract_network_identity_from_net_config(net_config)
        assert wan_ip_by_iface == {'eth0': '1.2.3.4'}
        assert gateway_ip_vlans == {'10.0.0.1': {'vlan': None, 'name': 'Default'}}


# ── Persistence tests ───────────────────────────────────────────────────────

class TestPersistNetworkIdentity:
    """Tests for Database.persist_network_identity()."""

    @pytest.fixture()
    def mock_db(self):
        db = MagicMock()
        db.get_config.return_value = ['eth0', 'eth1']
        return db

    def test_persists_wan_identity(self, mock_db):
        Database.persist_network_identity(
            mock_db,
            wan_ip_by_iface={'eth0': '1.2.3.4', 'eth1': '5.6.7.8'},
        )
        mock_db.set_config.assert_any_call('wan_ip_by_iface', {'eth0': '1.2.3.4', 'eth1': '5.6.7.8'})
        mock_db.set_config.assert_any_call('wan_ips', ['1.2.3.4', '5.6.7.8'])
        mock_db.set_config.assert_any_call('wan_ip', '1.2.3.4')

    def test_wan_ips_ordered_by_wan_interfaces_config(self, mock_db):
        """wan_ips must follow the configured wan_interfaces order."""
        from db import Database
        mock_db.get_config.return_value = ['eth1', 'eth0']
        Database.persist_network_identity(
            mock_db,
            wan_ip_by_iface={'eth0': '1.1.1.1', 'eth1': '2.2.2.2'},
        )
        mock_db.set_config.assert_any_call('wan_ips', ['2.2.2.2', '1.1.1.1'])
        mock_db.set_config.assert_any_call('wan_ip', '2.2.2.2')

    def test_persists_gateway_identity(self, mock_db):
        Database.persist_network_identity(
            mock_db,
            gateway_ip_vlans={'10.0.0.1': {'vlan': 1, 'name': 'LAN'}},
        )
        mock_db.set_config.assert_any_call('gateway_ip_vlans', {'10.0.0.1': {'vlan': 1, 'name': 'LAN'}})
        mock_db.set_config.assert_any_call('gateway_ips', ['10.0.0.1'])

    def test_empty_wan_ip_by_iface_does_not_clear(self, mock_db):
        """Empty wan_ip_by_iface must not overwrite last-known-good values."""
        Database.persist_network_identity(mock_db, wan_ip_by_iface={})
        # set_config should NOT be called for WAN keys
        for c in mock_db.set_config.call_args_list:
            assert c[0][0] not in ('wan_ip_by_iface', 'wan_ips', 'wan_ip')

    def test_none_wan_ip_by_iface_does_not_clear(self, mock_db):
        """None wan_ip_by_iface must not overwrite last-known-good values."""
        Database.persist_network_identity(mock_db, wan_ip_by_iface=None)
        for c in mock_db.set_config.call_args_list:
            assert c[0][0] not in ('wan_ip_by_iface', 'wan_ips', 'wan_ip')

    def test_empty_gateway_ip_vlans_does_not_clear(self, mock_db):
        """Empty gateway_ip_vlans must not overwrite last-known-good values."""
        Database.persist_network_identity(mock_db, gateway_ip_vlans={})
        for c in mock_db.set_config.call_args_list:
            assert c[0][0] not in ('gateway_ip_vlans', 'gateway_ips')

    def test_both_wan_and_gateway(self, mock_db):
        Database.persist_network_identity(
            mock_db,
            wan_ip_by_iface={'eth0': '1.2.3.4'},
            gateway_ip_vlans={'10.0.0.1': {'vlan': 1, 'name': 'LAN'}},
        )
        keys_written = [c[0][0] for c in mock_db.set_config.call_args_list]
        assert 'wan_ip_by_iface' in keys_written
        assert 'gateway_ip_vlans' in keys_written


# ── Log-based detection (issue #103) ────────────────────────────────────────

CUTOFF = datetime(2026, 10, 3, 12, 0, tzinfo=timezone.utc)


def _sql(text):
    return ' '.join(text.split())


def _config_db(config, rows=(), cutoff=CUTOFF):
    """MagicMock Database backed by a config dict; set_config writes through.

    The cursor's fetchone() answers the cutoff query (no row when `cutoff`
    is None, like the HAVING clause on an empty table); fetchall() returns
    `rows` for the detection query.
    """
    db = MagicMock()
    # SQL fragment is a class attribute read through `self`
    db._PRIVATE_IP_FILTER = Database._PRIVATE_IP_FILTER
    db.get_config.side_effect = lambda key, default=None: config.get(key, default)
    db.set_config.side_effect = config.__setitem__
    cur = MagicMock()
    cur.fetchone.return_value = (cutoff,) if cutoff is not None else None
    cur.fetchall.return_value = list(rows)
    conn = db.get_conn.return_value.__enter__.return_value
    conn.cursor.return_value.__enter__.return_value = cur
    return db, cur


def _keys_written(db):
    return [c.args[0] for c in db.set_config.call_args_list]


class TestRecentFirewallCutoff:
    """recent_firewall_cutoff(): 7 days before the newest firewall row, capped at NOW()."""

    def test_cutoff_query_caps_newest_row_at_now(self):
        cur = MagicMock()
        cur.fetchone.return_value = (CUTOFF,)
        assert recent_firewall_cutoff(cur) == CUTOFF
        sql = _sql(cur.execute.call_args.args[0])
        assert 'LEAST(MAX(timestamp), NOW())' in sql
        assert "INTERVAL '7 days'" in sql
        assert "log_type = 'firewall'" in sql

    def test_none_without_firewall_rows(self):
        cur = MagicMock()
        cur.fetchone.return_value = None
        assert recent_firewall_cutoff(cur) is None


class TestDetectionQueryWindow:
    """Detection queries bind the cutoff as a parameter so the planner can use
    idx_logs_type_time, and observe nothing when there is no cutoff."""

    def test_wan_query_binds_cutoff(self):
        db, cur = _config_db({}, rows=[('eth8', '1.1.1.1')])
        assert Database.get_wan_ips_by_interface(db, ['eth8', 'eth9']) == {'eth8': '1.1.1.1'}
        assert 'LEAST(MAX(timestamp), NOW())' in _sql(cur.execute.call_args_list[0].args[0])
        sql, params = cur.execute.call_args_list[1].args
        assert 'timestamp >= %s' in _sql(sql)
        assert 'host(dst_ip)' in sql
        assert params == [CUTOFF, 'eth8', 'eth9']

    def test_wan_query_skipped_without_cutoff(self):
        db, cur = _config_db({}, cutoff=None)
        assert Database.get_wan_ips_by_interface(db, ['eth8']) == {}
        assert cur.execute.call_count == 1  # cutoff lookup only

    def test_detect_wan_ip_persists_nothing_without_cutoff(self):
        config = {
            'wan_interfaces': ['eth8'],
            'wan_ip_by_iface': {'eth8': '1.1.1.1'},
            'wan_ips': ['1.1.1.1'],
            'wan_ip': '1.1.1.1',
        }
        db, _ = _config_db(config, cutoff=None)
        db.get_wan_ips_by_interface.side_effect = (
            lambda ifaces: Database.get_wan_ips_by_interface(db, ifaces))
        assert Database.detect_wan_ip(db) == '1.1.1.1'
        db.set_config.assert_not_called()

    def test_gateway_query_binds_cutoff(self):
        db, cur = _config_db({'gateway_ips': []}, rows=[('192.168.1.1',)])
        assert Database.detect_gateway_ips(db) == ['192.168.1.1']
        assert 'LEAST(MAX(timestamp), NOW())' in _sql(cur.execute.call_args_list[0].args[0])
        sql, params = cur.execute.call_args_list[1].args
        assert 'timestamp >= %s' in _sql(sql)
        assert params == [CUTOFF]

    def test_gateway_persists_nothing_without_cutoff(self):
        config = {'gateway_ips': ['10.0.0.1']}
        db, cur = _config_db(config, cutoff=None)
        assert Database.detect_gateway_ips(db) == ['10.0.0.1']
        assert cur.execute.call_count == 1
        db.set_config.assert_not_called()

    def test_candidates_query_binds_cutoff(self):
        db, cur = _config_db({}, rows=[('eth8', 12, '1.1.1.1'), ('eth9', 3, None)])
        assert Database.get_wan_ip_candidates(db) == [
            {'interface': 'eth8', 'event_count': 12, 'wan_ip': '1.1.1.1'},
            {'interface': 'eth9', 'event_count': 3, 'wan_ip': ''},
        ]
        assert 'LEAST(MAX(timestamp), NOW())' in _sql(cur.execute.call_args_list[0].args[0])
        sql, params = cur.execute.call_args_list[1].args
        assert 'timestamp >= %s' in _sql(sql)
        assert params == [CUTOFF]

    def test_candidates_empty_without_cutoff(self):
        db, cur = _config_db({}, cutoff=None)
        assert Database.get_wan_ip_candidates(db) == []
        assert cur.execute.call_count == 1


class TestDetectWanIpMerge:
    """detect_wan_ip() merges observations into persisted identity."""

    def test_keeps_wan2_when_only_wan1_observed(self):
        config = {
            'wan_interfaces': ['eth8', 'eth9'],
            'wan_ip_by_iface': {'eth8': '1.1.1.1', 'eth9': '2.2.2.2'},
            'wan_ips': ['1.1.1.1', '2.2.2.2'],
            'wan_ip': '1.1.1.1',
        }
        db, _ = _config_db(config)
        db.get_wan_ips_by_interface.return_value = {'eth8': '3.3.3.3'}

        assert Database.detect_wan_ip(db) == '3.3.3.3'
        assert config['wan_ip_by_iface'] == {'eth8': '3.3.3.3', 'eth9': '2.2.2.2'}
        assert config['wan_ips'] == ['3.3.3.3', '2.2.2.2']
        assert config['wan_ip'] == '3.3.3.3'

    def test_empty_observation_persists_nothing(self):
        config = {
            'wan_interfaces': ['eth8', 'eth9'],
            'wan_ip_by_iface': {'eth8': '1.1.1.1', 'eth9': '2.2.2.2'},
            'wan_ips': ['1.1.1.1', '2.2.2.2'],
            'wan_ip': '1.1.1.1',
        }
        db, _ = _config_db(config)
        db.get_wan_ips_by_interface.return_value = {}

        assert Database.detect_wan_ip(db) == '1.1.1.1'
        db.set_config.assert_not_called()

    def test_removed_interface_pruned_even_without_observations(self):
        config = {
            'wan_interfaces': ['eth8'],
            'wan_ip_by_iface': {'eth8': '1.1.1.1', 'eth9': '2.2.2.2'},
            'wan_ips': ['1.1.1.1', '2.2.2.2'],
            'wan_ip': '1.1.1.1',
        }
        db, _ = _config_db(config)
        db.get_wan_ips_by_interface.return_value = {}

        assert Database.detect_wan_ip(db) == '1.1.1.1'
        assert config['wan_ip_by_iface'] == {'eth8': '1.1.1.1'}
        assert config['wan_ips'] == ['1.1.1.1']
        assert 'wan_ip' not in _keys_written(db)

    def test_first_detection_populates_identity(self):
        config = {'wan_interfaces': ['ppp0']}
        db, _ = _config_db(config)
        db.get_wan_ips_by_interface.return_value = {'ppp0': '5.5.5.5'}

        assert Database.detect_wan_ip(db) == '5.5.5.5'
        assert config['wan_ip_by_iface'] == {'ppp0': '5.5.5.5'}
        assert config['wan_ips'] == ['5.5.5.5']
        assert config['wan_ip'] == '5.5.5.5'

    def test_unchanged_observation_writes_nothing(self):
        config = {
            'wan_interfaces': ['eth8'],
            'wan_ip_by_iface': {'eth8': '1.1.1.1'},
            'wan_ips': ['1.1.1.1'],
            'wan_ip': '1.1.1.1',
        }
        db, _ = _config_db(config)
        db.get_wan_ips_by_interface.return_value = {'eth8': '1.1.1.1'}

        Database.detect_wan_ip(db)
        db.set_config.assert_not_called()


class TestDetectGatewayIpsMerge:
    """detect_gateway_ips() unions observations and never drops an address."""

    def test_unions_with_persisted(self):
        config = {'gateway_ips': ['10.0.0.1']}
        db, _ = _config_db(config, rows=[('192.168.1.1',)])

        assert Database.detect_gateway_ips(db) == ['10.0.0.1', '192.168.1.1']
        assert config['gateway_ips'] == ['10.0.0.1', '192.168.1.1']

    def test_empty_observation_keeps_persisted(self):
        config = {'gateway_ips': ['10.0.0.1', '192.168.1.1']}
        db, _ = _config_db(config, rows=[])

        assert Database.detect_gateway_ips(db) == ['10.0.0.1', '192.168.1.1']
        db.set_config.assert_not_called()

    def test_partial_observation_never_drops(self):
        config = {'gateway_ips': ['10.0.0.1', '192.168.1.1']}
        db, _ = _config_db(config, rows=[('192.168.1.1',)])

        assert Database.detect_gateway_ips(db) == ['10.0.0.1', '192.168.1.1']
        db.set_config.assert_not_called()
