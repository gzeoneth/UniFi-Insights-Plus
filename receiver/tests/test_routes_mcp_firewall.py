"""Tests for the MCP set_firewall_syslog tool and id-less policies (#112)."""

import sys
from unittest.mock import MagicMock

import pytest

POLICY_ID = '11111111-2222-4333-8444-555555555555'
DERIVED_ID = '66666666-7777-4888-9999-aaaaaaaaaaaa'


@pytest.fixture
def mcp(monkeypatch):
    """Import routes.mcp with its dependencies stubbed."""
    for mod_name in list(sys.modules):
        if mod_name.startswith('routes'):
            monkeypatch.delitem(sys.modules, mod_name, raising=False)
    for name in ('deps', 'db', 'routes.logs', 'routes.stats', 'routes.setup',
                 'routes.unifi', 'routes.health', 'routes.threats', 'routes.auth'):
        monkeypatch.setitem(sys.modules, name, MagicMock())

    import routes.mcp as mcp_module
    mcp_module.unifi_routes.get_firewall_policies.return_value = {'policies': [
        {'id': POLICY_ID, 'name': 'Allow LAN', 'loggingEnabled': False,
         'metadata': {'origin': 'USER_DEFINED'}},
        {'id': DERIVED_ID, 'name': 'Auto rule', 'loggingEnabled': False,
         'metadata': {'origin': 'DERIVED'}},
        {'name': 'Legacy rule', 'loggingEnabled': False},
        {'id': '', 'name': 'Empty id rule', 'loggingEnabled': False},
    ]}
    mcp_module.unifi_api.bulk_patch_logging.return_value = {
        'total': 1, 'success': 1, 'failed': 0, 'skipped': 0, 'retried': 0, 'errors': [],
    }
    return mcp_module


class TestSetFirewallSyslogIdless:
    @pytest.mark.parametrize('target', [None, '', 'Legacy rule', 'Empty id rule'])
    def test_idless_policy_cannot_be_targeted(self, mcp, target):
        result = mcp._tool_set_firewall_syslog(
            {'policies': [{'id': target, 'loggingEnabled': True}]})

        assert result['success'] is False
        assert result['errors'][0]['id'] == target
        mcp.unifi_api.bulk_patch_logging.assert_not_called()

    def test_real_id_still_patched_next_to_idless_request(self, mcp):
        result = mcp._tool_set_firewall_syslog({'policies': [
            {'id': POLICY_ID, 'loggingEnabled': True},
            {'id': '', 'loggingEnabled': True},
        ]})

        mcp.unifi_api.bulk_patch_logging.assert_called_once_with(
            [{'id': POLICY_ID, 'loggingEnabled': True}])
        assert result['skipped'] == 1
        assert result['errors'] == [{'id': '', 'error': 'Unknown policy id'}]


class TestSetFirewallSyslogDerived:
    def test_derived_rejected_user_defined_patched(self, mcp):
        """origin lives under metadata; a DERIVED policy must never be patched."""
        result = mcp._tool_set_firewall_syslog({'policies': [
            {'id': DERIVED_ID, 'loggingEnabled': True},
            {'id': POLICY_ID, 'loggingEnabled': True},
        ]})

        mcp.unifi_api.bulk_patch_logging.assert_called_once_with(
            [{'id': POLICY_ID, 'loggingEnabled': True}])
        assert result['skipped'] == 1
        assert result['errors'] == [{'id': DERIVED_ID, 'error': 'Derived policy cannot be modified'}]

    def test_derived_only_request_is_not_patched(self, mcp):
        result = mcp._tool_set_firewall_syslog(
            {'policies': [{'id': DERIVED_ID, 'loggingEnabled': False}]})

        assert result == {'success': False,
                          'errors': [{'id': DERIVED_ID, 'error': 'Derived policy cannot be modified'}]}
        mcp.unifi_api.bulk_patch_logging.assert_not_called()
