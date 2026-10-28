"""WAN ownership uses addresses, including AP-mode console deployments."""

from unittest.mock import MagicMock, patch

from unifi_api import UniFiAPI


def test_ap_mode_console_does_not_become_the_wan_gateway():
    devices = [
        {'device_type': 'udm', 'device_name': 'Mesh AP', 'ip': '192.0.2.20'},
        {'device_type': 'udm', 'device_name': 'Site Gateway', 'ip': '192.0.2.1'},
    ]
    config = {'networks': [{'ip_subnet': '192.0.2.1/24'}],
              'wan_interfaces': [{'wan_ip': '203.0.113.7'}]}
    assert UniFiAPI._wan_device_names(devices, config) == {
        '203.0.113.7': 'Site Gateway',
    }


def test_per_wan_owner_wins_over_management_address_candidate():
    devices = [
        {'device_name': 'Primary', 'ip': '192.0.2.1', 'wan_ips': ['203.0.113.7']},
        {'device_name': 'Secondary', 'ip': '198.51.100.1', 'wan_ips': ['203.0.113.8']},
    ]
    config = {'networks': [{'ip_subnet': '192.0.2.1/24'}], 'wan_interfaces': [
        {'wan_ip': '203.0.113.7'}, {'wan_ip': '203.0.113.8'}]}
    assert UniFiAPI._wan_device_names(devices, config) == {
        '203.0.113.7': 'Primary', '203.0.113.8': 'Secondary',
    }


def test_unknown_or_ambiguous_gateway_uses_generic_label():
    config = {'wan_interfaces': [{'wan_ip': '203.0.113.7'}]}
    # A gateway-capable model alone is insufficient ownership evidence.
    assert UniFiAPI._wan_device_names([
        {'device_type': 'udm', 'device_name': 'Mesh AP'}], config) == {
        '203.0.113.7': 'Gateway',
    }
    devices = [{'device_name': name, 'wan_ips': ['203.0.113.7']}
               for name in ('Gateway A', 'Gateway B')]
    assert UniFiAPI._wan_device_names(devices, config) == {'203.0.113.7': 'Gateway'}


def test_successful_poll_replaces_old_wan_identity():
    db = MagicMock()
    with patch.object(UniFiAPI, '_resolve_config'):
        api = UniFiAPI(db)
    api.enabled = True
    api._poll_clients = MagicMock(return_value=[])
    api._poll_devices = MagicMock(return_value=[])
    api.get_network_config = MagicMock(return_value={'networks': [], 'wan_interfaces': []})
    api._ip_to_name = {'203.0.113.6': 'Old WAN'}
    assert api.poll()
    assert '203.0.113.6' not in api._ip_to_name
    assert any(call.args == ('wan_ip_names', {}) for call in db.set_config.call_args_list)


def test_device_poll_keeps_per_device_wan_addresses():
    with patch.object(UniFiAPI, '_resolve_config'):
        api = UniFiAPI(MagicMock())
    api._get = MagicMock(return_value={'data': [{
        'mac': '02:00:00:00:00:01', 'name': 'Gateway',
        'wan1': {'ip': '203.0.113.7'}, 'wan2': {}, 'wan3': None,
    }]})
    assert api._poll_devices()[0]['wan_ips'] == ['203.0.113.7']
