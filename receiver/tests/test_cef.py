"""Synthetic CEF fixtures: documentation addresses and invented device names."""

from datetime import datetime, timezone

import pytest

from parsers import _parse_cef_extensions, detect_log_type, parse_cef_threat, parse_log


def cef(extension='', *, event_id='201', name='Threat Detected and Blocked', severity='7'):
    return f'CEF:0|Ubiquiti|UniFi Network|10.0.0|{event_id}|{name}|{severity}|{extension}'


def syslog(body):
    return '<14>Oct 28 12:34:56 example-gateway ' + body


def test_ips_fields_remain_distinct_from_reputation_and_gateway_identity():
    raw = syslog(cef(
        'src=203.0.113.20 dst=10.20.0.4 spt=5678 dpt=443 proto=TCP act=blocked '
        'UNIFIrisk=medium UNIFIpolicyName=Example policy UNIFIpolicyType=IDS/IPS '
        'UNIFIdirection=incoming UNIFIipsSignature=Example synthetic IPS signature '
        'UNIFIipsSignatureId=1234567 UNIFIdeviceMac=02:00:00:00:00:01 '
        'UNIFIdeviceName=example-gateway UNIFIutcTime=2024-10-28T04:34:56.125Z '
        'msg=An invented event for a unit test.'))
    parsed = parse_log(raw)
    assert parsed['event_source'] == 'unifi_ips'
    assert parsed['source'] == 'syslog'
    assert parsed['log_type'] == 'firewall'
    assert parsed['event_id'] == '201'
    assert parsed['event_name'] == 'Threat Detected and Blocked'
    assert parsed['ips_signature'] == 'Example synthetic IPS signature'
    assert parsed['ips_signature_id'] == '1234567'
    assert parsed['ips_severity'] == 7
    assert parsed['ips_risk'] == 'medium'
    assert parsed['src_ip'] == '203.0.113.20'
    assert parsed['dst_ip'] == '10.20.0.4'
    assert parsed['src_port'] == 5678
    assert parsed['dst_port'] == 443
    assert parsed['protocol'] == 'tcp'
    assert parsed['direction'] == 'inbound'
    assert parsed['rule_action'] == 'block'
    assert parsed['rule_name'] == 'Example policy'
    assert parsed['timestamp'] == datetime(2024, 10, 28, 4, 34, 56, 125000, tzinfo=timezone.utc)
    assert parsed['raw_log'] == raw
    assert parsed['hostname'] == 'example-gateway'
    for forbidden in ('threat_score', 'threat_categories', 'mac_address', 'src_device_name', 'dst_device_name'):
        assert forbidden not in parsed


def test_header_and_extension_escaping():
    parsed = parse_cef_threat(cef(
        r'UNIFIipsSignature=literal dst\=203.0.113.99 | file C:\\rules '
        r'UNIFIipsSignatureId=123 dst=2001:db8::2 proto=6 '
        r'msg=line one\nline two\rkey\=value',
        name=r'Threat Detected \| synthetic \\ signature'))
    assert parsed['event_name'] == r'Threat Detected | synthetic \ signature'
    assert parsed['ips_signature'] == r'literal dst=203.0.113.99 | file C:\rules'
    assert parsed['dst_ip'] == '2001:db8::2'
    assert parsed['protocol'] == 'tcp'
    fields = _parse_cef_extensions(r'msg=first\nsecond\rkey\=value dst=203.0.113.3')
    assert fields['msg'] == 'first\nsecond\rkey=value'
    assert fields['dst'] == '203.0.113.3'


def test_escaped_backslash_before_header_separator_is_not_an_escape_for_pipe():
    parsed = parse_cef_threat(cef('src=203.0.113.3', name='Threat ends in \\\\'))
    assert parsed['event_name'] == 'Threat ends in \\'
    assert parsed['src_ip'] == '203.0.113.3'


def test_extension_duplicates_keep_first_value_and_unknown_escape_is_preserved():
    fields = _parse_cef_extensions(r'src=203.0.113.1 src=203.0.113.2 msg=unknown\q')
    assert fields == {'src': '203.0.113.1', 'msg': r'unknown\q'}


@pytest.mark.parametrize('extension,field', [
    ('src=999.999.999.999', 'src_ip'), ('dst=203.0.113.1/24', 'dst_ip'),
    ('src=fe80::1%eth0', 'src_ip'), ('spt=-1', 'src_port'),
    ('dpt=65536', 'dst_port'), ('dpt=1.5', 'dst_port'),
    ('dpt=' + '9' * 6000, 'dst_port'), ('proto=256', 'protocol'),
    ('proto=arbitrary-long-invalid-value', 'protocol'),
])
def test_invalid_network_fields_are_safe_for_direct_and_live_parsing(extension, field):
    assert parse_cef_threat(cef(extension))[field] is None
    assert parse_log(syslog(cef(extension)))[field] is None


@pytest.mark.parametrize('severity', ['-1', '11', 'high', '7.5', '9' * 6000])
def test_invalid_severity_is_unset_without_discarding_event(severity):
    parsed = parse_cef_threat(cef(severity=severity))
    assert parsed['ips_severity'] is None
    assert parsed['event_source'] == 'unifi_ips'


@pytest.mark.parametrize('action,expected', [
    ('blocked', 'block'), ('DROP', 'block'), ('allowed', 'allow'),
    ('Accept', 'allow'), ('detected', None), ('', None),
])
def test_action_is_normalized_only_when_explicit(action, expected):
    assert parse_cef_threat(cef('act=' + action))['rule_action'] == expected


@pytest.mark.parametrize('body', [
    cef(event_id='546', name='Config Modified'),
    cef(event_id='203', name='Blocked by Firewall'),
    cef().replace('Ubiquiti', 'OtherVendor'),
    cef().replace('UniFi Network', 'UniFi OS'),
    cef(event_id='2000'), 'CEF:0|Ubiquiti|truncated',
    cef(event_id='546', name='Config Modified', extension='msg=SRC=x DST=y PROTO=TCP'),
])
def test_unrelated_or_malformed_cef_preserved_as_system(body):
    assert parse_cef_threat(body) is None
    assert detect_log_type(body) == 'system'
    raw = syslog(body)
    assert parse_log(raw)['log_type'] == 'system'
    assert parse_log(raw)['raw_log'] == raw


def test_tagged_cef_and_dual_unifi_timestamp():
    body = cef('src=203.0.113.20')
    raw = 'Oct 28 12:34:56 2023-10-28T04:34:56.125Z example-gateway unifi[123]: ' + body
    parsed = parse_log(raw)
    assert parsed['event_source'] == 'unifi_ips'
    assert parsed['timestamp'] == datetime(2023, 10, 28, 4, 34, 56, 125000, tzinfo=timezone.utc)


def test_rfc5424_structured_data_with_escapes_and_bom():
    raw = ('<134>1 2023-10-28T12:34:56+08:00 gateway app 12 msg-id '
           r'[example@123 a="escaped\]bracket" b="escaped\\slash"][second x="y"] '
           '\ufeff' + cef('src=2001:db8::1 dst=2001:db8::2 proto=58'))
    parsed = parse_log(raw)
    assert parsed['timestamp'] == datetime(2023, 10, 28, 4, 34, 56, tzinfo=timezone.utc)
    assert parsed['event_source'] == 'unifi_ips'
    assert parsed['protocol'] == 'icmpv6'
    assert parsed['raw_log'] == raw


def test_rfc5424_nil_timestamp_can_use_explicit_cef_time():
    raw = '<134>1 - gateway app - - - ' + cef('UNIFIutcTime=2024-01-02T03:04:05Z')
    assert parse_log(raw)['timestamp'] == datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    assert parse_log('<134>1 - gateway app - - - ' + cef()) is None


@pytest.mark.parametrize('value', ['2020-01-01T01:02:03', 'garbage', '2020-99-99T99:99:99Z'])
def test_bad_cef_time_falls_back_to_envelope(value):
    raw = '<134>1 2023-10-28T12:34:56+08:00 gateway app - - - ' + cef('UNIFIutcTime=' + value)
    assert parse_log(raw)['timestamp'] == datetime(2023, 10, 28, 4, 34, 56, tzinfo=timezone.utc)


def test_malformed_rfc5424_structured_data_returns_none():
    assert parse_log('<134>1 2023-10-28T04:34:56Z gateway app - - [unclosed ' + cef()) is None


@pytest.mark.parametrize('prefix,expected', [
    ('<13>Oct 28 12:34:56 example-gateway ', 'example-gateway'),
    ('<13>1 2024-10-28T12:34:56Z example-rfc5424 app - - - ', 'example-rfc5424'),
    ('<13>Oct 28 12:34:56 2024-10-28T12:34:56Z example-dual ', 'example-dual'),
    ('<13>1 2024-10-28T12:34:56Z - app - - - ', None),
])
def test_firewall_emitter_is_recorded_for_scoped_rule_profiles(prefix, expected):
    body = '[EXAMPLE-A-100] IN=br0 OUT=eth0 SRC=192.0.2.10 DST=203.0.113.20 PROTO=TCP SPT=50000 DPT=443'
    parsed = parse_log(prefix + body)
    assert parsed.get('hostname') == expected
    assert parsed.get('src_device_name') is None
    assert parsed['raw_log'] == prefix + body


def test_emitter_does_not_replace_dhcp_client_hostname():
    parsed = parse_log('<13>Oct 28 12:34:56 example-gateway dnsmasq-dhcp[1]: DHCPACK(br0) 192.0.2.10 02:00:00:00:00:10 example-client')
    assert parsed['hostname'] == 'example-client'
