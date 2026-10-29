"""CEF display claims stay separate from parsed endpoint identities."""

from parsers import cef_reported_context, parse_cef_log


def test_aliases_without_addresses_do_not_invent_endpoints():
    raw = ('<14>Jan 01 00:00:00 gateway CEF:0|Ubiquiti|UniFi Network|10.0|201|Threat Blocked|7|'
           'UNIFIsrcClientAlias=Media device UNIFIdstClientHostname=receiver '
           'UNIFIdeviceName=Gateway app=SSH proto=TCP spt=12345 dpt=22 '
           'UNIFIipsSignature=Synthetic detection act=blocked')
    assert cef_reported_context(raw) == {
        'src_reported_name': 'Media device', 'dst_reported_name': 'receiver',
        'reported_application': 'SSH',
    }
    parsed = parse_cef_log(raw)
    assert parsed['src_ip'] is None and parsed['dst_ip'] is None
    assert 'src_device_name' not in parsed


def test_alias_priority_and_escaping_in_syslog_envelope():
    raw = ('<13>1 2026-01-01T00:00:00Z gateway app - - - '
           'CEF:0|Ubiquiti|UniFi Network|10.0|200|Threat Detected|5|'
           r'UNIFIsrcClientAlias=Player\=One UNIFIsrcClientHostname=player.example '
           'UNIFIipsSignature=Synthetic')
    assert cef_reported_context(raw)['src_reported_name'] == 'Player=One'


def test_rejects_other_emitters_and_bounds_display_fields():
    assert cef_reported_context(None) == {}
    assert cef_reported_context('ordinary system message') == {}
    assert cef_reported_context('<14>Jan 01 00:00:00 gateway CEF:0|Other|Product|1|201|Threat|7|app=SSH') == {}
    raw = ('<14>Jan 01 00:00:00 gateway CEF:0|Ubiquiti|UniFi Network|1|201|Threat|7|UNIFIsrcClientAlias=' + 'a' * 300)
    assert len(cef_reported_context(raw)['src_reported_name']) == 255
