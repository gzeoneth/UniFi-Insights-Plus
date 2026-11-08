import { describe, expect, it } from 'vitest'
import { LOG_PRESETS, buildLogPresetFilters, logFilterFingerprint } from '../lib/logPresets'

describe('built-in log presets', () => {
  it.each(LOG_PRESETS)('$name replaces conflicting filters and uses a 24h window', preset => {
    const current = { time_range: '7d', time_from: '2026-01-01', time_to: '2026-01-02', page: 9, per_page: 100, sort: 'id', order: 'asc',
      ip: '192.0.2.10', src_ip: '198.51.100.10', search: 'Previous search', rule_name: 'Previous rule', filter_rules: '[]',
      interface: 'example0', vpn_only: true, threat_min: 80, exclude_groups: '[]' }
    const defaults = { time_range: '24h', page: 1, per_page: 50, sort: 'timestamp', order: 'desc', ip: null, src_ip: null, search: null, rule_name: null }
    const result = buildLogPresetFilters(preset, current, defaults)
    expect(result).toMatchObject({ time_range: '24h', time_from: null, time_to: null, page: 1, per_page: 100, sort: 'id', order: 'asc', ip: null, src_ip: null, search: null, rule_name: null })
    for (const key of ['interface', 'vpn_only', 'threat_min', 'exclude_groups']) expect(result).not.toHaveProperty(key)
    expect(result.filter_rules ? JSON.parse(result.filter_rules) : null).toEqual(preset.filters.filter_rules || null)
  })

  it('uses shared security categories and advanced port OR/ranges', () => {
    const filters = id => LOG_PRESETS.find(preset => preset.id === id).filters
    expect(filters('ips').filter_rules).toEqual([{ field: 'security_event', operator: 'include', value: 'ips' }])
    expect(filters('unparsed-cef').filter_rules).toEqual([{ field: 'security_event', operator: 'include', value: 'unparsed_cef' }])
    expect(filters('discovery').filter_rules).toEqual([{ field: 'port', operator: 'include', value: '5353,1900' }])
    expect(filters('high-ports').filter_rules).toEqual([{ field: 'dst_port', operator: 'include', value: '49152-65535' }])
    expect(filters('missing-action')).toEqual({ log_type: 'firewall', filter_rules: [{ field: 'rule_action', operator: 'missing' }] })
    expect(filters('blocked-inter-vlan')).toEqual({ log_type: 'firewall', direction: 'inter_vlan', rule_action: 'block' })
    expect(filters('blocked-private')).toEqual({ log_type: 'firewall', rule_action: 'block', filter_rules: [
      { field: 'src_ip', operator: 'include', value: '10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7' },
      { field: 'dst_ip', operator: 'include', value: '10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7' },
    ] })
    expect(filters('nat-mapping')).toEqual({ log_type: 'firewall', protocol: 'udp', dst_port: '5351' })
  })

  it('keeps preset scope stable across paging, while recognizing a real filter change', () => {
    expect(logFilterFingerprint({ time_range: '24h', filter_rules: null, page: 1 })).toBe(logFilterFingerprint({ page: 2, filter_rules: '[]', time_range: '24h' }))
    expect(logFilterFingerprint({ time_range: '24h' })).not.toBe(logFilterFingerprint({ time_range: '7d' }))
  })
})
