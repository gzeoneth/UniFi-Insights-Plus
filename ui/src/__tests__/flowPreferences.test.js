import { describe, expect, it } from 'vitest'
import { isFlowHostIp, normalizeFlowPreferences } from '../lib/flowPreferences'

describe('Flow preference boundaries', () => {
  it('accepts IPv4 and IPv6 hosts without treating hostnames or URLs as IP filters', () => {
    for (const ip of ['192.0.2.10', '2001:db8::10', '::ffff:192.0.2.10']) expect(isFlowHostIp(ip)).toBe(true)
    for (const ip of ['example.test', '999.0.2.1', '192.00.2.1', 'http://192.0.2.1', '[2001:db8::1]', '2001:db8::x', '', null]) expect(isFlowHostIp(ip)).toBe(false)
  })

  it('restores one cross-filter and removes stale result context and unknown fields', () => {
    const restored = normalizeFlowPreferences({
      zoneFilter: { interface_in: 'br20', interface_out: 'br30' },
      sankeyFilter: { type: 'src_ip', value: '192.0.2.10' },
      hostIp: '2001:db8::20', expandedRow: { ip: '192.0.2.10', rowIndex: 10 },
      hostHistory: ['192.0.2.10'], data: [{ example: true }], credential: 'not-a-preference',
    })
    expect(restored).toMatchObject({ hostIp: '2001:db8::20', sankeyFilter: null,
      zoneFilter: { interface_in: 'br20', interface_out: 'br30' } })
    for (const key of ['expandedRow', 'hostHistory', 'data', 'credential']) expect(restored).not.toHaveProperty(key)
  })

  it('rejects reversed dates, invalid dimensions and invalid cross-filter values', () => {
    const restored = normalizeFlowPreferences({
      timeFrom: '2026-01-10T12:00:00Z', timeTo: '2026-01-10T11:00:00Z',
      dims: ['src_ip', 'src_ip', 'dst_port'],
      sankeyFilter: { type: 'dst_port', value: '65536' }, zoneFilter: { interface_in: '', interface_out: 'br20' },
      activeDirections: ['anything'], activeActions: [],
    })
    expect(restored).toMatchObject({ timeFrom: null, timeTo: null, dims: ['src_ip', 'dst_port', 'dst_ip'],
      sankeyFilter: null, zoneFilter: null, activeActions: ['allow', 'block'] })
    expect(restored.activeDirections).not.toContain('anything')
  })

  it('preserves valid directional cross-filters and a single date bound', () => {
    expect(normalizeFlowPreferences({ timeFrom: '2026-01-10T12:00:00Z',
      sankeyFilter: { type: 'interface_out', value: 'br20' }, advancedExpanded: false })).toMatchObject({
      timeFrom: '2026-01-10T12:00:00Z', timeTo: null,
      sankeyFilter: { type: 'interface_out', value: 'br20' }, advancedExpanded: false,
    })
  })
})
