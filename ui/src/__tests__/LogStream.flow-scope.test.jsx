import { cleanup, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import LogStream from '../components/LogStream'
import { fetchLogs } from '../api'
import { flowDrillScope } from '../lib/flowDrillScope'

const profile = JSON.stringify([{ conditions: [{ field: 'rule_name', operator: 'include', value: 'Example routine rule' }] }])
vi.mock('../components/ExclusionProfiles', () => ({
  useExclusionProfile: () => ({ excludeGroups: profile, openDraft: () => {} }), ExclusionCounts: () => null,
}))
vi.mock('../api', () => ({
  fetchLogs: vi.fn(), fetchLog: vi.fn(), fetchLogCountsByType: vi.fn(), getExportUrl: () => '/api/export',
}))
vi.mock('../components/FilterBar', () => ({ default: () => null }))
vi.mock('../components/FieldFilters', async importOriginal => ({ ...await importOriginal(), default: () => null }))
vi.mock('../components/LogTable', () => ({ default: () => null }))

const rules = [{ field: 'ip', operator: 'exclude', value: '198.51.100.0/24' }]
const drill = { src_ip: '192.0.2.10', dst_ip: '203.0.113.20', dst_port: 443, protocol: 'TCP',
  rule_action: 'block', direction: 'inter_vlan', time_range: '1h', filter_rules: JSON.stringify(rules),
  interface_in: 'br20', interface_out: 'br30', exclude_groups: profile }
const directional = [
  { field: 'interface_in', operator: 'include', value: 'br20' },
  { field: 'interface_out', operator: 'include', value: 'br30' },
]
beforeEach(() => {
  vi.clearAllMocks(); localStorage.clear(); sessionStorage.clear()
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' })
  fetchLogs.mockResolvedValue({ data: [], total: null, pages: null, has_more: false })
})
afterEach(cleanup)

describe('Flow to Log Stream scope', () => {
  it('preserves host exclusions, action, direction, protocol and exact interfaces on first and later drills', async () => {
    const view = render(<LogStream drillFilters={drill} />)
    await waitFor(() => expect(fetchLogs).toHaveBeenCalledOnce())
    expect(fetchLogs.mock.calls[0][0]).toMatchObject({ src_ip: drill.src_ip, dst_ip: drill.dst_ip, dst_port: '443',
      protocol: 'TCP', rule_action: 'block', direction: 'inter_vlan', exclude_groups: profile,
      time_range: '1h', filter_rules: JSON.stringify([...rules, ...directional]) })
    view.rerender(<LogStream drillFilters={{ ...drill, protocol: 'UDP', src_ip: '192.0.2.11' }} />)
    await waitFor(() => expect(fetchLogs.mock.lastCall[0].protocol).toBe('UDP'))
    expect(fetchLogs.mock.lastCall[0]).toMatchObject({ src_ip: '192.0.2.11', filter_rules: JSON.stringify([...rules, ...directional]), exclude_groups: profile })
  })

  it('deduplicates identical selected interfaces but retains a conflicting condition', () => {
    const conflicting = { field: 'interface_in', operator: 'include', value: 'br40' }
    const scoped = flowDrillScope({ ...drill, filter_rules: JSON.stringify([...rules, ...directional, conflicting]) })
    expect(JSON.parse(scoped.filter_rules)).toEqual([...rules, ...directional, conflicting])
  })

  it('never truncates a full filter list to make room for the zone condition', () => {
    const many = Array.from({ length: 24 }, (_, index) => ({ field: 'device', operator: 'exclude', value: `example-${index}` }))
    expect(JSON.parse(flowDrillScope({ ...drill, filter_rules: many }).filter_rules)).toHaveLength(26)
  })

  it('does not discard an empty directional interface supplied in a drill', () => {
    expect(JSON.parse(flowDrillScope({ ...drill, interface_out: '' }).filter_rules))
      .toContainEqual({ field: 'interface_out', operator: 'include', value: '' })
  })

  it('shows a server validation error explicitly instead of widening an over-limit drill', async () => {
    fetchLogs.mockRejectedValueOnce(Object.assign(new Error('Invalid field filter: expected at most 24 rules'), { status: 400 }))
    render(<LogStream drillFilters={drill} />)
    await screen.findByText('Invalid field filter: expected at most 24 rules')
  })
})
