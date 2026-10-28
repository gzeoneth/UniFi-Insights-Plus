import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import TopIPPairs from '../components/TopIPPairs'
import { fetchIPPairs } from '../api'
import { exportCsv } from '../lib/exportCsv'

vi.mock('../api', () => ({ fetchIPPairs: vi.fn() }))

const rules = JSON.stringify([{ field: 'ip', operator: 'exclude', value: '198.51.100.0/24' }])
const filters = { time_range: '1h', filter_rules: rules, exclude_groups: '[]', rule_action: 'block', direction: 'inter_vlan' }
const pair = { src_ip: '192.0.2.10', dst_ip: '203.0.113.20', dst_port: 443, protocol: 'TCP', service_name: 'HTTPS', block_count: 4 }
beforeEach(() => {
  vi.clearAllMocks(); sessionStorage.clear()
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' })
  fetchIPPairs.mockResolvedValue({ pairs: [pair] })
})
afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals() })

describe('Flow drilldown and export scope', () => {
  it('retains advanced filters and zone selection in the pair request and drill event', async () => {
    const received = vi.fn()
    window.addEventListener('drillToLogs', received)
    try {
      render(<TopIPPairs filters={filters} zoneFilter={{ interface_in: 'br20', interface_out: 'br30' }} />)
      fireEvent.click(await screen.findByText('443/TCP'))
      expect(fetchIPPairs.mock.lastCall[0]).toMatchObject({ ...filters, interface_in: 'br20', interface_out: 'br30' })
      expect(received.mock.lastCall[0].detail).toMatchObject({ ...filters, src_ip: pair.src_ip, dst_ip: pair.dst_ip, dst_port: 443, protocol: 'TCP', interface_in: 'br20', interface_out: 'br30' })
    } finally { window.removeEventListener('drillToLogs', received) }
  })

  it('sends the identical host exclusions and cross-filter to the CSV endpoint', async () => {
    const request = vi.fn().mockResolvedValue({ ok: true, blob: async () => new Blob(['example csv']) })
    vi.stubGlobal('fetch', request)
    URL.createObjectURL = vi.fn(() => 'blob:example')
    URL.revokeObjectURL = vi.fn()
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
    await exportCsv(filters, { type: 'src_ip', value: '192.0.2.10' }, { interface_in: 'br20', interface_out: 'br30' })
    const url = new URL(request.mock.lastCall[0], 'https://example.test')
    expect(url.pathname).toBe('/api/stats/ip-pairs/csv')
    expect(Object.fromEntries(url.searchParams)).toEqual({ ...filters, src_ip: '192.0.2.10', interface_in: 'br20', interface_out: 'br30' })
    expect(URL.revokeObjectURL).toHaveBeenCalledWith('blob:example')
  })
})
