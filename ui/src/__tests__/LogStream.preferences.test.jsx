import { act, cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import LogStream from '../components/LogStream'
import { fetchLogs } from '../api'
import { TR_KEY } from '../utils'

const storageKey = 'unifi-log-insight:log-filters:v1'
const rules = [{ field: 'ip', operator: 'exclude', value: '198.51.100.0/24' }]
const applied = {
  log_type: 'firewall', rule_action: 'block', direction: 'inter_vlan',
  ip: '192.0.2.10', src_ip: '192.0.2.0/24', dst_ip: '203.0.113.20',
  rule_name: 'Example rule', search: 'example marker', service: 'HTTPS',
  country: '!AA', asn: 'Example network', dst_port: '!443', src_port: '50000',
  protocol: 'TCP', interface: 'br20', vpn_only: true, threat_min: 30,
  filter_rules: JSON.stringify(rules), time_range: null,
  time_from: '2026-01-01T00:00:00Z', time_to: '2026-01-01T01:00:00Z',
  sort: 'timestamp', order: 'asc', per_page: 200,
}
vi.mock('../api', () => ({
  fetchLogs: vi.fn(), fetchLog: vi.fn(), fetchLogCountsByType: vi.fn(), getExportUrl: () => '/api/export',
}))
vi.mock('../components/FilterBar', () => ({ default: ({ filters, onChange }) => <>
  <output data-testid="filters">{JSON.stringify(filters)}</output>
  <button onClick={() => onChange({ ...filters, ...applied })}>Apply example filters</button>
  <button onClick={() => onChange({ ...filters, time_range: '6h', time_from: null, time_to: null })}>Choose six hours</button>
  <button onClick={() => onChange({ time_range: '24h', per_page: filters.per_page })}>Reset filters</button>
</> }))
vi.mock('../components/FieldFilters', async importOriginal => ({ ...await importOriginal(), default: () => null }))
vi.mock('../components/LogTable', () => ({ default: ({ hiddenColumns }) => <output data-testid="columns">{JSON.stringify([...hiddenColumns])}</output> }))

const flush = async () => { await act(async () => { await Promise.resolve() }) }
const renderView = async props => { const view = render(<LogStream {...props} />); await flush(); return view }
const filters = () => JSON.parse(screen.getByTestId('filters').textContent)
beforeEach(() => {
  vi.clearAllMocks(); localStorage.clear(); sessionStorage.clear()
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' })
  fetchLogs.mockResolvedValue({ data: [], total: null, pages: null, has_more: true, page_cursor: 'window-token', next_cursor: 'next-token' })
})
afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.useRealTimers() })

describe('durable Log Stream preferences', () => {
  it('restores every applied filter, exact dates, page size, pause and hidden columns after a new browser session', async () => {
    const first = await renderView()
    fireEvent.click(screen.getByRole('button', { name: 'Apply example filters' })); await flush()
    fireEvent.click(screen.getByRole('button', { name: 'Live' }))
    fireEvent.click(screen.getByRole('button', { name: 'Columns' }))
    fireEvent.click(screen.getByRole('checkbox', { name: 'Country' }))
    fireEvent.click(screen.getByRole('button', { name: 'Next page' })); await flush()
    expect(fetchLogs.mock.lastCall[0]).toMatchObject({ page: 2, cursor: 'next-token' })
    first.unmount(); sessionStorage.clear(); fetchLogs.mockClear()
    await renderView()
    expect(filters()).toMatchObject(applied)
    expect(fetchLogs.mock.calls[0][0]).toMatchObject({ ...applied, page: 1, cursor: null, count_mode: 'none' })
    expect(screen.getByRole('button', { name: 'Paused' })).toBeTruthy()
    expect(screen.getByTestId('columns')).toHaveTextContent('["country"]')
    const saved = JSON.parse(localStorage.getItem(storageKey))
    for (const key of ['page', 'cursor', 'page_cursor', 'next_cursor', 'data', 'count_mode']) expect(saved).not.toHaveProperty(key)
  })

  it('keeps a relative window rolling and uses the latest shared selection from another view', async () => {
    const first = await renderView()
    fireEvent.click(screen.getByRole('button', { name: 'Choose six hours' })); await flush()
    expect(localStorage.getItem(TR_KEY)).toBe('6h')
    first.unmount(); sessionStorage.clear()
    localStorage.setItem(TR_KEY, '1h')
    await renderView()
    expect(fetchLogs.mock.lastCall[0]).toMatchObject({ time_range: '1h', time_from: null, time_to: null, cursor: null })
  })

  it('migrates earlier type/action/direction/page-size and session time choices', async () => {
    localStorage.setItem('unifi-log-insight:log-types', 'dns,firewall')
    localStorage.setItem('unifi-log-insight:rule-action', 'block')
    localStorage.setItem('unifi-log-insight:direction', 'outbound')
    localStorage.setItem('unifi-log-insight:rows-per-page', '500')
    sessionStorage.setItem(TR_KEY, '7d')
    const first = await renderView()
    expect(fetchLogs.mock.lastCall[0]).toMatchObject({ log_type: 'dns,firewall', rule_action: 'block', direction: 'outbound', per_page: 500, time_range: '7d' })
    expect(sessionStorage.getItem(TR_KEY)).toBeNull()
    first.unmount(); sessionStorage.clear()
    await renderView()
    expect(fetchLogs.mock.lastCall[0]).toMatchObject({ log_type: 'dns,firewall', time_range: '7d', per_page: 500 })
  })

  it('discards invalid stored types and dates without copying unknown keys to requests', async () => {
    localStorage.setItem(storageKey, JSON.stringify({ ip: ['192.0.2.10'], per_page: 100000, sort: 'unknown', order: 'invalid',
      time_from: 'not-a-date', time_to: {}, filter_rules: [{ field: 'unknown', operator: 'include', value: 'x' }],
      service: 'HTTPS', page: 20, cursor: 'stale', token: 'example-not-a-credential', data: [{ id: 1 }] }))
    localStorage.setItem('unifi-log-insight:hidden-columns', JSON.stringify(['unknown']))
    localStorage.setItem('unifi-log-insight:log-auto-refresh', 'not-a-boolean')
    await renderView()
    expect(fetchLogs.mock.lastCall[0]).toMatchObject({ ip: null, per_page: 50, sort: 'timestamp', order: 'desc', time_from: null, time_to: null, filter_rules: null, service: 'HTTPS', page: 1, cursor: null })
    expect(screen.getByRole('button', { name: 'Live' })).toBeTruthy()
    expect(screen.getByTestId('columns')).toHaveTextContent('[]')
    expect(fetchLogs.mock.lastCall[0]).not.toHaveProperty('token')
    expect(JSON.parse(localStorage.getItem(storageKey))).not.toHaveProperty('data')
  })

  it.each(['{broken', 'null', '[]', 'false'])('falls back when the filter snapshot is %s', async value => {
    localStorage.setItem(storageKey, value)
    await renderView()
    expect(fetchLogs.mock.lastCall[0]).toMatchObject({ time_range: '24h', per_page: 50, page: 1, ip: null })
  })

  it('gives an explicit drill priority over stored scope and persists its exact custom dates', async () => {
    localStorage.setItem(storageKey, JSON.stringify(applied))
    const drill = { src_ip: '192.0.2.99', protocol: 'UDP', time_from: '2026-02-01T01:00:00Z', time_to: '2026-02-01T02:00:00Z' }
    const first = await renderView({ drillFilters: drill })
    expect(fetchLogs.mock.calls[0][0]).toMatchObject({ ...drill, time_range: null, search: null, ip: null, service: null, filter_rules: null })
    first.unmount(); sessionStorage.clear(); fetchLogs.mockClear()
    await renderView()
    expect(fetchLogs.mock.calls[0][0]).toMatchObject({ ...drill, time_range: null, page: 1 })
  })

  it('preserves absolute dates from legacy snapshots that also contain a relative range', async () => {
    localStorage.setItem(storageKey, JSON.stringify({ ...applied, time_range: '24h' }))
    localStorage.setItem(TR_KEY, '6h')
    const first = await renderView()
    expect(fetchLogs.mock.calls[0][0]).toMatchObject({ time_range: null, time_from: applied.time_from, time_to: applied.time_to })
    expect(JSON.parse(localStorage.getItem(storageKey))).toMatchObject({ time_range: null, time_from: applied.time_from, time_to: applied.time_to })
    first.unmount(); sessionStorage.clear(); fetchLogs.mockClear()
    await renderView()
    expect(fetchLogs.mock.calls[0][0]).toMatchObject({ time_range: null, time_from: applied.time_from, time_to: applied.time_to })
  })

  it('keeps a reset empty rather than restoring older individual keys again', async () => {
    localStorage.setItem('unifi-log-insight:rule-action', 'block')
    localStorage.setItem(storageKey, JSON.stringify(applied))
    const first = await renderView()
    fireEvent.click(screen.getByRole('button', { name: 'Reset filters' })); await flush()
    first.unmount(); await renderView()
    expect(fetchLogs.mock.lastCall[0]).toMatchObject({ time_range: '24h', rule_action: null, ip: null, filter_rules: null, time_from: null, time_to: null, per_page: 200 })
  })

  it('loads one fresh page after restoring pause without restarting background polling', async () => {
    vi.useFakeTimers()
    localStorage.setItem('unifi-log-insight:log-auto-refresh', 'false')
    await renderView()
    expect(fetchLogs).toHaveBeenCalledOnce()
    await act(async () => { await vi.advanceTimersByTimeAsync(20000) })
    expect(fetchLogs).toHaveBeenCalledOnce()
    fireEvent.click(screen.getByRole('button', { name: /Refresh/ })); await flush()
    expect(fetchLogs).toHaveBeenCalledTimes(2)
  })
})
