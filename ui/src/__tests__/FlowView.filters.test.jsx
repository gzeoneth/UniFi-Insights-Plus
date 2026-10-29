import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import FlowView from '../components/FlowView'
import { createSavedView, fetchFlowGraph, fetchHostDetail, fetchIPPairs, fetchSavedViews, fetchZoneMatrix } from '../api'
import { TR_KEY } from '../utils'

vi.mock('../api', async original => ({
  ...await original(),
  fetchFlowGraph: vi.fn(), fetchIPPairs: vi.fn(), fetchZoneMatrix: vi.fn(), fetchHostDetail: vi.fn(),
  fetchSavedViews: vi.fn(), createSavedView: vi.fn(), deleteSavedView: vi.fn(),
}))

const rules = [{ field: 'ip', operator: 'exclude', value: '192.0.2.10,198.51.100.0/24' }]
const ruleParam = JSON.stringify(rules)
const flush = async () => { await act(async () => { await Promise.resolve() }) }
const applyRules = () => {
  fireEvent.click(screen.getByText('Include / exclude hosts and traffic'))
  fireEvent.click(screen.getByRole('button', { name: 'Add condition' }))
  fireEvent.change(screen.getByLabelText('Value 1'), { target: { value: rules[0].value } })
  fireEvent.click(screen.getByRole('button', { name: 'Apply filters' }))
}

beforeEach(() => {
  vi.clearAllMocks()
  sessionStorage.clear(); localStorage.clear()
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' })
  vi.stubGlobal('ResizeObserver', class { observe() {} disconnect() {} })
  fetchSavedViews.mockResolvedValue({ views: [] })
  createSavedView.mockResolvedValue({ id: 1 })
  fetchFlowGraph.mockResolvedValue({ nodes: [], links: [], total_events: 0 })
  fetchIPPairs.mockResolvedValue({ pairs: [] })
  fetchZoneMatrix.mockResolvedValue({ cells: [], interfaces: [], labels: {} })
  fetchHostDetail.mockResolvedValue({ ip: '203.0.113.20', summary: {} })
})
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

describe('Flow conditions across panels and saved views', () => {
  it('applies a host/CIDR exclusion to graph, pairs, host details and matrix only after Apply', async () => {
    render(<FlowView />)
    await waitFor(() => expect(fetchIPPairs).toHaveBeenCalledOnce())
    fireEvent.click(screen.getByText('Include / exclude hosts and traffic'))
    fireEvent.click(screen.getByRole('button', { name: 'Add condition' }))
    fireEvent.change(screen.getByLabelText('Value 1'), { target: { value: rules[0].value } })
    await flush()
    expect(fetchFlowGraph).toHaveBeenCalledOnce()
    fireEvent.click(screen.getByRole('button', { name: 'Apply filters' }))
    await waitFor(() => expect(fetchIPPairs.mock.lastCall[0].filter_rules).toBe(ruleParam))
    expect(fetchFlowGraph.mock.lastCall[0].filter_rules).toBe(ruleParam)
    expect(fetchFlowGraph.mock.lastCall[1].signal).toBeInstanceOf(AbortSignal)

    fireEvent.change(screen.getByLabelText('Search by IP address'), { target: { value: '203.0.113.20' } })
    fireEvent.keyDown(screen.getByLabelText('Search by IP address'), { key: 'Enter' })
    await waitFor(() => expect(fetchHostDetail).toHaveBeenCalled())
    expect(fetchHostDetail.mock.lastCall[0]).toMatchObject({ ip: '203.0.113.20', filter_rules: ruleParam })

    fireEvent.click(screen.getByRole('button', { name: 'Zone Matrix' }))
    await waitFor(() => expect(fetchZoneMatrix).toHaveBeenCalledOnce())
    expect(fetchZoneMatrix.mock.lastCall[0].filter_rules).toBe(ruleParam)
    expect(JSON.parse(localStorage.getItem('flowview_filters')).filter_rules).toEqual(rules)
  })

  it('migrates session conditions before the first request and saves them with the flow view', async () => {
    sessionStorage.setItem('flowview_filters', JSON.stringify({ filter_rules: rules }))
    render(<FlowView />)
    await waitFor(() => expect(fetchIPPairs).toHaveBeenCalledOnce())
    expect(fetchFlowGraph.mock.calls.every(([p]) => p.filter_rules === ruleParam)).toBe(true)
    expect(fetchIPPairs.mock.calls.every(([p]) => p.filter_rules === ruleParam)).toBe(true)
    fireEvent.click(screen.getAllByRole('button', { name: 'Menu' })[0])
    fireEvent.change(screen.getByPlaceholderText('View name...'), { target: { value: 'Exclude example hosts' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save', exact: true }))
    await waitFor(() => expect(createSavedView).toHaveBeenCalledOnce())
    expect(createSavedView.mock.lastCall).toEqual(['Exclude example hosts', expect.objectContaining({ filter_rules: rules })])
    expect(sessionStorage.getItem('flowview_filters')).toBeNull()
    expect(JSON.parse(localStorage.getItem('flowview_filters')).filter_rules).toEqual(rules)
  })

  it('restores filters, host selection, panel and pair limit after a new browser session', async () => {
    const first = render(<FlowView />)
    await waitFor(() => expect(fetchIPPairs).toHaveBeenCalledOnce())
    applyRules()
    fireEvent.click(screen.getByRole('button', { name: '1h', exact: true }))
    fireEvent.click(screen.getByRole('button', { name: 'allow', exact: true }))
    fireEvent.change(screen.getByLabelText('Top N'), { target: { value: '22' } })
    fireEvent.change(screen.getByLabelText('Number of IP pairs'), { target: { value: '50' } })
    fireEvent.change(screen.getByLabelText('Search by IP address'), { target: { value: '203.0.113.20' } })
    fireEvent.keyDown(screen.getByLabelText('Search by IP address'), { key: 'Enter' })
    fireEvent.click(screen.getByRole('button', { name: 'Zone Matrix' }))
    await waitFor(() => expect(fetchZoneMatrix).toHaveBeenCalled())
    await waitFor(() => expect(JSON.parse(localStorage.getItem('flowview_filters')).activePanel).toBe('zone-matrix'))
    const saved = JSON.parse(localStorage.getItem('flowview_filters'))
    expect(saved).toMatchObject({ topN: 22, activeActions: ['block'], hostIp: '203.0.113.20', filter_rules: rules })
    expect(saved).not.toHaveProperty('expandedRow')
    first.unmount()
    sessionStorage.clear()
    vi.clearAllMocks()
    render(<FlowView />)
    await waitFor(() => expect(fetchZoneMatrix).toHaveBeenCalledOnce())
    await waitFor(() => expect(fetchIPPairs).toHaveBeenCalledOnce())
    expect(fetchFlowGraph).not.toHaveBeenCalled()
    expect(fetchZoneMatrix.mock.lastCall[0]).toMatchObject({ time_range: '1h', rule_action: 'block', filter_rules: ruleParam })
    expect(fetchIPPairs.mock.lastCall[0]).toMatchObject({ time_range: '1h', limit: 50, filter_rules: ruleParam })
    expect(fetchHostDetail.mock.lastCall[0]).toMatchObject({ ip: '203.0.113.20', filter_rules: ruleParam })
    fireEvent.click(screen.getByRole('button', { name: 'Flow Graph', exact: true }))
    await waitFor(() => expect(fetchFlowGraph).toHaveBeenCalled())
    expect(fetchFlowGraph.mock.lastCall[0]).toMatchObject({ top_n: 22, ip: '203.0.113.20' })
    expect(screen.getByLabelText('Search by IP address').value).toBe('203.0.113.20')
  })

  it('restores a custom time window and cross-filter before queries start', async () => {
    const from = '2026-01-10T10:00:00Z', to = '2026-01-10T11:00:00Z'
    localStorage.setItem('flowview_filters', JSON.stringify({
      activePanel: 'zone-matrix', timeFrom: from, timeTo: to, filter_rules: rules,
      zoneFilter: { interface_in: 'br20', interface_out: 'br30', in_label: 'Example A', out_label: 'Example B' },
      filtersExpanded: true, advancedExpanded: false,
    }))
    render(<FlowView />)
    await waitFor(() => expect(fetchIPPairs).toHaveBeenCalled())
    expect(fetchIPPairs.mock.calls.every(([p]) => p.time_range === null && p.time_from === from && p.time_to === to && p.interface_in === 'br20' && p.interface_out === 'br30')).toBe(true)
    expect(screen.getByText(/Include \/ exclude hosts and traffic/).closest('details').open).toBe(false)
    expect(screen.getByRole('button', { name: /Filters \(/ }).getAttribute('aria-expanded')).toBe('true')
    fireEvent.click(screen.getByRole('button', { name: 'Reset', exact: true }))
    await waitFor(() => expect(JSON.parse(localStorage.getItem('flowview_filters')).zoneFilter).toBeNull())
    expect(JSON.parse(localStorage.getItem('flowview_filters'))).toMatchObject({ timeFrom: null, timeTo: null, filter_rules: [] })
  })

  it('ignores malformed stored shapes instead of sending invalid graph parameters', async () => {
    localStorage.setItem('flowview_filters', JSON.stringify({ dims: ['src_ip', 'src_ip', 4], topN: -1,
      activeActions: 'block', activeDirections: {}, filter_rules: [null], hostIp: 'not-an-ip',
      activePanel: 'unknown', timeFrom: 'invalid', timeTo: 5 }))
    localStorage.setItem('unifi-log-insight:flow-pair-limit', '999')
    render(<FlowView />)
    await waitFor(() => expect(fetchIPPairs).toHaveBeenCalledOnce())
    expect(fetchFlowGraph.mock.lastCall[0]).toMatchObject({ dimensions: 'src_ip,dst_port,dst_ip', top_n: 15, filter_rules: null, rule_action: null, direction: null, time_from: null, time_to: null })
    expect(fetchIPPairs.mock.lastCall[0].limit).toBe(25)
    expect(fetchHostDetail).not.toHaveBeenCalled()
    expect(screen.queryByLabelText('Value 1')).toBeNull()
  })

  it('does not restore a saved-view label after another view changed the shared time range', async () => {
    localStorage.setItem('flowview_filters', JSON.stringify({ activeViewName: 'Example last hour', timeRange: '1h', filter_rules: rules }))
    localStorage.setItem(TR_KEY, '7d')
    render(<FlowView />)
    await waitFor(() => expect(fetchIPPairs).toHaveBeenCalled())
    expect(fetchFlowGraph.mock.calls[0][0].time_range).toBe('7d')
    expect(screen.queryByTitle('Clear saved view label')).toBeNull()
    expect(JSON.parse(localStorage.getItem('flowview_filters')).activeViewName).toBeNull()
  })

  it('loads saved conditions and clears them when loading an older view without conditions', async () => {
    fetchSavedViews.mockResolvedValue({ views: [
      { id: 1, name: 'Filtered flow', filters: { dims: ['src_ip', 'dst_port', 'dst_ip'], filter_rules: rules } },
      { id: 2, name: 'Original flow', filters: { dims: ['src_ip', 'dst_port', 'dst_ip'] } },
    ] })
    render(<FlowView />)
    await waitFor(() => expect(fetchIPPairs).toHaveBeenCalledOnce())
    const load = async name => {
      fireEvent.click(screen.getAllByRole('button', { name: 'Menu' })[0])
      fireEvent.click(screen.getByRole('button', { name: 'Load View' }))
      fireEvent.click(await screen.findByRole('button', { name, exact: true }))
      await flush()
    }
    await load('Filtered flow')
    await waitFor(() => expect(fetchIPPairs.mock.lastCall[0].filter_rules).toBe(ruleParam))
    expect(screen.getByLabelText('Value 1').value).toBe(rules[0].value)
    await load('Original flow')
    expect(JSON.parse(localStorage.getItem('flowview_filters')).filter_rules).toEqual([])
    expect(screen.queryByLabelText('Value 1')).toBeNull()
    // The unfiltered scope may use its own fresh cache; it must never reuse filtered data.
    expect(screen.getAllByText('No flow data for this time range').length).toBeGreaterThan(0)
  })

  it('keeps the pair query deferred until the matching graph request settles', async () => {
    let finish
    fetchFlowGraph.mockImplementationOnce(() => new Promise(resolve => { finish = resolve }))
    render(<FlowView />)
    expect(fetchIPPairs).not.toHaveBeenCalled()
    applyRules()
    expect(fetchFlowGraph).toHaveBeenCalledOnce()
    expect(fetchIPPairs).not.toHaveBeenCalled()
    await act(async () => finish({ nodes: [], links: [], total_events: 9 }))
    await waitFor(() => expect(fetchIPPairs).toHaveBeenCalledOnce())
    expect(fetchFlowGraph).toHaveBeenCalledTimes(2)
    expect(fetchIPPairs.mock.lastCall[0].filter_rules).toBe(ruleParam)
  })

  it('shows a query error rather than an empty-flow success', async () => {
    fetchIPPairs.mockRejectedValueOnce(new Error('Example query unavailable'))
    render(<FlowView />)
    await screen.findByRole('alert')
    expect(screen.getByRole('alert').textContent).toBe('Could not load IP pairs for the current filters. Refresh to try again.')
    expect(screen.getAllByText('No flow data for this time range')).toHaveLength(1) // graph only
  })
})
