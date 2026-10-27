import { useEffect } from 'react'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import ExclusionProfiles, { EXCLUSION_DEFAULT_KEY, ExclusionProfileProvider } from '../components/ExclusionProfiles'
import FlowView from '../components/FlowView'
import LogStream from '../components/LogStream'
import { createSavedView, fetchIPPairs, fetchLogs, fetchSavedViews } from '../api'

vi.mock('../api', () => ({
  fetchSavedViews: vi.fn(), createSavedView: vi.fn(), deleteSavedView: vi.fn(), fetchExclusionPreview: vi.fn(),
  fetchLogs: vi.fn(), fetchLog: vi.fn(), fetchLogCountsByType: vi.fn(),
  fetchIPPairs: vi.fn(),
  getExportUrl: params => `/api/export?${new URLSearchParams(Object.entries(params).filter(([, value]) => value != null))}`,
}))
vi.mock('../components/FilterBar', () => ({ default: () => <div /> }))
vi.mock('../components/LogTable', () => ({ default: ({ logs, loading }) => <div data-testid="rows">{loading ? 'loading' : logs.map(row => row.id).join(',')}</div> }))
vi.mock('../components/Pagination', () => ({ default: () => <div /> }))
vi.mock('../components/SankeyChart', () => ({ default: ({ filters, requestKey, onDataLoaded }) => {
  useEffect(() => { onDataLoaded(requestKey) }, [requestKey, onDataLoaded])
  return <output data-testid="sankey-filters">{JSON.stringify(filters)}</output>
} }))
vi.mock('../components/TopIPPairs', () => ({ default: ({ filters, savedViews, onIpClick }) => <>
  <output data-testid="pair-filters">{JSON.stringify(filters)}</output>
  <output data-testid="flow-views">{savedViews.map(view => view.name).join(',')}</output>
  <button onClick={() => onIpClick('192.0.2.10', 0)}>Inspect host</button>
</> }))
vi.mock('../components/HostSlidePanel', () => ({ default: ({ filters }) => <output data-testid="host-filters">{JSON.stringify(filters)}</output> }))
vi.mock('../components/ZoneMatrix', () => ({ default: ({ filters }) => <output data-testid="zone-filters">{JSON.stringify(filters)}</output> }))

const groups = [{ conditions: [{ field: 'hostname_exact', operator: 'include', value: 'gateway.example.test' }] }]
const serialized = JSON.stringify(groups)
const profile = { id: 7, name: 'Routine events', filters: { view_type: 'exclusions', exclude_groups: groups } }

beforeEach(() => {
  vi.clearAllMocks(); localStorage.clear(); sessionStorage.clear()
  localStorage.setItem(EXCLUSION_DEFAULT_KEY, '7')
  fetchSavedViews.mockResolvedValue({ views: [profile, { id: 8, name: 'Traffic view', filters: {} }] })
  fetchLogs.mockImplementation(async params => ({ data: [{ id: params.exclude_groups ? 'filtered' : 'all' }], total: 1, page: 1, pages: 1, view_counts: { total: 3, visible: params.exclude_groups ? 1 : 3, hidden: params.exclude_groups ? 2 : 0 } }))
})

describe('exclusions across views', () => {
  it('loads built-in log scopes without inherited drill filters or creating saved views', async () => {
    render(<ExclusionProfileProvider><ExclusionProfiles activeTab="logs" /><LogStream drillFilters={{ src_ip: '192.0.2.10', dst_ip: '198.51.100.20', dst_port: 443, time_range: '7d' }} /></ExclusionProfileProvider>)
    await waitFor(() => expect(screen.getByTestId('rows')).toHaveTextContent('filtered'))
    const select = screen.getByLabelText('Log view')
    expect(select.querySelector('optgroup[label="Built-in"]')).toBeTruthy()
    expect(select.querySelector('optgroup[label="Saved"]')).toBeTruthy()
    fireEvent.change(select, { target: { value: 'builtin:dns' } })
    await waitFor(() => expect(fetchLogs.mock.lastCall[0]).toMatchObject({ time_range: '24h', log_type: 'dns', src_ip: null, dst_ip: null, dst_port: null, filter_rules: null, exclude_groups: serialized, page: 1 }))
    expect(screen.getByLabelText('Selected log view scope')).toHaveTextContent('The active exclusion profile also applies.')
    expect(screen.getByLabelText('View event counts')).toHaveTextContent('2 hidden by profile')
    expect(createSavedView).not.toHaveBeenCalled()
    expect(screen.queryByRole('button', { name: 'Delete saved view' })).toBeNull()
    fireEvent.change(select, { target: { value: 'builtin:blocked-private' } })
    await waitFor(() => expect(fetchLogs.mock.lastCall[0]).toMatchObject({ log_type: 'firewall', rule_action: 'block', direction: null }))
    expect(JSON.parse(fetchLogs.mock.lastCall[0].filter_rules).map(rule => rule.field)).toEqual(['src_ip', 'dst_ip'])
    expect(screen.getByLabelText('Selected log view scope')).toHaveTextContent('including private gateway and transit addresses')
    fireEvent.change(select, { target: { value: 'builtin:discovery' } })
    await waitFor(() => expect(fetchLogs.mock.lastCall[0].protocol).toBe('udp'))
    expect(JSON.parse(fetchLogs.mock.lastCall[0].filter_rules)).toEqual([{ field: 'port', operator: 'include', value: '5353,1900' }])
    fireEvent.change(screen.getByLabelText('Value 1'), { target: { value: '5353' } })
    fireEvent.click(screen.getByRole('button', { name: 'Apply filters' }))
    await waitFor(() => expect(screen.getByLabelText('Log view')).toHaveValue(''))
    expect(screen.queryByLabelText('Selected log view scope')).toBeNull()
  })

  it.each(['all', 'ips', 'unparsed-cef'])('bypasses the profile for %s and uses the same scope for counts and export', async preset => {
    render(<ExclusionProfileProvider><ExclusionProfiles activeTab="logs" /><LogStream /></ExclusionProfileProvider>)
    await waitFor(() => expect(screen.getByTestId('rows')).toHaveTextContent('filtered'))
    fireEvent.change(screen.getByLabelText('Log view'), { target: { value: `builtin:${preset}` } })
    await waitFor(() => expect(screen.getByTestId('rows')).toHaveTextContent('all'))
    expect(screen.getByLabelText('Show all (ignore profile)')).toBeChecked()
    expect(screen.getByLabelText('View event counts')).toHaveTextContent('0 hidden by profile')
    expect(localStorage.getItem(EXCLUSION_DEFAULT_KEY)).toBe('7')
    const params = fetchLogs.mock.lastCall[0]
    const url = new URL(screen.getByRole('link', { name: /Export CSV/ }).href)
    expect(params.exclude_groups).toBeNull()
    expect(url.searchParams.has('exclude_groups')).toBe(false)
    if (preset === 'all') expect(params.filter_rules).toBeNull()
    else {
      const expected = [{ field: 'security_event', operator: 'include', value: preset === 'ips' ? 'ips' : 'unparsed_cef' }]
      expect(JSON.parse(params.filter_rules)).toEqual(expected)
      expect(JSON.parse(url.searchParams.get('filter_rules'))).toEqual(expected)
    }
  })

  it('does not retain old IP pairs while a new profile is deferred or fails, and can restore its own cached scope', async () => {
    const { default: ActualTopIPPairs } = await vi.importActual('../components/TopIPPairs')
    fetchIPPairs.mockResolvedValueOnce({ pairs: [{ src_ip: '192.0.2.10', dst_ip: '198.51.100.20', dst_port: 443, protocol: 'tcp', allow_count: 5 }] })
    fetchIPPairs.mockRejectedValueOnce(new Error('unavailable'))
    const props = { filters: { time_range: '24h' }, refreshKey: 0, savedViews: [] }
    const { rerender } = render(<ActualTopIPPairs {...props} />)
    await screen.findByText('192.0.2.10')
    rerender(<ActualTopIPPairs {...props} filters={{ ...props.filters, exclude_groups: serialized }} deferFetch />)
    expect(screen.queryByText('192.0.2.10')).toBeNull()
    rerender(<ActualTopIPPairs {...props} filters={{ ...props.filters, exclude_groups: serialized }} />)
    await screen.findByText('Could not load IP pairs for the current filters. Refresh to try again.')
    expect(screen.queryByText('192.0.2.10')).toBeNull()
    rerender(<ActualTopIPPairs {...props} />)
    await screen.findByText('192.0.2.10')
    expect(screen.queryByRole('alert')).toBeNull()
    expect(fetchIPPairs).toHaveBeenCalledTimes(2)
  })

  it('passes the active profile to graph, pairs, zone and host views and excludes profiles from flow saved views', async () => {
    render(<ExclusionProfileProvider><ExclusionProfiles activeTab="flow-view" /><FlowView /></ExclusionProfileProvider>)
    await waitFor(() => expect(JSON.parse(screen.getByTestId('sankey-filters').textContent).exclude_groups).toBe(serialized))
    expect(JSON.parse(screen.getByTestId('pair-filters').textContent).exclude_groups).toBe(serialized)
    expect(screen.getByTestId('flow-views')).toHaveTextContent('Traffic view')
    expect(screen.getByTestId('flow-views')).not.toHaveTextContent('Routine events')
    fireEvent.click(screen.getByText('Inspect host'))
    expect(JSON.parse(screen.getByTestId('host-filters').textContent).exclude_groups).toBe(serialized)
    fireEvent.click(screen.getByRole('button', { name: 'Zone Matrix' }))
    await waitFor(() => expect(JSON.parse(screen.getByTestId('zone-filters').textContent).exclude_groups).toBe(serialized))
    fireEvent.click(screen.getByLabelText('Show all (ignore profile)'))
    for (const id of ['pair-filters', 'host-filters', 'zone-filters']) expect(JSON.parse(screen.getByTestId(id).textContent).exclude_groups).toBeNull()
  })

  it('uses the same profile for Log Stream results, counts and CSV, then refetches when bypassed', async () => {
    render(<ExclusionProfileProvider><ExclusionProfiles activeTab="logs" /><LogStream /></ExclusionProfileProvider>)
    await waitFor(() => expect(screen.getByTestId('rows')).toHaveTextContent('filtered'))
    expect(screen.getByLabelText('View event counts')).toHaveTextContent('2 hidden by profile')
    expect(new URL(screen.getByRole('link', { name: /Export CSV/ }).href).searchParams.get('exclude_groups')).toBe(serialized)
    fireEvent.click(screen.getByLabelText('Show all (ignore profile)'))
    await waitFor(() => expect(screen.getByTestId('rows')).toHaveTextContent('all'))
    expect(screen.getByLabelText('View event counts')).toHaveTextContent('0 hidden by profile')
    expect(new URL(screen.getByRole('link', { name: /Export CSV/ }).href).searchParams.has('exclude_groups')).toBe(false)
  })

  it('does not show previously unfiltered rows as a filtered result when loading the profile fails', async () => {
    fetchLogs.mockImplementation(async params => {
      if (params.exclude_groups) throw new Error('unavailable')
      return { data: [{ id: 'unfiltered-old-row' }], total: 1, page: 1, pages: 1 }
    })
    render(<ExclusionProfileProvider><ExclusionProfiles activeTab="logs" /><LogStream /></ExclusionProfileProvider>)
    await screen.findByText('Could not load events for the current filters. Refresh to try again.')
    expect(screen.getByTestId('rows')).not.toHaveTextContent('unfiltered-old-row')
  })
})
