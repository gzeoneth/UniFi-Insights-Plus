import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import RuleUsage from '../components/RuleUsage'
import { apiFetch, fetchSavedViews } from '../api'
import { TR_KEY } from '../utils'

vi.mock('../api', () => ({ apiFetch: vi.fn(), fetchSavedViews: vi.fn(), createSavedView: vi.fn(), deleteSavedView: vi.fn() }))

const response = { data: [], notice: 'Observed logs only.', limit: 200, truncated: false }
beforeEach(() => {
  vi.clearAllMocks()
  localStorage.clear(); sessionStorage.clear()
  apiFetch.mockResolvedValue(response)
  fetchSavedViews.mockResolvedValue({ views: [] })
})

describe('RuleUsage', () => {
  it('forwards every saved basic filter together with advanced rules', async () => {
    const rules = [{ field: 'ip', operator: 'exclude', value: '203.0.113.0/24' }]
    const filters = { view_type: 'logs', time_range: '7d', rule_name: 'Synthetic rule',
      src_ip: '10.0.0.1', dst_port: '443', protocol: 'tcp', country: 'US',
      log_type: 'firewall', rule_action: 'allow', threat_min: 0, vpn_only: false, filter_rules: rules }
    fetchSavedViews.mockResolvedValue({ views: [{ id: 1, name: 'Scoped rule', filters }] })
    render(<RuleUsage />)
    await screen.findByRole('option', { name: 'Scoped rule' })
    fireEvent.change(screen.getByLabelText('Saved log view'), { target: { value: '1' } })
    await waitFor(() => expect(apiFetch).toHaveBeenCalledTimes(2))
    const params = new URL(apiFetch.mock.calls[1][0], 'https://example.test').searchParams
    expect(params.get('src_ip')).toBe('10.0.0.1')
    expect(params.get('dst_port')).toBe('443')
    expect(params.get('protocol')).toBe('tcp')
    expect(params.get('country')).toBe('US')
    expect(params.get('threat_min')).toBe('0')
    expect(params.get('vpn_only')).toBe('false')
    expect(JSON.parse(params.get('filter_rules'))).toEqual(rules)
    expect(params.has('view_type')).toBe(false)
  })

  it('ignores a late response for a previously selected rule', async () => {
    let resolveOld
    apiFetch.mockImplementationOnce(() => new Promise(resolve => { resolveOld = resolve }))
    render(<RuleUsage />)
    fireEvent.change(screen.getByLabelText('Rule name contains'), { target: { value: 'New rule' } })
    fireEvent.click(screen.getByText('Apply rule filter'))
    expect(apiFetch).toHaveBeenCalledTimes(1)
    await act(async () => resolveOld({ ...response, notice: 'Stale response must not be shown' }))
    await screen.findByText('No matching logged events in this period.')
    expect(screen.queryByText('Stale response must not be shown')).toBeNull()
    expect(apiFetch.mock.calls[0][1].signal.aborted).toBe(false)
  })
})

  it('loads rule totals without a separate count and changes to endpoint detail on demand', async () => {
    render(<RuleUsage />)
    await screen.findByText('No matching logged events in this period.')
    const first = new URL(apiFetch.mock.calls[0][0], 'https://example.test').searchParams
    expect(first.get('group_by')).toBe('rule')
    expect(first.get('count_mode')).toBe('none')
    expect(screen.queryByRole('columnheader', { name: 'Source' })).toBeNull()
    fireEvent.change(screen.getByLabelText('Group observations by'), { target: { value: 'endpoint' } })
    await screen.findByRole('columnheader', { name: 'Source' })
    expect(apiFetch.mock.lastCall[0]).toContain('group_by=endpoint')
    fireEvent.click(screen.getByText('Count matching events'))
    await waitFor(() => expect(apiFetch.mock.lastCall[0]).toContain('count_mode=exact'))
  })

  it('does not issue a database query for every typed rule-name character', async () => {
    render(<RuleUsage />)
    await screen.findByText('No matching logged events in this period.')
    fireEvent.change(screen.getByLabelText('Rule name contains'), { target: { value: 'A' } })
    fireEvent.change(screen.getByLabelText('Rule name contains'), { target: { value: 'Allow' } })
    expect(apiFetch).toHaveBeenCalledTimes(1)
    fireEvent.click(screen.getByText('Apply rule filter'))
    await waitFor(() => expect(apiFetch).toHaveBeenCalledTimes(2))
  })

  it('restores applied filters and grouping before the first query after reopening', async () => {
    const rules = [{ field: 'ip', operator: 'exclude', value: '203.0.113.0/24' }]
    fetchSavedViews.mockResolvedValue({ views: [{ id: 1, name: 'Example scope', filters: {
      view_type: 'logs', time_range: '7d', rule_name: 'Example allow', protocol: 'tcp', filter_rules: rules,
    } }] })
    const first = render(<RuleUsage />)
    await screen.findByRole('option', { name: 'Example scope' })
    fireEvent.change(screen.getByLabelText('Saved log view'), { target: { value: '1' } })
    fireEvent.change(screen.getByLabelText('Group observations by'), { target: { value: 'endpoint' } })
    await waitFor(() => expect(apiFetch.mock.lastCall[0]).toContain('group_by=endpoint'))
    first.unmount(); sessionStorage.clear(); apiFetch.mockClear()
    render(<RuleUsage />)
    await screen.findByText('No matching logged events in this period.')
    const params = new URL(apiFetch.mock.calls[0][0], 'https://example.test').searchParams
    expect(params.get('time_range')).toBe('7d')
    expect(params.get('rule_name')).toBe('Example allow')
    expect(params.get('protocol')).toBe('tcp')
    expect(params.get('group_by')).toBe('endpoint')
    expect(JSON.parse(params.get('filter_rules'))).toEqual(rules)
    expect(screen.getByLabelText('Rule name contains')).toHaveValue('Example allow')
    expect(params.has('page')).toBe(false)
    expect(params.has('view_type')).toBe(false)
  })

  it('ignores invalid saved filters without issuing a malformed query', async () => {
    localStorage.setItem('unifi-log-insight:rule-usage-filters', JSON.stringify({ time_range: 'bad', filter_rules: '[null]' }))
    localStorage.setItem('unifi-log-insight:rule-usage-grouping', JSON.stringify(['endpoint']))
    render(<RuleUsage />)
    await screen.findByText('No matching logged events in this period.')
    const params = new URL(apiFetch.mock.calls[0][0], 'https://example.test').searchParams
    expect(params.get('time_range')).toBe('24h')
    expect(params.get('group_by')).toBe('rule')
    expect(params.has('filter_rules')).toBe(false)
  })

  it('labels a restored custom window and clears it when selecting a shared relative period', async () => {
    localStorage.setItem('unifi-log-insight:rule-usage-filters', JSON.stringify({
      time_range: '24h', time_from: '2025-01-01T00:00:00Z', time_to: '2025-01-02T00:00:00Z', rule_name: 'Example rule',
    }))
    const first = render(<RuleUsage />)
    await screen.findByText('No matching logged events in this period.')
    expect(screen.getByLabelText('Rule observation period')).toHaveValue('custom')
    expect(screen.getByRole('option', { name: 'Custom date range' })).toBeDisabled()
    fireEvent.change(screen.getByLabelText('Rule observation period'), { target: { value: '180d' } })
    await waitFor(() => expect(apiFetch.mock.lastCall[0]).toContain('time_range=180d'))
    const changed = new URL(apiFetch.mock.lastCall[0], 'https://example.test').searchParams
    expect(changed.has('time_from')).toBe(false)
    expect(changed.has('time_to')).toBe(false)
    expect(localStorage.getItem(TR_KEY)).toBe('180d')
    first.unmount(); sessionStorage.clear(); apiFetch.mockClear()
    render(<RuleUsage />)
    await screen.findByText('No matching logged events in this period.')
    expect(screen.getByLabelText('Rule observation period')).toHaveValue('180d')
    const restored = new URL(apiFetch.mock.calls[0][0], 'https://example.test').searchParams
    expect(restored.get('time_range')).toBe('180d')
    expect(restored.get('rule_name')).toBe('Example rule')
    expect(restored.has('time_from')).toBe(false)
    expect(restored.has('time_to')).toBe(false)
  })

  it.each(['60d', '180d', '365d'])('uses the shared %s period when stored scope has no time bounds', async range => {
    localStorage.setItem(TR_KEY, range)
    localStorage.setItem('unifi-log-insight:rule-usage-filters', '{}')
    render(<RuleUsage />)
    await screen.findByText('No matching logged events in this period.')
    expect(screen.getByLabelText('Rule observation period')).toHaveValue(range)
    const params = new URL(apiFetch.mock.calls[0][0], 'https://example.test').searchParams
    expect(params.get('time_range')).toBe(range)
  })
