import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import RuleUsage from '../components/RuleUsage'
import { apiFetch, fetchSavedViews } from '../api'

vi.mock('../api', () => ({ apiFetch: vi.fn(), fetchSavedViews: vi.fn(), createSavedView: vi.fn(), deleteSavedView: vi.fn() }))

const response = { data: [], notice: 'Observed logs only.', limit: 200, truncated: false }
beforeEach(() => {
  vi.clearAllMocks()
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
    await screen.findByText('No matching logged events in this period.')
    await act(async () => resolveOld({ ...response, notice: 'Stale response must not be shown' }))
    expect(screen.queryByText('Stale response must not be shown')).toBeNull()
    expect(apiFetch.mock.calls[0][1].signal.aborted).toBe(true)
  })
})
