import { describe, it, expect, vi, beforeEach } from 'vitest'
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import SecuritySummary from '../components/SecuritySummary'
import { fetchSecuritySummary } from '../api'

vi.mock('../api', () => ({ fetchSecuritySummary: vi.fn() }))

const summary = {
  ips_blocked: 4, ips_allowed: 2, ips_unknown: 1,
  firewall_blocks: 8, reputation_alerts: 3,
  top_signatures: [{ ips_signature_id: '123', ips_signature: 'Synthetic detection', count: 7,
    ips_risk: 'medium', ips_severity: 7, last_seen: '2026-01-01T00:00:00Z' }],
}

beforeEach(() => vi.clearAllMocks())

describe('SecuritySummary', () => {
  it('shows IPS counts and signatures independently of IP reputation', async () => {
    fetchSecuritySummary.mockResolvedValue(summary)
    render(<SecuritySummary timeRange="7d" />)
    expect(screen.getByRole('status').textContent).toContain('Loading')
    await screen.findByText('Synthetic detection')
    for (const label of ['IPS blocked', 'IPS allowed', 'IPS action unknown', 'Firewall blocks', 'IP reputation >50']) {
      expect(screen.getByText(label)).toBeTruthy()
    }
    expect(screen.getByText('ID 123')).toBeTruthy()
    expect(screen.getByText('medium / 7/10')).toBeTruthy()
    expect(fetchSecuritySummary.mock.calls[0][0].time_range).toBe('7d')
    expect(fetchSecuritySummary.mock.calls[0][1].signal).toBeInstanceOf(AbortSignal)
  })

  it('distinguishes no events from a failed request and allows retry', async () => {
    fetchSecuritySummary.mockRejectedValueOnce(new Error('unavailable'))
    fetchSecuritySummary.mockResolvedValueOnce({ ...summary, top_signatures: [] })
    render(<SecuritySummary />)
    await screen.findByRole('alert')
    expect(screen.queryByText('No IPS events in this time range.')).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    await screen.findByText('No IPS events in this time range.')
    expect(screen.queryByRole('alert')).toBeNull()
  })

  it('discards a late response after the selected time range changes', async () => {
    let resolveOld
    fetchSecuritySummary.mockImplementationOnce(() => new Promise(resolve => { resolveOld = resolve }))
    fetchSecuritySummary.mockResolvedValueOnce({ ...summary, ips_blocked: 9 })
    const { rerender } = render(<SecuritySummary timeRange="24h" />)
    const oldSignal = fetchSecuritySummary.mock.calls[0][1].signal
    rerender(<SecuritySummary timeRange="1h" />)
    await screen.findByText('Synthetic detection')
    expect(oldSignal.aborted).toBe(true)
    await act(async () => resolveOld({ ...summary, ips_blocked: 999 }))
    const blocked = screen.getByText('IPS blocked').parentElement
    expect(within(blocked).getByText('9')).toBeTruthy()
    expect(screen.queryByText('999')).toBeNull()
  })

  it('passes custom bounds without losing the selected range', async () => {
    fetchSecuritySummary.mockResolvedValue(summary)
    render(<SecuritySummary timeRange="24h" timeFrom="2026-01-01T00:00:00Z" timeTo="2026-01-02T00:00:00Z" />)
    await waitFor(() => expect(fetchSecuritySummary).toHaveBeenCalled())
    expect(fetchSecuritySummary.mock.calls[0][0]).toEqual({
      time_range: '24h', time_from: '2026-01-01T00:00:00Z', time_to: '2026-01-02T00:00:00Z',
    })
  })
})
