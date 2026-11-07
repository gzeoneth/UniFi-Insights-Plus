import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import SettingsPihole from '../components/SettingsPihole'
import { fetchPiholeSettings, updatePiholeSettings } from '../api'

vi.mock('../api', () => ({
  fetchPiholeSettings: vi.fn(),
  updatePiholeSettings: vi.fn(),
  testPiholeConnection: vi.fn(),
}))

const saved = {
  host: 'https://dns.example.test', enabled: true, password_set: true,
  poll_interval: 60, enrichment: 'both', dns_server: '',
  status: { connected: true },
}

beforeEach(() => {
  vi.clearAllMocks()
  fetchPiholeSettings.mockResolvedValue({ ...saved })
  updatePiholeSettings.mockResolvedValue({ success: true })
})

describe('Pi-hole DNS enrichment endpoint', () => {
  it('saves a DNS IP independently of web credentials or another connection test', async () => {
    render(<SettingsPihole />)
    const input = await screen.findByLabelText('DNS server for enrichment (optional)')
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled()
    fireEvent.change(input, { target: { value: '2001:db8::53' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(updatePiholeSettings).toHaveBeenCalledWith(
      expect.objectContaining({ dns_server: '2001:db8::53', password: '' }),
    ))
  })

  it('can clear an override to return to the web URL host', async () => {
    fetchPiholeSettings.mockResolvedValue({ ...saved, dns_server: '192.0.2.53' })
    render(<SettingsPihole />)
    const input = await screen.findByLabelText('DNS server for enrichment (optional)')
    expect(input).toHaveValue('192.0.2.53')
    fireEvent.change(input, { target: { value: '' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(updatePiholeSettings).toHaveBeenCalledWith(
      expect.objectContaining({ dns_server: '' }),
    ))
  })

  it('shows that None avoids DNS queries and retains the stored override', async () => {
    fetchPiholeSettings.mockResolvedValue({ ...saved, enrichment: 'none', dns_server: '192.0.2.53' })
    render(<SettingsPihole />)
    const input = await screen.findByLabelText('DNS server for enrichment (optional)')
    expect(input).toBeDisabled()
    expect(input).toHaveValue('192.0.2.53')
    expect(screen.getByText('Import queries without extra DNS lookups or GeoIP and threat enrichment.')).toBeInTheDocument()
  })
})
