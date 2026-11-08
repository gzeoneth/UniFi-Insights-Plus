import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import SettingsSecurity from '../components/SettingsSecurity'
import { fetchAuthStatus, fetchAuthMe, fetchProxyToken } from '../api'

vi.mock('../api', () => ({
  fetchAuthStatus: vi.fn(),
  fetchAuthMe: vi.fn(),
  fetchProxyToken: vi.fn(),
  authChangePassword: vi.fn(),
  authSetup: vi.fn(),
  updateSessionTtl: vi.fn(),
}))

beforeEach(() => {
  vi.clearAllMocks()
  fetchAuthMe.mockResolvedValue({ username: 'test-admin', role: 'admin' })
  fetchProxyToken.mockResolvedValue({ token: 'synthetic-proxy-token' })
})

describe('native HTTPS authentication settings', () => {
  it('allows first-user setup without a reverse proxy', async () => {
    fetchAuthStatus.mockResolvedValue({ is_https: true, proxy_trusted: false, has_admin: false, auth_enabled_effective: false })
    render(<SettingsSecurity />)
    expect(await screen.findByRole('button', { name: 'Enable Authentication' })).toBeInTheDocument()
    expect(screen.queryByText(/Enabling authentication requires HTTPS/)).not.toBeInTheDocument()
  })

  it('does not warn a direct HTTPS admin that proxy trust is required', async () => {
    fetchAuthStatus.mockResolvedValue({ is_https: true, proxy_trusted: false, has_admin: true, auth_enabled_effective: true })
    render(<SettingsSecurity />)
    expect(await screen.findByText(/Direct HTTPS connections do not need a proxy header/)).toBeInTheDocument()
    expect(screen.queryByText(/HTTPS is not verified/)).not.toBeInTheDocument()
  })

  it('keeps the warning when neither native nor trusted-proxy HTTPS is verified', async () => {
    fetchAuthStatus.mockResolvedValue({ is_https: false, proxy_trusted: false, has_admin: true, auth_enabled_effective: true })
    render(<SettingsSecurity />)
    expect(await screen.findByText(/HTTPS is not verified/)).toBeInTheDocument()
  })
})
