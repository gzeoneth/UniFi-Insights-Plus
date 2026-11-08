/**
 * Tests for VPN toast per-interface dismissal (set-difference logic).
 *
 * Verifies that vpn_toast_dismissed now stores a per-interface array
 * (was a global boolean), and that Dismiss posts the current unlabeled
 * interface names while X is session-only.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'

// ── Mock setup (before App import) ──────────────────────────────────────────

const baseConfig = {
  wan_interfaces: ['ppp0'],
  interface_labels: {},
  setup_complete: true,
  config_version: 2,
  unifi_enabled: false,
  vpn_networks: {},
  vpn_toast_dismissed: [],
  wan_ip_by_iface: {},
  upgrade_v2_dismissed: true,
  mcp_enabled: false,
}

const mockInterfaces = [
  { name: 'tun0', count: 50 },
  { name: 'tun1', count: 30 },
  { name: 'ppp0', count: 200 },
  { name: 'br0', count: 100 },
]

// Per-test config override — set in each test before render
let configOverride = {}

vi.mock('../api', () => ({
  fetchSavedViews: vi.fn(() => Promise.resolve({ views: [] })),
  fetchConfig: vi.fn(() => Promise.resolve({ ...baseConfig, ...configOverride })),
  fetchHealth: vi.fn(() => Promise.resolve({ status: 'ok', version: '3.3.0' })),
  fetchLatestRelease: vi.fn(() => Promise.resolve(null)),
  dismissUpgradeModal: vi.fn(() => Promise.resolve()),
  dismissVpnToast: vi.fn(() => Promise.resolve({ success: true })),
  fetchInterfaces: vi.fn(() => Promise.resolve({ interfaces: [...mockInterfaces] })),
  fetchUiSettings: vi.fn(() => Promise.resolve({})),
  updateUiSettings: vi.fn(() => Promise.resolve()),
  fetchUniFiSettings: vi.fn(() => Promise.resolve({})),
  fetchAuthStatus: vi.fn(() => Promise.resolve({ auth_enabled: false })),
  fetchAuthMe: vi.fn(() => Promise.resolve(null)),
  authLogout: vi.fn(() => Promise.resolve()),
  setAuthExpiredHandler: vi.fn(),
}))

vi.mock('../utils', async importOriginal => ({
  ...await importOriginal(),
  loadInterfaceLabels: vi.fn(() => ({})),
}))

vi.mock('../vpnUtils', () => ({
  isVpnInterface: vi.fn((name) => name.startsWith('tun') || name.startsWith('wg')),
}))

// Mock heavy child components to keep tests fast
vi.mock('../components/LogStream', () => ({ default: () => <div data-testid="logstream" /> }))
vi.mock('../components/SetupWizard', () => ({ default: () => <div /> }))
vi.mock('../components/SettingsOverlay', () => ({ default: () => <div /> }))
vi.mock('../components/Dashboard', () => ({
  default: () => <div />,
  DashboardSkeleton: () => <div />,
}))
vi.mock('../components/ThreatMap', () => ({
  default: () => <div />,
  ThreatMapSkeleton: () => <div />,
}))
vi.mock('../components/FlowView', () => ({ default: () => <div /> }))
vi.mock('../components/FlowViewSkeleton', () => ({ default: () => <div /> }))
vi.mock('../components/Login', () => ({ default: () => <div /> }))

// Import after mocks are declared
import App from '../App'
import { dismissVpnToast, fetchAuthMe, fetchAuthStatus, fetchConfig, fetchHealth, fetchInterfaces } from '../api'

beforeEach(() => {
  vi.clearAllMocks()
  localStorage.clear(); sessionStorage.clear()
  window.history.replaceState(null, '', '/')
  configOverride = {}
  fetchAuthStatus.mockResolvedValue({ auth_enabled: false })
  fetchAuthMe.mockResolvedValue(null)
  fetchHealth.mockResolvedValue({ status: 'ok', version: '3.3.0' })
})

describe('remembered navigation', () => {
  it('restores the last tab and allows an explicit URL to override it', async () => {
    localStorage.setItem('unifi-log-insight:active-tab', JSON.stringify('dashboard'))
    const first = render(<App />)
    await screen.findByRole('button', { name: 'System status' })
    expect(screen.queryByTestId('logstream')).toBeNull()
    first.unmount()
    window.history.replaceState(null, '', '/#logs')
    render(<App />)
    await screen.findByTestId('logstream')
    expect(JSON.parse(localStorage.getItem('unifi-log-insight:active-tab'))).toBe('logs')
  })
})

describe('collection status indicator', () => {
  it('keeps normal pending processing neutral despite incomplete metadata', async () => {
    fetchHealth.mockResolvedValue({ status: 'ok', version: '3.3.0', ingestion: {
      status: 'fresh', state: 'pending', stats: { dropped: 0 }, batch: { pending: 12, inflight: 3 },
      collection: { incomplete: true, reasons: ['processing'], attention_required: false, attention_reasons: [], state: 'processing' },
    } })
    render(<App />)
    await screen.findByRole('button', { name: 'Processing recent events' })
    expect(screen.queryByRole('button', { name: 'Collection needs attention' })).toBeNull()
    expect(screen.queryByText('Collection incomplete')).toBeNull()
    expect(screen.getByRole('button', { name: 'System status' }).querySelector('span')).toHaveClass('bg-emerald-400')
  })

  it.each(['backlog_lag', 'queue_pressure', 'worker_stalled', 'delivery_retry', 'stale_snapshot', 'unavailable_snapshot'])(
    'shows an attention indicator for %s', async reason => {
      fetchHealth.mockResolvedValue({ status: 'ok', version: '3.3.0', ingestion: {
        stats: { dropped: 0 }, collection: { incomplete: true, attention_required: true, attention_reasons: [reason], state: 'delayed' },
      } })
      render(<App />)
      await screen.findByRole('button', { name: 'Collection needs attention' })
      expect(screen.queryByRole('button', { name: 'Processing recent events' })).toBeNull()
      expect(screen.getByRole('button', { name: 'System status' }).querySelector('span')).toHaveClass('bg-amber-400')
    })

  it('shows an amber loss indicator even when the API and database are reachable', async () => {
    fetchHealth.mockResolvedValue({ status: 'ok', version: '3.3.0', ingestion: { stats: { dropped: 4 } } })
    render(<App />)
    await screen.findByRole('button', { name: 'Collection loss: 4' })
    const status = screen.getByRole('button', { name: 'System status' })
    expect(status).toHaveAttribute('title', expect.stringContaining('does not establish a current outage'))
    expect(status.querySelector('span')).toHaveClass('bg-amber-400')
  })

  it('does not turn enrichment-only skips into a collection-loss warning', async () => {
    fetchHealth.mockResolvedValue({ status: 'ok', version: '3.3.0', ingestion: { stats: { dropped: 0 }, enrichment: { dropped: 4 } } })
    render(<App />)
    await screen.findByRole('button', { name: 'System status' })
    expect(screen.queryByRole('button', { name: /Collection loss:/ })).toBeNull()
    expect(screen.getByRole('button', { name: 'System status' })).toHaveAttribute('title', expect.stringContaining('does not confirm complete log collection'))
  })
})

describe('HTTPS connection warning', () => {
  it.each([
    { is_https: true, proxy_trusted: false },
    { is_https: true, proxy_trusted: true },
  ])('does not require a proxy header once HTTPS is verified: %o', async (connection) => {
    fetchAuthStatus.mockResolvedValue({ ...connection, setup_complete: true, auth_enabled_effective: true })
    fetchAuthMe.mockResolvedValue({ authenticated: true })
    render(<App />)
    await screen.findByTestId('logstream')
    expect(screen.queryByText(/Reverse proxy trust is not configured/)).not.toBeInTheDocument()
  })

  it('warns when authenticated access has no verified HTTPS or proxy', async () => {
    fetchAuthStatus.mockResolvedValue({ is_https: false, proxy_trusted: false, setup_complete: true, auth_enabled_effective: true })
    fetchAuthMe.mockResolvedValue({ authenticated: true })
    render(<App />)
    expect(await screen.findByText(/Reverse proxy trust is not configured/)).toBeInTheDocument()
  })
})


describe('VPN toast per-interface dismissal', () => {
  it('shows toast when new interface is not dismissed', async () => {
    configOverride = { vpn_toast_dismissed: ['tun0'] }

    render(<App />)

    await waitFor(() => {
      expect(screen.getByText(/Unlabeled VPN networks found/)).toBeInTheDocument()
    })
  })

  it('hides toast when all unlabeled are dismissed', async () => {
    configOverride = { vpn_toast_dismissed: ['tun0', 'tun1'] }

    render(<App />)

    // Wait for the interfaces fetch to complete
    await waitFor(() => {
      expect(fetchInterfaces).toHaveBeenCalled()
    })

    // Allow effects to settle
    await new Promise(r => setTimeout(r, 100))
    expect(screen.queryByText(/Unlabeled VPN networks found/)).not.toBeInTheDocument()
  })

  it('Dismiss posts current unlabeled interface names', async () => {
    configOverride = { vpn_toast_dismissed: [] }

    render(<App />)

    await waitFor(() => {
      expect(screen.getByText(/Unlabeled VPN networks found/)).toBeInTheDocument()
    })

    fireEvent.click(screen.getByText('Dismiss'))

    await waitFor(() => {
      expect(dismissVpnToast).toHaveBeenCalledTimes(1)
    })
    const args = dismissVpnToast.mock.calls[0][0]
    expect(args).toEqual(expect.arrayContaining(['tun0', 'tun1']))
    expect(args).toHaveLength(2)
  })

  it('Dismiss reloads config so toast stays hidden on next poll', async () => {
    configOverride = { vpn_toast_dismissed: [] }

    render(<App />)

    await waitFor(() => {
      expect(screen.getByText(/Unlabeled VPN networks found/)).toBeInTheDocument()
    })

    // After dismiss, the backend accepts ['tun0', 'tun1'] — simulate config
    // reload returning the updated dismissed list so the next poll sees it.
    const initialCallCount = fetchConfig.mock.calls.length
    dismissVpnToast.mockImplementationOnce(() => {
      // On next fetchConfig call (reloadConfig), return dismissed interfaces
      configOverride = { vpn_toast_dismissed: ['tun0', 'tun1'] }
      return Promise.resolve({ success: true })
    })

    fireEvent.click(screen.getByText('Dismiss'))

    // Verify reloadConfig was triggered (fetchConfig called again)
    await waitFor(() => {
      expect(fetchConfig.mock.calls.length).toBeGreaterThan(initialCallCount)
    })

    // Allow effects to settle after config reload
    await new Promise(r => setTimeout(r, 100))
    expect(screen.queryByText(/Unlabeled VPN networks found/)).not.toBeInTheDocument()
  })

  it('X button is session-only and does not call dismiss API', async () => {
    configOverride = { vpn_toast_dismissed: [] }

    render(<App />)

    await waitFor(() => {
      expect(screen.getByText(/Unlabeled VPN networks found/)).toBeInTheDocument()
    })

    fireEvent.click(screen.getByTestId('vpn-toast-close'))

    await waitFor(() => {
      expect(screen.queryByText(/Unlabeled VPN networks found/)).not.toBeInTheDocument()
    })

    expect(dismissVpnToast).not.toHaveBeenCalled()
  })
})
