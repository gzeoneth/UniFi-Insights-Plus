/**
 * Id-less firewall policies (#112, option A): they stay listed, a single
 * warning notice links to the docs, and their row toggle is disabled with an
 * explanatory tooltip.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor, cleanup, fireEvent } from '@testing-library/react'

const mockFetch = vi.fn()

vi.mock('../api', () => ({
  fetchFirewallPolicies: (...args) => mockFetch(...args),
  patchFirewallPolicy: vi.fn(() => Promise.resolve({})),
  bulkUpdateFirewallLoggingStream: vi.fn(() => Promise.resolve({})),
}))

vi.mock('../components/SyslogToggle', () => ({
  default: ({ disabled, title }) => (
    <button data-testid="toggle" disabled={disabled} title={title} />
  ),
}))

import FirewallRules from '../components/FirewallRules'
import { patchFirewallPolicy, bulkUpdateFirewallLoggingStream } from '../api'

const ZONES = [
  { id: 'z-int', name: 'Internal', networkIds: [], metadata: { origin: 'SYSTEM_DEFINED' } },
  { id: 'z-ext', name: 'External', networkIds: [], metadata: { origin: 'SYSTEM_DEFINED' } },
]

function policy(overrides) {
  return {
    name: 'Rule',
    enabled: true,
    loggingEnabled: false,
    index: 100,
    action: { type: 'ALLOW' },
    source: { zoneId: 'z-int' },
    destination: { zoneId: 'z-ext' },
    metadata: { origin: 'USER_DEFINED' },
    ...overrides,
  }
}

function payload(policies) {
  return { policies, zones: ZONES, totalCount: policies.length }
}

const DOCS = 'https://insightsplus.dev/docs/troubleshooting#firewall-policies-without-an-id'

const IDLESS_TITLE = /^Logging cannot be toggled here: the UniFi controller returned this policy without an id/

describe('FirewallRules id-less policies', () => {
  let consoleError
  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear(); sessionStorage.clear()
    mockFetch.mockReset()
    consoleError = vi.spyOn(console, 'error')
  })
  afterEach(() => {
    // Id-less rows must get stable keys: no React "unique key" warning.
    // Unmount and restore first so a failure here cannot leak into the next test.
    cleanup()
    const keyWarnings = consoleError.mock.calls.filter(args => String(args[0]).includes('unique "key"'))
    consoleError.mockRestore()
    expect(keyWarnings).toEqual([])
  })

  it('shows one singular notice with the docs link and disables only the id-less toggle', async () => {
    mockFetch.mockResolvedValue(payload([
      policy({ id: '11111111-2222-4333-8444-555555555555', name: 'Has id' }),
      policy({ name: 'Legacy rule', index: 200 }),
    ]))
    render(<FirewallRules />)

    const notice = await screen.findByText(/1 firewall policy was returned by the UniFi controller without an id/)
    expect(notice.textContent).toContain('It still counts toward the zone matrix.')
    const link = screen.getByRole('link', { name: /Learn why and how to fix it/ })
    expect(link.getAttribute('href')).toBe(DOCS)
    expect(link.getAttribute('target')).toBe('_blank')
    expect(link.getAttribute('rel')).toBe('noopener noreferrer')

    const toggles = screen.getAllByTestId('toggle')
    const disabled = toggles.filter(t => t.disabled)
    expect(disabled).toHaveLength(1)
    expect(disabled[0].getAttribute('title')).toMatch(IDLESS_TITLE)
  })

  it('explains a disabled group toggle when every rule in the group is id-less', async () => {
    mockFetch.mockResolvedValue(payload([
      policy({ name: 'Legacy pair' }),
      policy({ name: 'Legacy pair', index: 200 }),
      policy({ id: '11111111-2222-4333-8444-555555555555', name: 'Has id', index: 300 }),
    ]))
    render(<FirewallRules />)

    await screen.findByText(/2 firewall policies were returned/)
    const groupToggle = screen.getAllByTestId('toggle').find(t => t.disabled)
    expect(groupToggle.getAttribute('title')).toMatch(IDLESS_TITLE)
  })

  it('pluralises the notice', async () => {
    mockFetch.mockResolvedValue(payload([
      policy({ name: 'Legacy A' }),
      policy({ name: 'Legacy B', index: 200 }),
    ]))
    render(<FirewallRules />)

    expect(await screen.findByText(/2 firewall policies were returned by the UniFi controller without an id/)).toBeTruthy()
    expect(screen.getAllByText(/They still count toward the zone matrix\./)).toHaveLength(1)
  })

  it('shows no notice when every policy has an id', async () => {
    mockFetch.mockResolvedValue(payload([
      policy({ id: '11111111-2222-4333-8444-555555555555' }),
    ]))
    render(<FirewallRules />)

    await waitFor(() => expect(screen.getAllByTestId('toggle').length).toBeGreaterThan(0))
    expect(screen.queryByText(/without an id/)).toBeNull()
  })
  it('restores zone and visibility filters without replaying any firewall operation', async () => {
    mockFetch.mockResolvedValue(payload([
      policy({ id: 'example-id', name: 'Example rule' }),
      policy({ id: 'builtin-id', name: 'Example built-in', metadata: { origin: 'SYSTEM_DEFINED' } }),
    ]))
    const first = render(<FirewallRules />)
    await screen.findByText('Example rule')
    fireEvent.click(screen.getByRole('button', { name: 'Allow All(2)' }))
    fireEvent.click(screen.getByRole('checkbox', { name: 'Built-In' }))
    expect(screen.queryByText('Example built-in')).toBeNull()
    first.unmount(); sessionStorage.clear()
    render(<FirewallRules />)
    await screen.findByText('Example rule')
    expect(screen.getByRole('checkbox', { name: 'Built-In' })).not.toBeChecked()
    expect(screen.queryByText('Example built-in')).toBeNull()
    expect(screen.getByText('Internal → External')).toBeInTheDocument()
    expect(localStorage.getItem('unifi-log-insight:firewall-zone-pair')).toBe(JSON.stringify({ srcZoneId: 'z-int', dstZoneId: 'z-ext' }))
    expect(patchFirewallPolicy).not.toHaveBeenCalled()
    expect(bulkUpdateFirewallLoggingStream).not.toHaveBeenCalled()
  })

  it('clears a saved zone pair when the zones no longer exist', async () => {
    localStorage.setItem('unifi-log-insight:firewall-zone-pair', JSON.stringify({ srcZoneId: 'removed', dstZoneId: 'z-ext' }))
    localStorage.setItem('unifi-log-insight:firewall-filters', JSON.stringify({ ipv4: 'false' }))
    mockFetch.mockResolvedValue(payload([policy({ id: 'example-id', name: 'Example rule' })]))
    render(<FirewallRules />)
    await screen.findByText('Example rule')
    expect(screen.getByRole('checkbox', { name: 'IPv4' })).toBeChecked()
    await waitFor(() => expect(localStorage.getItem('unifi-log-insight:firewall-zone-pair')).toBe('null'))
  })

})
