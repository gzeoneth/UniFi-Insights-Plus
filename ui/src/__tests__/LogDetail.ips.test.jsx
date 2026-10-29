import { describe, it, expect, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import LogDetail from '../components/LogDetail'
import { matchFirewallPolicyForLog } from '../api'

vi.mock('../api', () => ({
  fetchAbuseIPDBStatus: vi.fn(), enrichIP: vi.fn(),
  matchFirewallPolicyForLog: vi.fn(), patchFirewallPolicy: vi.fn(),
}))

const log = {
  id: 1, log_type: 'firewall', event_source: 'unifi_ips', event_id: '201',
  event_name: 'Threat Detected and Blocked', ips_signature: 'Synthetic IPS detection',
  ips_signature_id: '123', ips_severity: 7, ips_risk: 'medium', rule_action: 'block',
  rule_name: 'LAN_WAN-D-2147483647', threat_score: 91, raw_log: 'Synthetic raw event',
}

describe('LogDetail IPS fields', () => {
  it('shows gateway risk and severity independently from AbuseIPDB percentage', () => {
    render(<LogDetail log={log} />)
    const ips = screen.getByRole('region', { name: 'UniFi IPS detection' })
    expect(within(ips).getByText('Synthetic IPS detection')).toBeTruthy()
    expect(within(ips).getByText('123')).toBeTruthy()
    expect(within(ips).getByText('7/10')).toBeTruthy()
    expect(within(ips).getByText('medium')).toBeTruthy()
    expect(within(ips).getByText('Blocked')).toBeTruthy()
    expect(screen.getByText('AbuseIPDB Score')).toBeTruthy()
    expect(screen.getByText(/91%/)).toBeTruthy()
    expect(matchFirewallPolicyForLog).not.toHaveBeenCalled()
    expect(screen.queryByText('Rule Details')).toBeNull()
  })

  it('still shows IPS information when reputation columns are hidden', () => {
    render(<LogDetail log={{ ...log, ips_severity: 0, rule_action: null }} hiddenColumns={new Set(['threat', 'categories'])} />)
    expect(screen.getByText('0/10')).toBeTruthy()
    expect(screen.getByText('IPS action').nextSibling.textContent).toBe('Unknown')
    expect(screen.queryByText('AbuseIPDB Score')).toBeNull()
  })

  it('keeps reported aliases separate when the gateway omitted IPs', () => {
    render(<LogDetail log={{ ...log, src_reported_name: 'Player', dst_reported_name: 'Player', reported_application: 'Media' }} />)
    const ips = screen.getByRole('region', { name: 'UniFi IPS detection' })
    expect(within(ips).getAllByText('Player')).toHaveLength(2)
    expect(within(ips).getAllByText('IP not supplied by gateway')).toHaveLength(2)
    expect(within(ips).getByText('Reported application')).toBeTruthy()
    expect(screen.queryByText('Source IP')).toBeNull()
    expect(screen.queryByText('Destination IP')).toBeNull()
  })

  it('labels the port registration separately from a reported application', () => {
    render(<LogDetail log={{ ...log, service_name: 'example-service', dst_port: 9999, reported_application: 'Media' }} />)
    expect(screen.getByText('Registered port service')).toBeTruthy()
    expect(screen.getByText(/IANA registration for this port and protocol/)).toBeTruthy()
    expect(screen.getByText('Media')).toBeTruthy()
  })
})
