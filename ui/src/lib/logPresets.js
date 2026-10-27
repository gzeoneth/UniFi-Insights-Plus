// Built-ins are selectable query templates. They do not seed saved views or hide events at startup.
const PRIVATE_SUBNETS = '10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7'

export const LOG_PRESETS = [
  { id: 'all', name: 'All events', description: 'All recorded log types and actions. The exclusion profile is bypassed.', bypassProfile: true, filters: {} },
  { id: 'blocks', name: 'Firewall blocks', description: 'Firewall records with a recorded block action. This does not include traffic that was never logged.', filters: { log_type: 'firewall', rule_action: 'block' } },
  { id: 'ips', name: 'IPS detections', description: 'Records classified as IPS or carrying an IPS signature ID, across all log types. The exclusion profile is bypassed.', bypassProfile: true, filters: { filter_rules: [{ field: 'security_event', operator: 'include', value: 'ips' }] } },
  { id: 'unparsed-cef', name: 'Unparsed CEF candidates', description: 'Retained CEF threat candidates without parsed IPS attribution. These are candidates for inspection, not confirmed threat verdicts. The exclusion profile is bypassed.', bypassProfile: true, filters: { filter_rules: [{ field: 'security_event', operator: 'include', value: 'unparsed_cef' }] } },
  { id: 'inter-vlan', name: 'Inter-VLAN traffic', description: 'Firewall records classified as inter-VLAN traffic. Classification depends on the configured interface labels.', filters: { log_type: 'firewall', direction: 'inter_vlan' } },
  { id: 'blocked-inter-vlan', name: 'Blocked inter-VLAN', description: 'Blocked firewall records classified as inter-VLAN. Traffic addressed to the gateway itself uses the separate local direction and is not included.', filters: { log_type: 'firewall', direction: 'inter_vlan', rule_action: 'block' } },
  { id: 'blocked-private', name: 'Blocked private traffic', description: 'Blocked firewall records with both source and destination in RFC1918 IPv4 or IPv6 ULA ranges, in any direction, including private gateway and transit addresses. Public addresses and the IPv4 CGNAT range (100.64.0.0/10) are excluded. Private addressing does not establish device ownership or trust.', filters: { log_type: 'firewall', rule_action: 'block', filter_rules: [{ field: 'src_ip', operator: 'include', value: PRIVATE_SUBNETS }, { field: 'dst_ip', operator: 'include', value: PRIVATE_SUBNETS }] } },
  { id: 'dns', name: 'DNS', description: 'Parsed DNS records. Firewall traffic on port 53 is a separate log type.', filters: { log_type: 'dns' } },
  { id: 'missing-action', name: 'Firewall action missing', description: 'Firewall records with no recorded action. This is a parsing or visibility check; it does not imply that traffic was allowed or blocked.', filters: { log_type: 'firewall', filter_rules: [{ field: 'rule_action', operator: 'missing' }] } },
  { id: 'discovery', name: 'A/V discovery', description: 'Logged UDP firewall events with source or destination port 5353 (mDNS) or 1900 (SSDP), covering queries and responses. Ports suggest discovery but do not confirm the application. Same-subnet traffic may never reach the gateway.', filters: { log_type: 'firewall', protocol: 'udp', filter_rules: [{ field: 'port', operator: 'include', value: '5353,1900' }] } },
  { id: 'nat-mapping', name: 'NAT-PMP / PCP attempts', description: 'Logged UDP firewall events to destination port 5351, commonly used for NAT-PMP or PCP mapping requests. A matching port does not confirm the protocol or a successful mapping. This view does not cover all UPnP traffic.', filters: { log_type: 'firewall', protocol: 'udp', dst_port: '5351' } },
  { id: 'high-ports', name: 'High destination ports', description: 'Logged firewall events to destination ports 49152–65535, including return traffic. Observation alone does not establish that a broad allow rule is needed.', filters: { log_type: 'firewall', filter_rules: [{ field: 'dst_port', operator: 'include', value: '49152-65535' }] } },
]

export function buildLogPresetFilters(preset, current, defaults) {
  return {
    ...defaults,
    ...preset.filters,
    filter_rules: preset.filters.filter_rules ? JSON.stringify(preset.filters.filter_rules) : null,
    time_range: '24h', time_from: null, time_to: null, page: 1,
    per_page: current.per_page || defaults.per_page,
    sort: current.sort || defaults.sort,
    order: current.order || defaults.order,
  }
}

export function logFilterFingerprint(filters) {
  const snapshot = { ...filters }
  for (const key of ['page', 'per_page', 'sort', 'order']) delete snapshot[key]
  const rules = typeof snapshot.filter_rules === 'string' ? snapshot.filter_rules : JSON.stringify(snapshot.filter_rules || [])
  snapshot.filter_rules = rules === '[]' ? null : rules
  return JSON.stringify(Object.entries(snapshot).filter(([, value]) => value !== null && value !== undefined && value !== '').sort(([a], [b]) => a.localeCompare(b)))
}
