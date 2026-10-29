export const FILTER_FIELDS = [
  ['ip', 'Either IP / subnet'], ['src_ip', 'Source IP / subnet'], ['dst_ip', 'Destination IP / subnet'],
  ['remote_ip', 'Remote IP / subnet'], ['port', 'Either port / range'], ['src_port', 'Source port / range'], ['dst_port', 'Destination port / range'],
  ['protocol', 'Protocol'], ['log_type', 'Log type'], ['direction', 'Direction'], ['rule_action', 'Action'],
  ['rule_name', 'Rule name'], ['device', 'Either recorded device name'], ['src_device', 'Recorded source device name'],
  ['dst_device', 'Recorded destination device name'], ['country', 'Country code'], ['asn', 'ASN name'],
  ['service', 'Service'], ['interface', 'Either interface'], ['interface_in', 'Inbound interface'], ['interface_out', 'Outbound interface'], ['hostname', 'Hostname'], ['search', 'Raw message'],
  ['event_source', 'Event source'], ['source', 'Collector source'], ['ips_signature', 'IPS signature'],
  ['security_event', 'Security classification'],
  ['ips_signature_id', 'IPS signature ID'], ['ips_risk', 'IPS risk'], ['ips_severity', 'IPS severity (0–10)'],
  ['threat_score', 'IP reputation (0–100)'],
]

const FILTER_FIELD_KEYS = new Set([
  ...FILTER_FIELDS.map(([field]) => field),
  'rule_name_exact', 'rule_desc_exact', 'hostname_exact',
])

export function isValidFilterRules(rules) {
  return Array.isArray(rules) && rules.length <= 24 && rules.every(rule => (
    rule && typeof rule === 'object' && !Array.isArray(rule)
    && Object.keys(rule).every(key => ['field', 'operator', 'value'].includes(key))
    && FILTER_FIELD_KEYS.has(rule.field)
    && ['include', 'exclude', 'present', 'missing'].includes(rule.operator)
    && (rule.value === undefined || (typeof rule.value === 'string' && rule.value.length <= 1024))
    && (['present', 'missing'].includes(rule.operator) || (typeof rule.value === 'string' && rule.value.trim().length > 0))
  )) && JSON.stringify(rules).length <= 16384
}

export function readFilterRules(value) {
  try {
    const rules = typeof value === 'string' ? JSON.parse(value) : value
    return isValidFilterRules(rules) ? rules : []
  } catch { return [] }
}

