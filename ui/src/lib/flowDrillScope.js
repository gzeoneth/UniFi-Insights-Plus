// Preserve the aggregate scope when opening its underlying firewall records.
// Directional interfaces use advanced conditions because Log Stream's legacy
// interface parameter matches either side.
export function flowDrillScope(drill) {
  let filterRules = drill.filter_rules || null
  try {
    const rules = typeof filterRules === 'string' ? JSON.parse(filterRules) : filterRules || []
    if (Array.isArray(rules)) {
      const combined = [...rules]
      for (const field of ['interface_in', 'interface_out']) {
        if (drill[field] === undefined || drill[field] === null) continue
        const value = String(drill[field])
        if (!combined.some(rule => rule.field === field && rule.operator === 'include' && rule.value === value)) {
          combined.push({ field, operator: 'include', value })
        }
      }
      // Never truncate a scope to fit the server's limit. A validation error is
      // safer than silently returning records outside the selected flow.
      filterRules = combined.length ? JSON.stringify(combined) : null
    }
  } catch { /* Preserve malformed input for server validation. */ }
  return {
    filter_rules: filterRules,
    src_ip: drill.src_ip || null,
    dst_ip: drill.dst_ip || null,
    dst_port: drill.dst_port?.toString() || null,
    service: drill.service || null,
    protocol: drill.protocol || null,
    rule_action: drill.rule_action || null,
    direction: drill.direction || null,
    log_type: 'firewall',
  }
}
