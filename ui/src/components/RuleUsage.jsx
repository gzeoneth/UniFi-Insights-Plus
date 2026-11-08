import { useExclusionProfile, ExclusionCounts, ruleExclusionGroup } from './ExclusionProfiles'
import { useState } from 'react'
import usePreference from '../hooks/usePreference'
import { readTimeRange, writeTimeRange, TIME_RANGES } from '../lib/preferences'
import { isRecord, isShortText, isOptionalDate } from '../lib/viewPreferences'
import useSerializedPoll from '../hooks/useSerializedPoll'
import { apiFetch } from '../api'
import FieldFilters, { readFilterRules, isValidFilterRules } from './FieldFilters'

const FILTER_KEYS = new Set([
  'time_range', 'time_from', 'time_to', 'rule_name', 'filter_rules', 'log_type',
  'src_ip', 'dst_ip', 'ip', 'direction', 'rule_action', 'country', 'threat_min',
  'search', 'service', 'interface', 'vpn_only', 'asn', 'dst_port', 'src_port', 'protocol',
])

function validFilters(value) {
  if (!isRecord(value) || !Object.keys(value).every(key => FILTER_KEYS.has(key))) return false
  for (const [key, item] of Object.entries(value)) {
    if (item == null) continue
    if (key === 'filter_rules') {
      if (typeof item !== 'string' || item.length > 16384) return false
      let rules
      try { rules = JSON.parse(item) } catch { return false }
      if (!isValidFilterRules(rules)) return false
    } else if (key === 'time_range') {
      if (!TIME_RANGES.includes(item)) return false
    } else if (key === 'time_from' || key === 'time_to') {
      if (!isOptionalDate(item)) return false
    } else if (key === 'vpn_only') {
      if (typeof item !== 'boolean') return false
    } else if (key === 'threat_min') {
      if (!Number.isFinite(Number(item)) || Number(item) < 0 || Number(item) > 100) return false
    } else if (!isShortText(item)) return false
  }
  return (TIME_RANGES.includes(value.time_range) || Boolean(value.time_from)) &&
    (!value.time_from || !value.time_to || Date.parse(value.time_from) <= Date.parse(value.time_to))
}

function filterPreferences(filters) {
  const next = Object.fromEntries(Object.entries(filters).filter(([key]) => FILTER_KEYS.has(key)))
  if (next.time_from) next.time_range = null
  else if (!TIME_RANGES.includes(next.time_range)) next.time_range = readTimeRange()
  return next
}

const fetchUsage = (params, options) => apiFetch(`/api/rules/usage?${new URLSearchParams(params)}`, options)

export default function RuleUsage() {
  const { excludeGroups, openDraft } = useExclusionProfile()
  const [filters, setFilters] = usePreference('unifi-log-insight:rule-usage-filters',
    { time_range: readTimeRange(), rule_name: '', filter_rules: null }, validFilters)
  const [groupBy, setGroupBy] = usePreference('unifi-log-insight:rule-usage-grouping', 'rule', value => ['rule', 'endpoint'].includes(value))
  const [ruleDraft, setRuleDraft] = useState(() => filters.rule_name || '')
  const previewRule = row => {
    const scope = { ...filters, log_type: 'firewall' }
    if (filters.log_type && !filters.log_type.split(',').map(v => v.trim()).includes('firewall')) {
      scope.log_type = filters.log_type
      scope.filter_rules = JSON.stringify([...readFilterRules(filters.filter_rules), { field: 'log_type', operator: 'include', value: 'firewall' }])
    }
    openDraft(row, scope)
  }
  const params = { group_by: groupBy, count_mode: 'none' }
  for (const [key, value] of Object.entries(filters)) {
    if (value !== null && value !== undefined && value !== '' && FILTER_KEYS.has(key)) params[key] = value
  }
  if (excludeGroups) params.exclude_groups = excludeGroups
  const { data, error, refresh, loading } = useSerializedPoll({ params, fetcher: fetchUsage, enabled: false })
  const customPeriod = Boolean(filters.time_from || filters.time_to)
  const changeFilters = next => {
    const normalized = filterPreferences(next)
    setFilters(normalized)
    setRuleDraft(normalized.rule_name || '')
    if (!normalized.time_from && !normalized.time_to) writeTimeRange(normalized.time_range)
  }
  const changePeriod = range => {
    if (!TIME_RANGES.includes(range)) return
    writeTimeRange(range)
    setFilters(current => ({ ...current, time_range: range, time_from: null, time_to: null }))
  }
  return <section className="space-y-3" aria-label="Firewall rule usage">
    <h2 className="font-semibold text-lg text-gray-100">Firewall rule usage</h2>
    <p className="text-sm text-gray-400">Observe the IPs, protocols and destination ports using a rule before narrowing it. Counts are logged events, not complete traffic or connection counts.</p>
    <p className="text-xs text-gray-500">Start with rule totals to find noisy logging, then inspect endpoint details. Hiding a view keeps the stored logs; disabling firewall logging stops collection. Neither requires allowing blocked traffic.</p>
    <form className="flex flex-wrap gap-2" onSubmit={e => { e.preventDefault(); setFilters({ ...filters, rule_name: ruleDraft }) }}>
      <input className="bg-gray-900 border border-gray-700 rounded p-2 text-gray-100" aria-label="Rule name contains" placeholder="Rule name contains" value={ruleDraft} onChange={e => setRuleDraft(e.target.value)} />
      <button type="submit" className="border border-gray-700 rounded px-3">Apply rule filter</button>
      <select className="bg-gray-900 border border-gray-700 rounded p-2" aria-label="Rule observation period" value={customPeriod ? 'custom' : filters.time_range} onChange={e => changePeriod(e.target.value)}>
        {customPeriod && <option value="custom" disabled>Custom date range</option>}
        {TIME_RANGES.map(range => <option key={range}>{range}</option>)}
      </select>
      <select className="bg-gray-900 border border-gray-700 rounded p-2" aria-label="Group observations by" value={groupBy} onChange={e => setGroupBy(e.target.value)}>
        <option value="rule">Rule totals</option><option value="endpoint">Endpoint details</option>
      </select>
      <button type="button" className="border border-gray-700 rounded px-3" onClick={() => refresh()}>Refresh</button>
    </form>
    <FieldFilters filters={filters} onChange={changeFilters} selectionStorageKey="unifi-log-insight:rule-usage-view-selection" />
    {error && <p role="alert" className="text-red-400">{error.message}</p>}
    {!error && (loading || !data) && <p className="text-gray-400">Loading observations…</p>}
    {data && !loading && <>
      <div className="flex gap-3 items-center">
        <ExclusionCounts counts={data.view_counts} unknown={Boolean(excludeGroups)} />
        <button type="button" className="text-xs text-blue-300 underline" onClick={() => refresh({ count_mode: 'exact' })}>Count matching events</button>
        {data.view_counts && <span className="text-xs text-gray-400">{data.view_counts.visible.toLocaleString()} visible events</span>}
        {data.timings?.query_ms != null && <span className="text-xs text-gray-500">Query {Math.round(data.timings.query_ms)} ms</span>}
      </div>
      <p className="text-xs text-amber-300">{data.notice} {data.truncated && `Showing the busiest ${data.limit} groups; narrow the filters for more detail.`}</p>
      <div className="overflow-x-auto"><table className="w-full text-sm text-left">
        <thead><tr>{['Rule / action', ...(groupBy === 'endpoint' ? ['Source', 'Destination', 'Protocol', 'Destination port'] : []), 'Log hits', 'First / last seen'].map(label => <th key={label} className="p-2 border-b border-gray-700">{label}</th>)}</tr></thead>
        <tbody>{data.data.map((row, i) => <tr key={i} className="border-b border-gray-800">
          <td className="p-2 max-w-64 break-words">{row.rule_desc || row.rule_name || 'Unknown'}<div className="text-gray-400">{row.rule_action || 'Unknown'} · {row.hostname || 'Unknown gateway'}</div>{ruleExclusionGroup(row) && <button className="text-xs text-blue-300" onClick={() => previewRule(row)}>Hide matching allow events</button>}</td>
          {groupBy === 'endpoint' && <><td className="p-2 font-mono">{row.src_ip || '—'}</td><td className="p-2 font-mono">{row.dst_ip || '—'}</td>
          <td className="p-2">{row.protocol || '—'}</td><td className="p-2">{row.dst_port ?? '—'}</td></>}<td className="p-2">{row.log_hits}</td>
          <td className="p-2 text-xs whitespace-nowrap">{new Date(row.first_seen).toLocaleString()}<br />{new Date(row.last_seen).toLocaleString()}</td>
        </tr>)}</tbody>
      </table></div>
      {data.data.length === 0 && <p className="text-gray-400">No matching logged events in this period.</p>}
    </>}
  </section>
}
