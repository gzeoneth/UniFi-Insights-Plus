import { useEffect, useState } from 'react'
import { apiFetch } from '../api'
import FieldFilters from './FieldFilters'

const FILTER_KEYS = new Set([
  'time_range', 'time_from', 'time_to', 'rule_name', 'filter_rules', 'log_type',
  'src_ip', 'dst_ip', 'ip', 'direction', 'rule_action', 'country', 'threat_min',
  'search', 'service', 'interface', 'vpn_only', 'asn', 'dst_port', 'src_port', 'protocol',
])

export default function RuleUsage() {
  const [filters, setFilters] = useState({ time_range: '24h', rule_name: '', filter_rules: null })
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  const [refresh, setRefresh] = useState(0)
  useEffect(() => {
    const controller = new AbortController()
    let active = true
    const params = new URLSearchParams()
    for (const [key, value] of Object.entries(filters)) {
      if (value !== null && value !== undefined && value !== '' && FILTER_KEYS.has(key)) params.set(key, value)
    }
    setError(''); setData(null)
    apiFetch(`/api/rules/usage?${params}`, { signal: controller.signal })
      .then(value => { if (active) setData(value) })
      .catch(e => { if (active && e.name !== 'AbortError') setError(e.message) })
    return () => { active = false; controller.abort() }
  }, [filters, refresh])
  return <section className="space-y-3" aria-label="Firewall rule usage">
    <h2 className="font-semibold text-lg text-gray-100">Firewall rule usage</h2>
    <p className="text-sm text-gray-400">Observe the IPs, protocols and destination ports using a rule before narrowing it. Counts are logged events, not complete traffic or connection counts.</p>
    <div className="flex flex-wrap gap-2">
      <input className="bg-gray-900 border border-gray-700 rounded p-2 text-gray-100" aria-label="Rule name contains" placeholder="Rule name contains" value={filters.rule_name || ''} onChange={e => setFilters({ ...filters, rule_name: e.target.value })} />
      <select className="bg-gray-900 border border-gray-700 rounded p-2" aria-label="Rule observation period" value={filters.time_range} onChange={e => setFilters({ ...filters, time_range: e.target.value })}>
        {['1h', '6h', '24h', '7d', '30d', '90d'].map(range => <option key={range}>{range}</option>)}
      </select>
      <button className="border border-gray-700 rounded px-3" onClick={() => setRefresh(n => n + 1)}>Refresh</button>
    </div>
    <FieldFilters filters={filters} onChange={setFilters} />
    {error && <p role="alert" className="text-red-400">{error}</p>}
    {!error && !data && <p className="text-gray-400">Loading observations…</p>}
    {data && <>
      <p className="text-xs text-amber-300">{data.notice} {data.truncated && `Showing the busiest ${data.limit} groups; narrow the filters for more detail.`}</p>
      <div className="overflow-x-auto"><table className="w-full text-sm text-left">
        <thead><tr>{['Rule / action', 'Source', 'Destination', 'Protocol', 'Destination port', 'Log hits', 'First / last seen'].map(label => <th key={label} className="p-2 border-b border-gray-700">{label}</th>)}</tr></thead>
        <tbody>{data.data.map((row, i) => <tr key={i} className="border-b border-gray-800">
          <td className="p-2 max-w-64 break-words">{row.rule_desc || row.rule_name || 'Unknown'}<div className="text-gray-400">{row.rule_action || 'Unknown'}</div></td>
          <td className="p-2 font-mono">{row.src_ip || '—'}</td><td className="p-2 font-mono">{row.dst_ip || '—'}</td>
          <td className="p-2">{row.protocol || '—'}</td><td className="p-2">{row.dst_port ?? '—'}</td><td className="p-2">{row.log_hits}</td>
          <td className="p-2 text-xs whitespace-nowrap">{new Date(row.first_seen).toLocaleString()}<br />{new Date(row.last_seen).toLocaleString()}</td>
        </tr>)}</tbody>
      </table></div>
      {data.data.length === 0 && <p className="text-gray-400">No matching logged events in this period.</p>}
    </>}
  </section>
}
