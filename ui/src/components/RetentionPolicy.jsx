import { useEffect, useState } from 'react'
import { apiFetch } from '../api'

const inputStyle = 'bg-gray-900 border border-gray-700 rounded p-2 text-gray-100 w-full'
const types = ['dns', 'firewall', 'dhcp', 'wifi', 'system', 'unknown']

export default function RetentionPolicy() {
  const [policy, setPolicy] = useState(null)
  const [inherited, setInherited] = useState({})
  const [summaries, setSummaries] = useState(null)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [busy, setBusy] = useState(false)
  const [range, setRange] = useState({ start: '', end: '' })
  useEffect(() => {
    let alive = true
    apiFetch('/api/config/retention/policy').then(data => { if (alive) { setPolicy(data.policy); setInherited(data) } }).catch(e => { if (alive) setError(e.message) })
    return () => { alive = false }
  }, [])
  const edit = patch => { setPolicy(current => ({ ...current, ...patch })); setNotice('') }
  const number = (key, title, { optional = false, min = 1, max = 3650 } = {}) => <label className="text-sm text-gray-300" key={key}>{title}
    <input className={inputStyle} aria-label={title} type="number" min={min} max={max} value={policy[key] ?? ''} placeholder={optional ? 'Inherit default' : ''} onChange={e => edit({ [key]: e.target.value === '' ? (optional ? null : '') : Number(e.target.value) })} />
  </label>
  const loadSummaries = async () => {
    setError(''); setBusy(true)
    try { const params = new URLSearchParams(Object.entries(range).filter(([, v]) => v)); setSummaries(await apiFetch(`/api/retention/summaries?${params}`)) }
    catch (e) { setError(e.message) } finally { setBusy(false) }
  }
  return <section className="space-y-4" aria-label="Retention and archives">
    <h2 className="font-semibold text-lg text-gray-100">Retention and archives</h2>
    <p className="text-sm text-gray-400">Overrides take effect at scheduled cleanup. Empty periods inherit the existing defaults. Archives and summaries are optional; enabling this does not immediately delete data.</p>
    {error && <p role="alert" className="text-red-400">{error}</p>}
    {notice && <p role="status" className="text-green-400">{notice}</p>}
    {!policy && !error && <p>Loading policy…</p>}
    {policy && <>
      <p className="text-xs text-gray-400">Existing defaults: general {inherited.inherited_general_days} days; DNS {inherited.inherited_dns_days} days.</p>
      <label className="flex gap-2"><input type="checkbox" checked={policy.enabled} onChange={e => edit({ enabled: e.target.checked })} />Enable retention overrides</label>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        {number('security_days', 'Security events: days', { optional: true })}
        {number('firewall_allow_days', 'Allowed firewall events: days', { optional: true })}
        {types.map(type => <label key={type} className="text-sm text-gray-300">{type}: days
          <input className={inputStyle} aria-label={`${type} retention days`} type="number" min="1" max="3650" placeholder="Inherit default" value={policy.type_days[type] ?? ''} onChange={e => {
            const typeDays = { ...policy.type_days }; if (e.target.value === '') delete typeDays[type]; else typeDays[type] = Number(e.target.value); edit({ type_days: typeDays })
          }} />
        </label>)}
      </div>
      <p className="text-xs text-gray-400">IPS events use the security period, even when their action is allow. Their period must exceed any explicitly shortened allowed-firewall period.</p>
      <div className="flex flex-wrap gap-5">
        <label className="flex gap-2"><input type="checkbox" checked={policy.summaries_enabled} onChange={e => edit({ summaries_enabled: e.target.checked })} />Keep daily summaries</label>
        <label className="flex gap-2"><input type="checkbox" checked={policy.summary_group_by_rule} onChange={e => edit({ summary_group_by_rule: e.target.checked })} />Group summaries by rule</label>
        <label className="flex gap-2"><input type="checkbox" checked={policy.archives_enabled} onChange={e => edit({ archives_enabled: e.target.checked })} />Archive expired records before deletion</label>
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        {number('summary_retention_days', 'Summary retention: days')}
        <label className="text-sm text-gray-300">Archive directory<input className={inputStyle} aria-label="Archive directory" value={policy.archive_directory} onChange={e => edit({ archive_directory: e.target.value })} /></label>
        <label className="text-sm text-gray-300">Archive budget: GiB<input className={inputStyle} aria-label="Archive budget GiB" type="number" min="1" step="1" value={policy.archive_max_bytes / 1024 ** 3} onChange={e => edit({ archive_max_bytes: Math.round(Number(e.target.value) * 1024 ** 3) })} /></label>
      </div>
      <p className="text-xs text-amber-300">The archive directory must be a persistent private mount. If archiving fails or reaches its budget, affected cleanup stops; archive files are never automatically removed.</p>
      <button className="rounded bg-blue-600 text-white px-4 py-2 disabled:opacity-50" disabled={busy} onClick={async () => {
        setBusy(true); setError(''); setNotice('')
        try { const data = await apiFetch('/api/config/retention/policy', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(policy) }); setPolicy(data.policy); setNotice('Policy saved. It will be used by scheduled cleanup.') }
        catch (e) { setError(e.message) } finally { setBusy(false) }
      }}>Save policy</button>
    </>}
    <div className="border-t border-gray-800 pt-4 space-y-3">
      <p className="text-sm text-gray-400">Daily summaries cover expired events removed by cleanup, using UTC days. They do not include current raw records.</p>
      <div className="flex flex-wrap gap-2">
        <input className={inputStyle + ' max-w-48'} type="date" aria-label="Summary start date" value={range.start} onChange={e => setRange({ ...range, start: e.target.value })} />
        <input className={inputStyle + ' max-w-48'} type="date" aria-label="Summary end date" value={range.end} onChange={e => setRange({ ...range, end: e.target.value })} />
        <button className="border border-gray-700 rounded px-3" disabled={busy} onClick={loadSummaries}>Load summaries</button>
      </div>
      {summaries && <div className="overflow-x-auto"><table className="text-sm w-full text-left">
        <thead><tr>{['UTC day', 'Type', 'Action', 'Source', 'Rule', 'Events'].map(label => <th className="p-2 border-b border-gray-700" key={label}>{label}</th>)}</tr></thead>
        <tbody>{summaries.summaries.map((row, i) => <tr key={i} className="border-b border-gray-800">
          <td className="p-2">{row.day}</td><td className="p-2">{row.event_source || row.log_type}</td><td className="p-2">{row.rule_action || 'Unknown'}</td><td className="p-2">{row.source}</td><td className="p-2">{row.grouped_by_rule ? row.rule_name || 'Unknown' : 'All rules'}</td><td className="p-2">{row.event_count}</td>
        </tr>)}</tbody>
      </table>{summaries.summaries.length === 0 && <p className="text-gray-400">No archived-event summaries in this period.</p>}{summaries.truncated && <p>Results truncated; choose a shorter period.</p>}</div>}
    </div>
  </section>
}
