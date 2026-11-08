import { useEffect, useState } from 'react'
import { createSavedView, deleteSavedView, fetchSavedViews } from '../api'
import { logFilterFingerprint } from '../lib/logPresets'
import { readPreference, writePreference } from '../lib/preferences'

import { FILTER_FIELDS, readFilterRules, isValidFilterRules } from '../lib/fieldFilterRules'
export { FILTER_FIELDS, readFilterRules, isValidFilterRules } from '../lib/fieldFilterRules'

const style = 'bg-gray-900 border border-gray-700 rounded px-2 py-1.5 text-sm text-gray-200'
const VIEW_SELECTION_KEY = 'unifi-log-insight:log-view-selection'
const validSelection = value => value && typeof value === 'object' && !Array.isArray(value)
  && typeof value.selected === 'string' && value.selected.length <= 128
  && typeof value.fingerprint === 'string' && value.fingerprint.length <= 32768

export default function FieldFilters({ filters, onChange, savedViews = true, presets = [], onPresetSelect, profileApplied = false, selectionStorageKey = VIEW_SELECTION_KEY }) {
  const [rules, setRules] = useState(() => readFilterRules(filters.filter_rules))
  const [views, setViews] = useState([])
  const [name, setName] = useState('')
  const [initialSelection] = useState(() => savedViews ? readPreference(selectionStorageKey, null, validSelection) : null)
  const [selected, setSelected] = useState(initialSelection?.selected || '')
  const [viewSnapshot, setViewSnapshot] = useState(initialSelection?.fingerprint || null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const selectedPreset = presets.find(preset => selected === `builtin:${preset.id}`)
  const fingerprint = logFilterFingerprint(filters)
  const selectionCurrent = selected && viewSnapshot === fingerprint && (!selectedPreset?.bypassProfile || !profileApplied)
  const presetCurrent = selectedPreset && selectionCurrent
  useEffect(() => {
    if (!savedViews) return
    writePreference(selectionStorageKey, { selected: selectionCurrent ? selected : '', fingerprint: selectionCurrent ? fingerprint : '' })
  }, [savedViews, selectionCurrent, selected, fingerprint, selectionStorageKey])
  useEffect(() => setRules(readFilterRules(filters.filter_rules)), [filters.filter_rules])
  const reloadViews = async () => {
    const result = await fetchSavedViews()
    setViews((result.views || []).filter(view => view.filters?.view_type === 'logs'))
  }
  useEffect(() => { if (savedViews) reloadViews().catch(e => setError(e.message)) }, [savedViews])
  const valid = isValidFilterRules(rules)
  const update = (index, patch) => setRules(current => current.map((rule, i) => i === index ? { ...rule, ...patch } : rule))
  const apply = () => onChange({ ...filters, filter_rules: rules.length ? JSON.stringify(rules) : null, page: 1 })
  const save = async () => {
    if (!name.trim() || !valid) return
    setBusy(true); setError('')
    try {
      const next = { ...filters, filter_rules: rules.length ? JSON.stringify(rules) : null, page: 1,
        time_range: (filters.time_from || filters.time_to) ? null : (filters.time_range || '24h') }
      const { page, per_page, sort, order, ...snapshot } = next
      const result = await createSavedView(name.trim(), { ...snapshot, view_type: 'logs', filter_rules: rules })
      if (result.id != null) {
        setSelected(String(result.id))
        setViewSnapshot(logFilterFingerprint(next))
      }
      onChange(next); setName(''); await reloadViews()
    } catch (e) { setError(e.message) } finally { setBusy(false) }
  }
  return <section className="rounded-lg border border-gray-800 bg-gray-900/40 p-3 space-y-3" aria-label="Include and exclude filters">
    <div className="flex flex-wrap items-center gap-3">
      <strong className="text-sm text-gray-200">Include / exclude</strong>
      <span className="text-xs text-gray-400">All conditions must match. Commas mean any listed value. Exclusions keep missing fields.</span>
    </div>
    {rules.map((rule, index) => <div key={index} className="flex flex-wrap gap-2">
      <select className={style} aria-label={`Field ${index + 1}`} value={rule.field} onChange={e => update(index, { field: e.target.value })}>
        {FILTER_FIELDS.map(([value, label]) => <option key={value} value={value}>{label}</option>)}
      </select>
      <select className={style} aria-label={`Operator ${index + 1}`} value={rule.operator} onChange={e => update(index, { operator: e.target.value })}>
        <option value="include">Include</option><option value="exclude">Exclude</option>
        <option value="present">Has value</option><option value="missing">Missing value</option>
      </select>
      {!['present', 'missing'].includes(rule.operator) && <input className={`${style} flex-1 min-w-40`} aria-label={`Value ${index + 1}`} maxLength={1024} value={rule.value || ''} onChange={e => update(index, { value: e.target.value })} placeholder={rule.field === 'security_event' ? 'ips or unparsed_cef (comma OR)' : 'IP/CIDR, port range, or literal text'} />}
      <button type="button" className="text-sm text-red-400 px-2" aria-label={`Remove condition ${index + 1}`} onClick={() => setRules(current => current.filter((_, i) => i !== index))}>Remove</button>
    </div>)}
    <div className="flex flex-wrap gap-2 items-center">
      <button type="button" className={style} disabled={rules.length >= 24} onClick={() => setRules(current => [...current, { field: 'ip', operator: 'exclude', value: '' }])}>Add condition</button>
      <button type="button" className={`${style} border-blue-600 disabled:opacity-40`} disabled={!valid} onClick={apply}>Apply filters</button>
      <button type="button" className={style} onClick={() => { setRules([]); onChange({ ...filters, filter_rules: null, page: 1 }) }}>Clear conditions</button>
    </div>
    <p className="text-xs text-gray-500">IP fields accept exact addresses or CIDRs. Ports accept values such as 443,8000-8100. Names match literal text; protocol, country and action match complete values.</p>
    {savedViews && <div className="flex flex-wrap gap-2 border-t border-gray-800 pt-3">
      <select className={style} aria-label={presets.length ? 'Log view' : 'Saved log view'} value={selectionCurrent ? selected : ''} onChange={e => {
        setSelected(e.target.value)
        const preset = presets.find(item => e.target.value === `builtin:${item.id}`)
        if (preset) { const next = onPresetSelect?.(preset); setViewSnapshot(next ? logFilterFingerprint(next) : null); return }
        setViewSnapshot(null)
        const view = views.find(v => String(v.id) === e.target.value)
        if (view) {
          const { view_type, ...rest } = view.filters
          const next = { ...rest, filter_rules: JSON.stringify(readFilterRules(rest.filter_rules)), page: 1, per_page: filters.per_page || 50 }
          if (next.time_from || next.time_to) next.time_range = null
          setViewSnapshot(logFilterFingerprint(next))
          onChange(next)
        }
      }}><option value="">{presets.length ? 'Choose log view' : 'Saved log views'}</option>
        {presets.length > 0 && <optgroup label="Built-in">{presets.map(preset => <option key={preset.id} value={`builtin:${preset.id}`}>{preset.name}</option>)}</optgroup>}
        <optgroup label="Saved">{views.map(view => <option key={view.id} value={view.id}>{view.name}</option>)}</optgroup>
      </select>
      <input className={style} aria-label="New view name" value={name} maxLength={100} onChange={e => setName(e.target.value)} placeholder="Name this view" />
      <button className={style} type="button" disabled={busy || !valid || !name.trim()} onClick={save}>Save view</button>
      {selectionCurrent && !selectedPreset && <button className={style} type="button" disabled={busy} onClick={async () => {
        setBusy(true); setError(''); try { await deleteSavedView(selected); setSelected(''); await reloadViews() } catch (e) { setError(e.message) } finally { setBusy(false) }
      }}>Delete saved view</button>}
    </div>}
    {presetCurrent && <p className="text-xs text-gray-400" aria-label="Selected log view scope">Last 24h. {selectedPreset.description} {profileApplied ? 'The active exclusion profile also applies.' : 'No profile exclusions applied.'}</p>}
    {error && <p className="text-sm text-red-400" role="alert">{error}</p>}
  </section>
}
