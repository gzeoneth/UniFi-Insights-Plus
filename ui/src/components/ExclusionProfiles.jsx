import { createContext, useContext, useEffect, useRef, useState } from 'react'
import { createSavedView, deleteSavedView, fetchSavedViews, fetchExclusionPreview } from '../api'
import { FILTER_FIELDS } from './FieldFilters'

export const EXCLUSION_DEFAULT_KEY = 'unifi-log-insight:exclusion-default'
const ExclusionContext = createContext({ excludeGroups: null, openDraft: () => {}, activeName: null })
const style = 'bg-gray-950 border border-gray-700 rounded px-2 py-1.5 text-sm text-gray-200 disabled:opacity-40'
const fields = [
  ['rule_name_exact', 'Exact recorded rule ID / name'],
  ['rule_desc_exact', 'Exact recorded rule description'],
  ['hostname_exact', 'Exact gateway hostname'],
  ...FILTER_FIELDS,
]

export function validExclusionGroups(groups) {
  return Array.isArray(groups) && groups.length > 0 && groups.length <= 12
    && JSON.stringify(groups).length <= 16384
    && groups.reduce((n, g) => n + (g?.conditions?.length || 0), 0) <= 48
    && groups.every(g => g && (g.name === undefined || (typeof g.name === 'string' && g.name.length <= 100))
      && Array.isArray(g.conditions) && g.conditions.length > 0 && g.conditions.length <= 8
      && g.conditions.every(c => c && fields.some(([f]) => f === c.field)
        && ['include', 'exclude', 'present', 'missing'].includes(c.operator)
        && (['present', 'missing'].includes(c.operator)
          || (typeof c.value === 'string' && c.value.trim().length > 0 && c.value.length <= 1024))))
}

export function ruleExclusionGroup(row) {
  if (row.rule_action !== 'allow' || !row.rule_name?.trim() || !row.hostname?.trim()
    || ['ips', 'unifi_ips'].includes(row.event_source) || row.ips_signature_id) return null
  const conditions = [
    { field: 'rule_name_exact', operator: 'include', value: row.rule_name },
    { field: 'hostname_exact', operator: 'include', value: row.hostname },
    { field: 'rule_action', operator: 'include', value: 'allow' },
  ]
  if (row.rule_desc?.trim()) conditions.push({ field: 'rule_desc_exact', operator: 'include', value: row.rule_desc })
  return { name: (row.rule_desc || row.rule_name).slice(0, 100), conditions }
}

export function useExclusionProfile() { return useContext(ExclusionContext) }

export function ExclusionCounts({ counts }) {
  if (!counts) return null
  return <p className="text-xs text-gray-400" aria-label="View event counts">
    {Number(counts.visible).toLocaleString()} visible · {Number(counts.hidden).toLocaleString()} hidden by profile · {Number(counts.total).toLocaleString()} matching events before profile
  </p>
}

function storedDefault() {
  try { return localStorage.getItem(EXCLUSION_DEFAULT_KEY) || '' } catch { return '' }
}

export function ExclusionProfileProvider({ children }) {
  const [profiles, setProfiles] = useState([])
  const [active, setActive] = useState(null)
  const [showAll, setShowAll] = useState(false)
  const [defaultId, setDefaultId] = useState(storedDefault)
  const defaultIdRef = useRef(defaultId)
  const [editor, setEditor] = useState(null)
  const [error, setError] = useState('')
  const selectionRevision = useRef(0)
  const listRevision = useRef(0)
  useEffect(() => {
    let cancelled = false
    const selection = selectionRevision.current, list = listRevision.current
    fetchSavedViews().then(result => {
      if (cancelled) return
      const profiles = (result.views || []).filter(v => v.filters?.view_type === 'exclusions')
      if (listRevision.current === list) setProfiles(profiles)
      const id = storedDefault()
      if (id && selectionRevision.current === selection) {
        const profile = profiles.find(v => String(v.id) === id)
        if (profile && validExclusionGroups(profile.filters.exclude_groups)) setActive(profile)
        else setError('The browser default profile is unavailable. Showing all events.')
      }
    }).catch(e => {
      if (!cancelled && selectionRevision.current === selection && listRevision.current === list) {
        setError(`Could not load exclusion profiles: ${e.message}. Showing all events.`)
      }
    })
    return () => { cancelled = true }
  }, [])
  const chooseProfile = value => { selectionRevision.current++; setActive(value) }
  const updateProfiles = value => { listRevision.current++; setProfiles(value) }
  const rememberDefault = id => {
    try {
      if (id) localStorage.setItem(EXCLUSION_DEFAULT_KEY, id)
      else localStorage.removeItem(EXCLUSION_DEFAULT_KEY)
      defaultIdRef.current = id
      setDefaultId(id)
    } catch { setError('This browser could not save the default profile.') }
  }
  const clearDefaultFor = id => { if (defaultIdRef.current === id) rememberDefault('') }
  const openDraft = (row, filters = {}) => {
    const group = ruleExclusionGroup(row)
    if (!group) return
    setEditor({ groups: [...(active?.filters.exclude_groups || []), group], name: '', scope: filters })
  }
  const excludeGroups = !showAll && active ? JSON.stringify(active.filters.exclude_groups) : null
  return <ExclusionContext.Provider value={{ profiles, setProfiles: updateProfiles, active, setActive: chooseProfile, showAll, setShowAll,
    defaultId, rememberDefault, clearDefaultFor, editor, setEditor, error, setError, excludeGroups,
    activeName: active?.name || null, openDraft }}>{children}</ExclusionContext.Provider>
}

export default function ExclusionProfiles({ activeTab }) {
  const ctx = useExclusionProfile()
  const [selected, setSelected] = useState('')
  const [busy, setBusy] = useState(false)
  const supported = ['logs', 'flow-view', 'dashboard', 'operations'].includes(activeTab)
  if (!supported) return null
  const remove = async () => {
    ctx.setError(''); setBusy(true)
    try {
      await deleteSavedView(selected)
      ctx.setProfiles(current => current.filter(v => String(v.id) !== selected))
      ctx.setActive(current => String(current?.id) === selected ? null : current)
      ctx.clearDefaultFor(selected)
      setSelected(current => current === selected ? '' : current)
    } catch (e) { ctx.setError(e.message) } finally { setBusy(false) }
  }
  return <section className="border-b border-gray-800 px-4 py-2 shrink-0 space-y-2" aria-label="View exclusion profiles">
    <div className="flex flex-wrap items-center gap-2">
      <strong className="text-sm text-gray-200">View exclusions</strong>
      <span className="text-xs text-gray-400">{ctx.active ? `${ctx.active.name}${ctx.showAll ? ' (bypassed)' : ''}` : 'None applied'}</span>
      {ctx.active && <label className="text-xs text-gray-300 flex items-center gap-1"><input type="checkbox" checked={ctx.showAll} onChange={e => ctx.setShowAll(e.target.checked)} />Show all (ignore profile)</label>}
      <select className={style} aria-label="Exclusion profile" value={selected} onChange={e => setSelected(e.target.value)}>
        <option value="">Saved exclusion profiles</option>{ctx.profiles.map(v => <option key={v.id} value={v.id}>{v.name}{String(v.id) === ctx.defaultId ? ' — default in this browser' : ''}</option>)}
      </select>
      <button className={style} disabled={!selected} onClick={() => {
        const profile = ctx.profiles.find(v => String(v.id) === selected)
        if (profile && validExclusionGroups(profile.filters.exclude_groups)) ctx.setEditor({ groups: profile.filters.exclude_groups, name: profile.name, profile, scope: { time_range: '24h' } })
        else ctx.setError('This profile is invalid. It has not been applied.')
      }}>Load and preview</button>
      <button className={style} onClick={() => ctx.setEditor({ groups: [], name: '', scope: { time_range: '24h' } })}>New profile</button>
      <button className={style} disabled={!selected || busy} onClick={remove}>Delete profile</button>
      <button className={style} disabled={!ctx.active?.id} onClick={() => ctx.rememberDefault(String(ctx.active.id))}>Make default in this browser</button>
      {ctx.defaultId && <button className={style} onClick={() => ctx.rememberDefault('')}>Clear browser default</button>}
    </div>
    <p className="text-xs text-gray-500">Logs, Rule Usage, charts and exports use this profile. Raw logs and collection are unchanged. Security and the threat map stay independent; IPS detections remain visible. Show all retains your other filters.</p>
    {ctx.error && <p role="alert" className="text-sm text-red-400">{ctx.error}</p>}
    {ctx.editor && <ExclusionEditor key={JSON.stringify(ctx.editor)} draft={ctx.editor} onClose={() => ctx.setEditor(null)} />}
  </section>
}

function ExclusionEditor({ draft, onClose }) {
  const ctx = useExclusionProfile()
  const [groups, setGroups] = useState(() => structuredClone(draft.groups))
  const [name, setName] = useState(draft.name)
  const [preview, setPreview] = useState(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const generation = useRef(0)
  const dialogRef = useRef(null)
  useEffect(() => () => { generation.current++ }, [])
  useEffect(() => {
    const previousFocus = document.activeElement
    const dialog = dialogRef.current
    dialog?.querySelector('button')?.focus()
    const keyboard = event => {
      if (event.key === 'Escape') { event.preventDefault(); onClose() }
      if (event.key !== 'Tab') return
      const controls = [...dialog.querySelectorAll('button:not(:disabled), input:not(:disabled), select:not(:disabled)')]
      const first = controls[0], last = controls[controls.length - 1]
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus() }
      if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus() }
    }
    dialog?.addEventListener('keydown', keyboard)
    return () => { dialog?.removeEventListener('keydown', keyboard); previousFocus?.focus() }
  }, []) // The editor is remounted for each draft.
  const change = next => { generation.current++; setGroups(next); setPreview(null); setBusy(false); setError('') }
  const updateGroup = (i, patch) => change(groups.map((g, j) => j === i ? { ...g, ...patch } : g))
  const updateCondition = (i, j, patch) => updateGroup(i, { conditions: groups[i].conditions.map((c, k) => j === k ? { ...c, ...patch } : c) })
  const valid = validExclusionGroups(groups)
  const scope = { ...draft.scope }
  for (const key of ['exclude_groups', 'page', 'per_page', 'sort', 'order']) delete scope[key]
  if (!scope.time_range && !scope.time_from && !scope.time_to) scope.time_range = '24h'
  const runPreview = async () => {
    const epoch = ++generation.current
    setBusy(true); setPreview(null); setError('')
    try {
      const result = await fetchExclusionPreview({ ...scope, exclude_groups: JSON.stringify(groups) })
      if (generation.current === epoch) setPreview(result)
    } catch (e) { if (generation.current === epoch) setError(e.message) }
    finally { if (generation.current === epoch) setBusy(false) }
  }
  const apply = async save => {
    if (!preview || !valid) return
    const epoch = ++generation.current
    setBusy(true); setError('')
    try {
      let profile = draft.profile && JSON.stringify(groups) === JSON.stringify(draft.profile.filters.exclude_groups)
        ? draft.profile : { name: name.trim() || 'Unsaved profile', filters: { view_type: 'exclusions', exclude_groups: groups } }
      if (save) {
        const saved = await createSavedView(name.trim(), { view_type: 'exclusions', exclude_groups: groups })
        const result = await fetchSavedViews()
        if (generation.current !== epoch) return
        const list = (result.views || []).filter(v => v.filters?.view_type === 'exclusions')
        ctx.setProfiles(list)
        profile = saved?.id ? saved : list.find(v => v.name === name.trim() && JSON.stringify(v.filters.exclude_groups) === JSON.stringify(groups)) || profile
      }
      ctx.setActive(profile); ctx.setShowAll(false); ctx.setError(''); onClose()
    } catch (e) { if (generation.current === epoch) setError(e.message) }
    finally { if (generation.current === epoch) setBusy(false) }
  }
  const total = groups.reduce((n, g) => n + (g.conditions?.length || 0), 0)
  return <div role="dialog" aria-label="Edit exclusion profile" aria-modal="true" className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
    <section ref={dialogRef} className="w-full max-w-4xl max-h-[85vh] overflow-y-auto rounded-lg border border-gray-700 bg-gray-900 p-4 space-y-3">
      <div className="flex justify-between items-center"><h2 className="font-semibold text-gray-100">Preview view exclusions</h2><button className={style} onClick={onClose}>Close editor</button></div>
      <p className="text-sm text-gray-400">Hide an event when every condition in any one group matches. Exact fields are case-sensitive and treat commas as literal text. An exact Matches condition requires a recorded value. IPS detections are retained.</p>
      <input className={style} aria-label="Exclusion profile name" value={name} maxLength={100} onChange={e => setName(e.target.value)} placeholder="Profile name" />
      {groups.map((g, i) => <fieldset key={i} className="border border-gray-700 rounded p-3 space-y-2">
        <legend className="text-sm text-gray-300">Group {i + 1} — all conditions match</legend>
        <div className="flex gap-2"><input className={`${style} flex-1`} aria-label={`Group ${i + 1} name`} maxLength={100} value={g.name || ''} onChange={e => updateGroup(i, { name: e.target.value })} placeholder="Optional group name" /><button className={style} onClick={() => change(groups.filter((_, j) => i !== j))}>Remove group {i + 1}</button></div>
        {g.conditions.map((c, j) => <div key={j} className="flex flex-wrap gap-2">
          <select className={style} aria-label={`Group ${i + 1} field ${j + 1}`} value={c.field} onChange={e => updateCondition(i, j, { field: e.target.value })}>{fields.map(([f, label]) => <option key={f} value={f}>{label}</option>)}</select>
          <select className={style} aria-label={`Group ${i + 1} operator ${j + 1}`} value={c.operator} onChange={e => updateCondition(i, j, { operator: e.target.value })}><option value="include">Matches</option><option value="exclude">Does not match</option><option value="present">Has value</option><option value="missing">Missing value</option></select>
          {!['present', 'missing'].includes(c.operator) && <input className={`${style} flex-1 min-w-40`} aria-label={`Group ${i + 1} value ${j + 1}`} maxLength={1024} value={c.value || ''} onChange={e => updateCondition(i, j, { value: e.target.value })} />}
          <button className={style} aria-label={`Remove group ${i + 1} condition ${j + 1}`} onClick={() => updateGroup(i, { conditions: g.conditions.filter((_, k) => j !== k) })}>Remove</button>
        </div>)}
        <button className={style} disabled={g.conditions.length >= 8 || total >= 48} onClick={() => updateGroup(i, { conditions: [...g.conditions, { field: 'rule_name_exact', operator: 'include', value: '' }] })}>Add condition to group {i + 1}</button>
      </fieldset>)}
      <button className={style} disabled={groups.length >= 12 || total >= 48} onClick={() => change([...groups, { name: '', conditions: [{ field: 'rule_name_exact', operator: 'include', value: '' }] }])}>Add exclusion group</button>
      <p className="text-xs text-gray-400">Preview scope: {scope.time_from || scope.time_to ? `${scope.time_from || 'start'} to ${scope.time_to || 'now'}` : `last ${scope.time_range}`}{Object.keys(scope).some(k => !k.startsWith('time_') && scope[k]) ? ', with the source view’s filters' : ''}. Counts describe this window, not future events.</p>
      <div className="flex gap-2 flex-wrap"><button className={style} disabled={!valid || busy} onClick={runPreview}>{busy ? 'Working…' : 'Preview matches'}</button><button className={style} disabled={!preview || !valid || busy} onClick={() => apply(false)}>Apply previewed profile</button><button className={style} disabled={!preview || !valid || !name.trim() || busy} onClick={() => apply(true)}>Save as new profile and apply</button></div>
      {preview && <div className="space-y-2"><ExclusionCounts counts={preview.view_counts} /><p className="text-xs text-gray-400">Sample events that would be hidden (up to 5):</p><ul className="text-xs text-gray-300 space-y-1">{(preview.examples || []).map((row, i) => <li key={row.id || i}>{row.timestamp} · {row.hostname || 'Unknown gateway'} · {row.rule_desc || row.rule_name || row.log_type || 'Event'} · {row.rule_action || 'Unknown action'}</li>)}</ul></div>}
      {error && <p role="alert" className="text-red-400 text-sm">{error}</p>}
    </section>
  </div>
}
