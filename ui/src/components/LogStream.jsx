import { useExclusionProfile, ExclusionCounts } from './ExclusionProfiles'
import { useState, useEffect, useCallback, useRef, useMemo } from 'react'
import { fetchLogs, fetchLog, getExportUrl, fetchLogCountsByType } from '../api'
import { readPreference, writePreference, readTimeRange, writeTimeRange } from '../lib/preferences'
import FilterBar from './FilterBar'
import FieldFilters, { isValidFilterRules } from './FieldFilters'
import LogTable from './LogTable'
import Pagination from './Pagination'
import { LOG_PRESETS, buildLogPresetFilters } from '../lib/logPresets'
import useSerializedPoll from '../hooks/useSerializedPoll'
import { LOG_PAGE_SIZE_KEY, logPageSize } from '../lib/pageSizes'
import { flowDrillScope } from '../lib/flowDrillScope'

const DEFAULT_FILTERS = {
  time_range: '24h',
  filter_rules: null,
  log_type: null,
  rule_action: null,
  direction: null,
  ip: null,
  src_ip: null,
  dst_ip: null,
  rule_name: null,
  search: null,
  service: null,
  country: null,
  asn: null,
  dst_port: null,
  src_port: null,
  protocol: null,
  interface: null,
  vpn_only: null,
  threat_min: null,
  time_from: null,
  time_to: null,
  page: 1,
  per_page: 50,
  sort: 'timestamp',
  order: 'desc',
}

const STORAGE_KEY = 'unifi-log-insight:log-types'
const ACTION_STORAGE_KEY = 'unifi-log-insight:rule-action'
const DIRECTION_STORAGE_KEY = 'unifi-log-insight:direction'
const COLUMNS_STORAGE_KEY = 'unifi-log-insight:hidden-columns'
const FILTERS_STORAGE_KEY = 'unifi-log-insight:log-filters:v1'
const REFRESH_STORAGE_KEY = 'unifi-log-insight:log-auto-refresh'
const DNS_VIEW_CONTROLS = new Set(['log_type', 'time_range', 'time_from', 'time_to', 'page', 'per_page', 'sort', 'order'])

const TOGGLEABLE_COLUMNS = [
  { key: 'country', label: 'Country' },
  { key: 'asn', label: 'ASN' },
  { key: 'proto', label: 'Protocol' },
  { key: 'rule', label: 'Rule / Info' },
  { key: 'threat', label: 'AbuseIPDB' },
  { key: 'categories', label: 'Categories' },
]

const isRecord = value => value !== null && typeof value === 'object' && !Array.isArray(value)
const isText = value => typeof value === 'string' && value.length <= 4096
const SORT_FIELDS = new Set(['timestamp', 'log_type', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
  'protocol', 'service_name', 'direction', 'rule_action', 'rule_name', 'geo_country',
  'threat_score', 'hostname', 'created_at'])
const TEXT_FILTERS = ['log_type', 'rule_action', 'direction', 'ip', 'src_ip', 'dst_ip',
  'rule_name', 'search', 'service', 'country', 'asn', 'dst_port', 'src_port', 'protocol', 'interface']

// Only applied query preferences belong here. Response data and frozen cursors
// must never survive a reload and masquerade as current results.
function filterSnapshot(value) {
  const result = {}
  for (const key of TEXT_FILTERS) {
    if (value[key] == null || isText(value[key])) result[key] = value[key] ?? null
    else if (['dst_port', 'src_port'].includes(key) && Number.isInteger(value[key])) result[key] = String(value[key])
  }
  if (value.vpn_only == null || typeof value.vpn_only === 'boolean') result.vpn_only = value.vpn_only ?? null
  if (value.threat_min == null || (Number.isInteger(value.threat_min) && value.threat_min >= 0 && value.threat_min <= 100)) result.threat_min = value.threat_min ?? null
  if (SORT_FIELDS.has(value.sort)) result.sort = value.sort
  if (['asc', 'desc'].includes(value.order)) result.order = value.order
  result.per_page = logPageSize(value.per_page)
  for (const key of ['time_from', 'time_to']) {
    if (typeof value[key] === 'string' && value[key].length <= 64 && Number.isFinite(Date.parse(value[key]))) result[key] = value[key]
  }
  if (result.time_from && result.time_to && Date.parse(result.time_from) > Date.parse(result.time_to)) {
    delete result.time_from; delete result.time_to
  }
  // The API gives explicit dates priority, including legacy saved views that
  // also contain a relative range. Preserve that scope when restoring them.
  if (result.time_from || result.time_to) result.time_range = null
  try {
    const rules = typeof value.filter_rules === 'string' ? JSON.parse(value.filter_rules) : value.filter_rules
    if (isValidFilterRules(rules)) {
      result.filter_rules = rules.length ? JSON.stringify(rules.map(({ field, operator, value }) => ({ field, operator, ...(value == null ? {} : { value }) }))) : null
    }
  } catch { /* Invalid stored filters do not prevent the page from opening. */ }
  return result
}

function restoreFilters() {
  const restored = { ...DEFAULT_FILTERS, time_range: readTimeRange() }
  const saved = readPreference(FILTERS_STORAGE_KEY, null, isRecord)
  if (saved) return { ...restored, ...filterSnapshot(saved) }
  restored.per_page = logPageSize(readPreference(LOG_PAGE_SIZE_KEY, 50, value => typeof value === 'number' || typeof value === 'string'))
  for (const [field, key] of [['log_type', STORAGE_KEY], ['rule_action', ACTION_STORAGE_KEY], ['direction', DIRECTION_STORAGE_KEY]]) {
    restored[field] = readPreference(key, null, value => value === null || isText(value))
  }
  return restored
}

export default function LogStream({ version, latestRelease, maxFilterDays, drillFilters, onDrillConsumed, interfaces: prefetchedInterfaces, onPauseChange, uiSettings }) {
  const { excludeGroups, openDraft, setShowAll } = useExclusionProfile()
  const [filters, setFilters] = useState(() => {
    const restored = restoreFilters()
    if (drillFilters) {
      return {
        ...DEFAULT_FILTERS,
        ...flowDrillScope(drillFilters),
        time_range: (drillFilters.time_from || drillFilters.time_to) ? null : (drillFilters.time_range || restored.time_range || readTimeRange()),
        time_from: drillFilters.time_from || null,
        time_to: drillFilters.time_to || null,
        page: 1,
        per_page: restored.per_page,
        sort: restored.sort,
        order: restored.order,
      }
    }
    return restored
  })
  const [autoRefresh, setAutoRefresh] = useState(() => readPreference(REFRESH_STORAGE_KEY, true, value => typeof value === 'boolean'))
  const [expandedId, setExpandedId] = useState(null)
  const [detailedLog, setDetailedLog] = useState(null)
  const [hiddenColumns, setHiddenColumns] = useState(() => new Set(readPreference(COLUMNS_STORAGE_KEY, [], value => Array.isArray(value)
    && value.every(key => TOGGLEABLE_COLUMNS.some(column => column.key === key)))))
  const [showColumnsMenu, setShowColumnsMenu] = useState(false)
  const columnsMenuRef = useRef(null)
  const scrollRef = useRef(null)
  const [showScrollTop, setShowScrollTop] = useState(false)
  const [drillContext, setDrillContext] = useState(null)

  // Derive hidden log types: processing disabled AND confirmed zero records in DB
  // null = unknown (fetch pending/failed) — keep badges visible until confirmed zero
  const [logTypeCounts, setLogTypeCounts] = useState(null)
  const wifiDisabled = uiSettings?.wifi_processing_enabled === false
  const systemDisabled = uiSettings?.system_processing_enabled === false
  useEffect(() => {
    if (!wifiDisabled && !systemDisabled) { setLogTypeCounts(null); return }
    fetchLogCountsByType().then(setLogTypeCounts).catch(err => console.error('Failed to load log counts:', err))
  }, [wifiDisabled, systemDisabled])
  const hiddenLogTypes = useMemo(() => {
    const hidden = new Set()
    if (!logTypeCounts) return hidden // unknown → keep all visible
    if (wifiDisabled && logTypeCounts.wifi === 0) hidden.add('wifi')
    if (systemDisabled && logTypeCounts.system === 0) hidden.add('system')
    return hidden
  }, [wifiDisabled, systemDisabled, logTypeCounts])

  // Apply drill filters from FlowView (F1/F4/F8)
  useEffect(() => {
    if (!drillFilters) return
    setFilters(prev => ({
      ...DEFAULT_FILTERS,
      ...flowDrillScope(drillFilters),
      time_range: (drillFilters.time_from || drillFilters.time_to) ? null : (drillFilters.time_range || prev.time_range || readTimeRange()),
      time_from: drillFilters.time_from || null,
      time_to: drillFilters.time_to || null,
      page: 1,
      per_page: prev.per_page,
      sort: prev.sort,
      order: prev.order,
    }))
    // Build display string for drill indicator banner
    const parts = []
    if (drillFilters.src_ip) parts.push(drillFilters.src_ip)
    if (drillFilters.dst_ip) parts.push(drillFilters.dst_ip)
    const label = parts.join(' \u2192 ')
    const portProto = [
      drillFilters.dst_port && `:${drillFilters.dst_port}`,
      drillFilters.service,
    ].filter(Boolean).join(' ')
    setDrillContext(label + (portProto ? ` ${portProto}` : ''))
    onDrillConsumed?.()
  }, [drillFilters]) // eslint-disable-line react-hooks/exhaustive-deps

  const clearDrill = useCallback(() => {
    setDrillContext(null)
    setFilters(prev => ({ ...DEFAULT_FILTERS, per_page: prev.per_page, sort: prev.sort, order: prev.order }))
    window.dispatchEvent(new Event('returnFromDrill'))
  }, [])


  useEffect(() => {
    writePreference(FILTERS_STORAGE_KEY, filterSnapshot(filters))
    writePreference(LOG_PAGE_SIZE_KEY, filters.per_page)
    if (filters.time_range) writeTimeRange(filters.time_range)
  }, [filters])
  useEffect(() => { writePreference(REFRESH_STORAGE_KEY, autoRefresh) }, [autoRefresh])

  // Persist hidden columns to localStorage
  const toggleColumn = (key) => {
    setHiddenColumns(prev => {
      const next = new Set(prev)
      if (next.has(key)) next.delete(key)
      else next.add(key)
      writePreference(COLUMNS_STORAGE_KEY, [...next])
      return next
    })
  }

  // Close columns menu on click outside
  useEffect(() => {
    if (!showColumnsMenu) return
    const handler = (e) => {
      if (columnsMenuRef.current && !columnsMenuRef.current.contains(e.target)) {
        setShowColumnsMenu(false)
      }
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [showColumnsMenu])

  const scopeKey = JSON.stringify({ ...filters, page: undefined, exclude_groups: excludeGroups })
  const [navigation, setNavigation] = useState(null)
  const page = navigation?.scopeKey === scopeKey ? navigation.page : 1
  const cursor = navigation?.scopeKey === scopeKey ? navigation.cursor : null
  const cursorHistory = useRef({ scopeKey: null, pages: [] })
  const cursorMode = !filters.sort || filters.sort === 'timestamp'
  const isRefreshing = autoRefresh && expandedId === null && page === 1 && !cursor
  const params = { ...filters, page, sort: filters.sort || 'timestamp', order: filters.order || 'desc', exclude_groups: excludeGroups, count_mode: 'none',
    pagination: cursorMode ? 'cursor' : 'offset', cursor: cursorMode ? cursor : null }
  const poll = useSerializedPoll({ params, fetcher: fetchLogs, enabled: isRefreshing })
  const data = poll.data || { data: [], total: null, pages: null, view_counts: null }
  const loading = poll.loading
  const lastUpdate = poll.loadedAt
  const loadError = poll.error
    ? (poll.error.status === 400 ? poll.error.message : 'Could not load events for the current filters. Refresh to try again.') : ''
  const showDnsHelp = Boolean(poll.data) && !loading && !loadError && page === 1 && data.data.length === 0
    && filters.log_type === 'dns' && !excludeGroups
    && !Object.entries(filters).some(([key, value]) => !DNS_VIEW_CONTROLS.has(key) && value != null && value !== '' && value !== false)

  useEffect(() => {
    if (!poll.data) return
    if (cursorHistory.current.scopeKey !== scopeKey || (page === 1 && !cursor)) {
      cursorHistory.current = { scopeKey, pages: [] }
    }
    cursorHistory.current.pages[page] = poll.data.page_cursor || cursor
    cursorHistory.current.pages[page + 1] = poll.data.next_cursor
  }, [poll.data, scopeKey, page, cursor])

  useEffect(() => { onPauseChange?.(!isRefreshing || !poll.visible) }, [isRefreshing, poll.visible, onPauseChange])

  const refreshLatest = () => {
    setExpandedId(null)
    if (page !== 1 || cursor) setNavigation(null)
    else poll.refresh()
  }

  // Fetch detail data when a row is expanded
  useEffect(() => {
    if (expandedId === null) { setDetailedLog(null); return }
    let cancelled = false
    fetchLog(expandedId)
      .then(detail => { if (!cancelled) setDetailedLog(detail) })
      .catch(() => { if (!cancelled) setDetailedLog(null) })
    return () => { cancelled = true }
  }, [expandedId])

  // Collapsing resumes the regular polling delay without adding a second request.
  const handleToggleExpand = (id) => {
    if (expandedId === id) {
      setExpandedId(null)
    } else {
      setExpandedId(id)
    }
  }

  // Show scroll-to-top button when scrolled down
  useEffect(() => {
    const el = scrollRef.current
    if (!el) return
    const handleScroll = () => setShowScrollTop(el.scrollTop > 300)
    el.addEventListener('scroll', handleScroll, { passive: true })
    return () => el.removeEventListener('scroll', handleScroll)
  }, [])

  useEffect(() => { setExpandedId(null) }, [excludeGroups])

  const handleFilterChange = (newFilters) => {
    setExpandedId(null)
    setFilters({ ...newFilters, page: 1 })
  }

  const handlePageChange = (page) => {
    setExpandedId(null)
    const nextCursor = cursorHistory.current.scopeKey === scopeKey ? cursorHistory.current.pages[page] : null
    if (cursorMode && !nextCursor) return
    setNavigation({ scopeKey, page, cursor: nextCursor })
  }

  const handlePerPageChange = (size) => {
    setExpandedId(null)
    setNavigation(null)
    setFilters(prev => ({ ...prev, per_page: logPageSize(size), page: 1 }))
    scrollRef.current?.scrollTo?.({ top: 0 })
  }

  const handlePresetSelect = preset => {
    const next = buildLogPresetFilters(preset, filters, DEFAULT_FILTERS)
    if (preset.bypassProfile) setShowAll?.(true)
    setDrillContext(null)
    handleFilterChange(next)
    return next
  }

  return (
    <div className="flex flex-col h-full">
      {/* Drill indicator banner (F8) */}
      {drillContext && (
        <div className="flex items-center justify-between px-4 py-1.5 bg-blue-500/10 border-b border-blue-500/30 text-xs text-blue-400">
          <span>Showing: <span className="font-medium text-blue-300">{drillContext}</span></span>
          <button onClick={clearDrill} className="text-blue-400 hover:text-blue-300 ml-4">&#x2715;</button>
        </div>
      )}
      {/* Filters */}
      <div className="px-4 py-2.5 border-b border-gray-800 bg-gray-950 relative z-20">
        <FilterBar filters={filters} onChange={handleFilterChange} maxFilterDays={maxFilterDays} prefetchedInterfaces={prefetchedInterfaces} hiddenLogTypes={hiddenLogTypes} />
        <FieldFilters filters={filters} onChange={handleFilterChange} presets={LOG_PRESETS} onPresetSelect={handlePresetSelect} profileApplied={!!excludeGroups} />
        {!loading && <ExclusionCounts counts={data.view_counts} unknown={Boolean(excludeGroups)} />}
        {loadError && <p role="alert" className="text-sm text-red-400">{loadError}</p>}
      </div>

      {/* Toolbar */}
      <div className="flex items-center justify-between px-4 py-1.5 border-b border-gray-800/50 bg-gray-950">
        <div className="flex items-center gap-3">
          <button
            onClick={() => {
              if (cursor || page > 1) { setNavigation(null); setAutoRefresh(true) }
              else setAutoRefresh(value => !value)
            }}
            className={`flex items-center gap-1.5 text-[11px] transition-colors ${
              isRefreshing ? 'text-emerald-400' : 'text-amber-400'
            }`}
          >
            <span className={`w-1.5 h-1.5 rounded-full ${isRefreshing && poll.visible ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'}`} />
            {isRefreshing && poll.visible ? 'Live' : 'Paused'}
          </button>
          {(!isRefreshing || !poll.visible) && <span className="text-[10px] text-gray-500">Automatic requests stopped</span>}
          {lastUpdate && (
            <span className="text-[10px] text-gray-500">
              Updated {lastUpdate.toLocaleTimeString('en-GB')}
            </span>
          )}
          {data.timings?.query_ms != null && <span className="text-[10px] text-gray-500">
            Page {Math.round(data.timings.query_ms)} ms{data.timings.count_ms != null ? ` · count ${Math.round(data.timings.count_ms)} ms` : ''}
          </span>}
        </div>
        <div className="flex items-center gap-2">
          <div className="relative inline-flex items-center" ref={columnsMenuRef}>
            {(() => {
              const asnAsSubline = uiSettings?.ui_ip_subline === 'asn_or_abuse'
              const menuColumns = TOGGLEABLE_COLUMNS.filter(col => !(col.key === 'asn' && asnAsSubline))
              return (
                <>
                  <button
                    onClick={() => setShowColumnsMenu(v => !v)}
                    className={`text-[11px] transition-colors ${hiddenColumns.size > 0 ? 'text-amber-400' : 'text-gray-400 hover:text-gray-200'}`}
                  >
                    Columns{hiddenColumns.size > 0 ? ` (${menuColumns.length - hiddenColumns.size}/${menuColumns.length})` : ''}
                  </button>
                  {showColumnsMenu && (
                    <div className="absolute right-0 top-full mt-1 w-40 bg-gray-950 border border-gray-700 rounded shadow-lg z-20 py-1">
                      {menuColumns.map(col => (
                        <label
                          key={col.key}
                          className="flex items-center gap-2 px-3 py-1.5 text-xs text-gray-300 hover:bg-gray-800 cursor-pointer select-none"
                        >
                          <input
                            type="checkbox"
                            checked={!hiddenColumns.has(col.key)}
                            onChange={() => toggleColumn(col.key)}
                            className="ui-checkbox"
                          />
                          {col.label}
                        </label>
                      ))}
                      <div className="border-t border-gray-700 mt-1 pt-1 px-3 pb-1">
                        <button
                          onClick={() => setShowColumnsMenu(false)}
                          className="w-full text-xs text-gray-300 hover:text-gray-200 py-1 transition-colors"
                        >
                          Done
                        </button>
                      </div>
                    </div>
                  )}
                </>
              )
            })()}
          </div>
          <button
            onClick={refreshLatest}
            className="text-[11px] text-gray-400 hover:text-gray-200 transition-colors"
          >
            ↻ Refresh
          </button>
          <button type="button" disabled={loading}
            onClick={() => {
              setAutoRefresh(false)
              poll.refresh({ count_mode: 'exact', cursor: data.page_cursor || cursor })
            }}
            className="text-[11px] text-gray-400 hover:text-gray-200 disabled:opacity-40"
            title="Pause updates and count all matching events in this time window. This can take longer than loading a page.">
            Count matching events
          </button>
          <a
            href={getExportUrl({ ...filters, exclude_groups: excludeGroups })}
            className="text-[11px] text-gray-400 hover:text-gray-200 transition-colors"
          >
            ↓ Export CSV
          </a>
        </div>
      </div>

      {showDnsHelp && <aside aria-label="DNS logging help" className="mx-4 my-3 rounded border border-gray-700 px-3 py-2 text-xs text-gray-400">
        <p>No parsed DNS query records match this time window. Firewall flows on port 53 do not contain the queried domain names.</p>
        <p className="mt-1">Gateway DNS flow logging alone does not confirm DNS query logging or export. Check the time range and the resolver's query-log settings; a resolver query-log integration may be needed.{' '}
          <a className="text-teal-400 underline hover:text-teal-300" href="https://github.com/gzeoneth/UniFi-Insights-Plus/blob/gzeon/insights-improvements/docs/dns-logging.md" target="_blank" rel="noreferrer">DNS logging guide</a>
        </p>
      </aside>}

      {/* Log table */}
      <div className="flex-1 relative overflow-hidden">
        <div className="h-full overflow-auto" ref={scrollRef}>
          <LogTable onHideAllow={row => openDraft(row, filters)} logs={data.data} loading={loading} expandedId={expandedId} detailedLog={detailedLog} onToggleExpand={handleToggleExpand} hiddenColumns={hiddenColumns} uiSettings={uiSettings} />
        </div>
        {showScrollTop && (
          <button
            onClick={() => scrollRef.current?.scrollTo({ top: 0, behavior: 'smooth' })}
            className="absolute bottom-4 right-4 z-20 w-8 h-8 rounded-full bg-gray-800 border border-gray-700 text-gray-400 hover:text-gray-200 hover:bg-gray-700 transition-colors shadow-lg flex items-center justify-center"
            title="Scroll to top"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M5 15l7-7 7 7" />
            </svg>
          </button>
        )}
      </div>

      {/* Pagination */}
      <Pagination
        page={page}
        pages={data.pages}
        total={data.total}
        rowCount={data.data.length}
        hasMore={data.has_more ?? (data.pages != null && page < data.pages)}
        cursorMode={cursorMode}
        loading={loading}
        perPage={filters.per_page}
        onPerPageChange={handlePerPageChange}
        onChange={handlePageChange}
        version={version}
        latestRelease={latestRelease}
      />
    </div>
  )
}
