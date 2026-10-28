import { useExclusionProfile } from './ExclusionProfiles'
import { useState, useCallback, useEffect, useRef, lazy, Suspense } from 'react'
import useTimeRange from '../hooks/useTimeRange'
import { ACTION_STYLES, DIRECTION_ICONS, DIRECTION_COLORS } from '../utils'
import { fetchSavedViews, createSavedView, deleteSavedView } from '../api'
import SankeyChart from './SankeyChart'
import TopIPPairs from './TopIPPairs'
import HostSlidePanel from './HostSlidePanel'
import DateRangePicker from './DateRangePicker'
import FieldFilters, { readFilterRules } from './FieldFilters'
import { readPreference, writePreference } from '../lib/preferences'
import { FLOW_PREFERENCE_KEY, FLOW_ACTIONS, FLOW_DIRECTIONS, normalizeFlowPreferences, isFlowHostIp } from '../lib/flowPreferences'

const ZoneMatrix = lazy(() => import('./ZoneMatrix'))

const ACTIONS = FLOW_ACTIONS
const DIRECTIONS = FLOW_DIRECTIONS
const SUB_TABS = [
  { key: 'sankey', label: 'Flow Graph' },
  { key: 'zone-matrix', label: 'Zone Matrix' },
]

export default function FlowView({ maxFilterDays }) {
  const { excludeGroups } = useExclusionProfile()
  const [initialFilters] = useState(() => normalizeFlowPreferences(readPreference(FLOW_PREFERENCE_KEY, {})))
  const [timeRange, setTimeRange, visibleRanges] = useTimeRange(maxFilterDays)
  const [activeActions, setActiveActions] = useState(initialFilters.activeActions || ACTIONS)
  const [activeDirections, setActiveDirections] = useState(initialFilters.activeDirections || DIRECTIONS)
  const [refreshKey, setRefreshKey] = useState(0)
  const [dims, setDims] = useState(initialFilters.dims || ['src_ip', 'dst_port', 'dst_ip'])
  const [topN, setTopN] = useState(initialFilters.topN || 15)
  const [activeViewName, setActiveViewName] = useState(() => (
    initialFilters.timeFrom || initialFilters.timeTo || initialFilters.timeRange === timeRange
  ) ? initialFilters.activeViewName : null)
  const [filterRules, setFilterRules] = useState(() => readFilterRules(initialFilters.filter_rules))

  // Saved views list
  const [savedViews, setSavedViews] = useState([])

  // Sub-tab state
  const [activePanel, setActivePanel] = useState(initialFilters.activePanel)

  // Defer ip-pairs until Sankey resolves (avoid concurrent heavy queries).
  // Uses request-key matching instead of a boolean to avoid effect-order races on remount.
  const [sankeyFulfilledKey, setSankeyFulfilledKey] = useState(null)

  // Cross-filter state
  const [sankeyFilter, setSankeyFilter] = useState(initialFilters.sankeyFilter)
  const [zoneFilter, setZoneFilter] = useState(initialFilters.zoneFilter)

  // Host detail expansion state — { ip, rowIndex } or null
  const [expandedRow, setExpandedRow] = useState(() => initialFilters.hostIp ? { ip: initialFilters.hostIp, rowIndex: -1 } : null)
  // Navigation history stack for host detail drill-down
  const [hostHistory, setHostHistory] = useState([])
  const [hostSearchInput, setHostSearchInput] = useState(initialFilters.hostSearchInput)
  const [filtersExpanded, setFiltersExpanded] = useState(initialFilters.filtersExpanded)
  const [advancedExpanded, setAdvancedExpanded] = useState(initialFilters.advancedExpanded)
  const [timeFrom, setTimeFrom] = useState(initialFilters.timeFrom || null)
  const [timeTo, setTimeTo] = useState(initialFilters.timeTo || null)

  // Ref to suppress badge clear during bulk-set operations (load, hydration, initial render)
  const skipBadgeClear = useRef(true)
  useEffect(() => {
    const timer = setTimeout(() => { skipBadgeClear.current = false }, 0)
    return () => clearTimeout(timer)
  }, [])

  // Initial filters are read before children can start a query.
  useEffect(() => {
    writePreference(FLOW_PREFERENCE_KEY, normalizeFlowPreferences({
      dims, topN, activeActions, activeDirections,
      timeRange, timeFrom, timeTo, activeViewName, filter_rules: filterRules,
      activePanel, filtersExpanded, advancedExpanded, sankeyFilter, zoneFilter,
      hostIp: expandedRow?.ip, hostSearchInput,
    }))
  }, [dims, topN, activeActions, activeDirections, timeRange, timeFrom, timeTo, activeViewName, filterRules,
    activePanel, filtersExpanded, advancedExpanded, sankeyFilter, zoneFilter, expandedRow?.ip, hostSearchInput])

  // Badge clear: any manual filter change clears the active view badge
  useEffect(() => {
    if (skipBadgeClear.current) return
    setActiveViewName(null)
  }, [activeActions, activeDirections, timeRange, timeFrom, timeTo, dims, topN, filterRules])

  // Derive a request key from the same deps SankeyChart uses to fetch.
  // When sankeyFulfilledKey matches, Sankey has satisfied the current request.
  const sankeyRequestKey = [timeRange, timeFrom, timeTo,
    activeActions.length === ACTIONS.length ? null : activeActions.join(','),
    activeDirections.length === DIRECTIONS.length ? null : activeDirections.join(','),
    dims.join(','), topN, expandedRow?.ip || '', refreshKey, excludeGroups, JSON.stringify(filterRules)].join('|')

  const refreshSavedViews = useCallback(() => {
    fetchSavedViews()
      .then(d => setSavedViews((d.views || []).filter(v => !['logs', 'exclusions'].includes(v.filters?.view_type))))
      .catch(err => console.error('Failed to fetch saved views:', err))
  }, [])

  // Fetch saved views on mount (initial population)
  useEffect(() => {
    refreshSavedViews()
  }, [refreshSavedViews])

  // Save view handler
  const handleSaveView = useCallback((name) => {
    const snapshot = {
      dims, topN, activeActions, activeDirections, filter_rules: filterRules,
      timeRange: (timeFrom || timeTo) ? null : timeRange,
      timeFrom: timeFrom || null,
      timeTo: timeTo || null,
    }
    return createSavedView(name, snapshot)
      .then(() => {
        skipBadgeClear.current = true
        setActiveViewName(name)
        setTimeout(() => { skipBadgeClear.current = false }, 0)
        refreshSavedViews()
      })
  }, [dims, topN, activeActions, activeDirections, timeRange, timeFrom, timeTo, filterRules, refreshSavedViews])

  // Load view handler
  const handleLoadView = useCallback((view) => {
    if (!view?.filters) return
    const f = normalizeFlowPreferences(view.filters)
    skipBadgeClear.current = true
    if (f.dims) setDims(f.dims)
    if (f.topN) setTopN(f.topN)
    if (f.activeActions) setActiveActions(f.activeActions)
    if (f.activeDirections) setActiveDirections(f.activeDirections)
    setFilterRules(readFilterRules(f.filter_rules))
    if (f.filter_rules.length) setAdvancedExpanded(true)
    setSankeyFilter(null)
    setZoneFilter(null)
    setExpandedRow(null)
    setHostSearchInput('')
    setHostHistory([])
    if (f.timeFrom || f.timeTo) {
      setTimeFrom(f.timeFrom || null)
      setTimeTo(f.timeTo || null)
    } else {
      setTimeFrom(null)
      setTimeTo(null)
      if (view.filters.timeRange) setTimeRange(view.filters.timeRange)
    }
    setActiveViewName(view.name)
    setTimeout(() => { skipBadgeClear.current = false }, 0)
  }, [setTimeRange])

  // Delete view handler
  const handleDeleteView = useCallback((id) => {
    deleteSavedView(id)
      .then(() => refreshSavedViews())
      .catch(err => console.error('Failed to delete view:', err))
  }, [refreshSavedViews])

  const toggleAction = (action) => {
    setActiveActions(prev => {
      const updated = prev.includes(action)
        ? prev.filter(a => a !== action)
        : [...prev, action]
      return updated.length === 0 ? [...ACTIONS] : updated
    })
  }

  const toggleDirection = (dir) => {
    setActiveDirections(prev => {
      const updated = prev.includes(dir)
        ? prev.filter(d => d !== dir)
        : [...prev, dir]
      return updated.length === 0 ? [...DIRECTIONS] : updated
    })
  }

  const isCustomTime = !!(timeFrom || timeTo)
  const filters = {
    exclude_groups: excludeGroups,
    filter_rules: filterRules.length ? JSON.stringify(filterRules) : null,
    time_range: isCustomTime ? null : timeRange,
    time_from: timeFrom,
    time_to: timeTo,
    rule_action: activeActions.length === ACTIONS.length ? null : activeActions.join(','),
    direction: activeDirections.length === DIRECTIONS.length ? null : activeDirections.join(','),
  }

  const refresh = useCallback(() => setRefreshKey(k => k + 1), [])
  const handleSankeyDataLoaded = useCallback((key) => setSankeyFulfilledKey(key), [])

  // Sankey node click — toggle filter, clear zone filter (mutual exclusivity)
  const handleSankeyNodeClick = useCallback(({ type, value }) => {
    if ((type === 'interface_in' || type === 'interface_out') && !value) return
    setSankeyFilter(prev => {
      if (prev && prev.type === type && prev.value === value) return null
      return { type, value }
    })
    setZoneFilter(null)
  }, [])

  // Zone cell click — toggle filter, clear sankey filter (mutual exclusivity)
  const handleZoneCellClick = useCallback(({ interface_in, interface_out, in_label, out_label }) => {
    setZoneFilter(prev => {
      if (prev && prev.interface_in === interface_in && prev.interface_out === interface_out) return null
      return { interface_in, interface_out, in_label, out_label }
    })
    setSankeyFilter(null)
  }, [])

  // IP click — toggle host detail expansion (from TopIPPairs row IPs)
  const handleIpClick = useCallback((ip, rowIndex) => {
    setExpandedRow(prev =>
      prev && prev.ip === ip && prev.rowIndex === rowIndex ? null : { ip, rowIndex }
    )
    setHostSearchInput(ip)
  }, [])

  // Sankey node click also expands host detail if IP type
  const handleSankeyNodeClickWithHost = useCallback(({ type, value }) => {
    handleSankeyNodeClick({ type, value })
    if (type === 'src_ip' || type === 'dst_ip') {
      setExpandedRow(prev => prev && prev.ip === value ? null : { ip: value, rowIndex: -1 })
      setHostSearchInput(value)
    }
  }, [handleSankeyNodeClick])

  const handleHostSearch = (e) => {
    if (e.key === 'Enter' && isFlowHostIp(hostSearchInput.trim())) {
      setExpandedRow({ ip: hostSearchInput.trim(), rowIndex: -1 })
    }
  }

  // Count active non-default filters for mobile badge
  const activeFilterCount = [
    activeActions.length !== ACTIONS.length,
    activeDirections.length !== DIRECTIONS.length,
    isCustomTime || timeRange !== '24h',
    hostSearchInput || expandedRow?.ip,
    filterRules.length,
    sankeyFilter,
    zoneFilter,
  ].filter(Boolean).length

  return (
    <div className="flex flex-col h-full overflow-hidden pt-2.5 px-4 pb-4 space-y-4">
      {excludeGroups && <p className="text-xs text-gray-400">Charts, host details and CSV exports exclude profile matches. Security is independent.</p>}
      {/* Filters (toggle + content wrapper to avoid space-y margin on desktop) */}
      <div>
        {/* Mobile filter toggle */}
        <button
          type="button"
          onClick={() => setFiltersExpanded(v => !v)}
          className="lg:hidden flex items-center gap-2 px-3 py-1.5 rounded text-xs font-medium border border-gray-600 text-gray-300 hover:bg-gray-700 transition-colors w-full justify-between"
          aria-expanded={filtersExpanded}
          aria-controls="flow-filters-panel"
        >
          <span>Filters{activeFilterCount > 0 ? ` (${activeFilterCount})` : ''}</span>
          <svg className={`w-3.5 h-3.5 transition-transform ${filtersExpanded ? 'rotate-180' : ''}`} viewBox="0 0 20 20" fill="currentColor" aria-hidden="true" focusable="false">
            <path fillRule="evenodd" d="M5.23 7.21a.75.75 0 011.06.02L10 11.168l3.71-3.938a.75.75 0 111.08 1.04l-4.25 4.5a.75.75 0 01-1.08 0l-4.25-4.5a.75.75 0 01.02-1.06z" clipRule="evenodd" />
          </svg>
        </button>

        {/* Filters — always visible on desktop, collapsible on mobile */}
        <div id="flow-filters-panel" className={`${filtersExpanded ? 'flex' : 'hidden'} lg:flex items-center gap-2 lg:gap-4 flex-wrap mt-4 lg:mt-0`}>
        {/* Action toggles */}
        <div className="flex items-center gap-1.5">
          {ACTIONS.map(action => (
            <button
              key={action}
              onClick={() => toggleAction(action)}
              className={`px-2 py-[3px] rounded text-xs font-medium uppercase border transition-all ${
                activeActions.includes(action)
                  ? ACTION_STYLES[action]
                  : 'border-transparent text-gray-500 hover:text-gray-400'
              }`}
            >
              {action}
            </button>
          ))}
        </div>

        <div className="hidden sm:block h-5 w-px bg-gray-700" />

        {/* Direction toggles */}
        <div className="flex items-center gap-1 flex-wrap">
          {DIRECTIONS.map(dir => (
            <button
              key={dir}
              onClick={() => toggleDirection(dir)}
              className={`px-2 py-1 rounded text-xs font-medium uppercase transition-all ${
                activeDirections.includes(dir)
                  ? 'bg-black text-white border border-gray-600'
                  : 'text-gray-500 hover:text-gray-400 border border-transparent'
              }`}
            >
              <span className={activeDirections.includes(dir) ? DIRECTION_COLORS[dir] : ''}>{DIRECTION_ICONS[dir]}</span> {dir === 'inter_vlan' ? 'vlan' : dir}
            </button>
          ))}
        </div>

        <div className="hidden sm:block h-5 w-px bg-gray-700" />

        {/* Time range */}
        <div className="flex items-center gap-1 flex-wrap">
          {visibleRanges.map(tr => (
            <button
              key={tr}
              onClick={() => { setTimeRange(tr); setTimeFrom(null); setTimeTo(null) }}
              className={`px-2 py-1 rounded text-xs font-medium transition-all ${
                !isCustomTime && timeRange === tr
                  ? 'bg-black text-white border border-gray-600'
                  : 'text-gray-400 hover:text-gray-300 border border-transparent'
              }`}
            >
              {tr}
            </button>
          ))}
          <DateRangePicker
            isActive={isCustomTime}
            timeFrom={timeFrom}
            timeTo={timeTo}
            maxFilterDays={maxFilterDays}
            onApply={({ time_from, time_to }) => {
              setTimeFrom(time_from)
              setTimeTo(time_to)
            }}
            onClear={() => {
              setTimeFrom(null)
              setTimeTo(null)
              setTimeRange('24h')
            }}
          />
        </div>

        {/* Saved view badge */}
        {activeViewName && (
          <button
            type="button"
            className="inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium
              bg-teal-500 text-white cursor-pointer"
            onClick={() => setActiveViewName(null)}
            title="Clear saved view label"
          >
            <svg className="shrink-0" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
            {activeViewName} &times;
          </button>
        )}

        {activeFilterCount > 0 && (
          <button
            type="button"
            onClick={() => {
              setTimeRange('24h')
              setTimeFrom(null)
              setTimeTo(null)
              setActiveActions([...ACTIONS])
              setActiveDirections([...DIRECTIONS])
              setSankeyFilter(null)
              setZoneFilter(null)
              setExpandedRow(null)
              setHostSearchInput('')
              setHostHistory([])
              setActiveViewName(null)
              setFilterRules([])
            }}
            className="shrink-0 text-xs text-gray-400 hover:text-gray-200 transition-colors"
          >
            Reset
          </button>
        )}

        <button
          type="button"
          onClick={refresh}
          className="ml-auto shrink-0 px-2.5 py-1 rounded text-xs font-medium text-gray-400 hover:text-gray-200 transition-colors"
          title="Refresh data"
        >
          ↻ Refresh
        </button>
        </div>
      </div>

      <details className="shrink-0 max-h-[45vh] overflow-y-auto" open={advancedExpanded}
        onToggle={event => setAdvancedExpanded(event.currentTarget.open)}>
        <summary className="cursor-pointer text-xs text-gray-300">Include / exclude hosts and traffic{filterRules.length ? ` (${filterRules.length})` : ''}</summary>
        <div className="mt-2">
          <FieldFilters filters={{ filter_rules: filters.filter_rules }} savedViews={false}
            onChange={next => setFilterRules(readFilterRules(next.filter_rules))} />
          <p className="text-xs text-gray-500 mt-2">Use Either IP / subnet for reliable host exclusion on both sides. Device-name filters search recorded labels, which can be stale or absent. Conditions apply to every chart, host detail and export, and are saved with the flow view. The selected exclusion profile remains separate.</p>
        </div>
      </details>

      {/* Sub-tabs */}
      <div className="flex items-center gap-1">
        {SUB_TABS.map(tab => (
          <button
            key={tab.key}
            onClick={() => setActivePanel(tab.key)}
            className={`px-3 py-1.5 rounded text-xs font-medium transition-all ${
              activePanel === tab.key
                ? 'bg-black text-white border border-gray-600'
                : 'text-gray-500 hover:text-gray-300 border border-transparent'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Main content — side by side: chart 65%, IP pairs 35% */}
      <div className="flex flex-col sm:flex-row gap-4 min-h-0 flex-1">
        {/* Left: active panel (60%) */}
        <div className="w-full flex-1 min-h-0 sm:flex-[3_1_0%] sm:h-auto min-w-0 overflow-hidden">
          {activePanel === 'sankey' && (
            <SankeyChart
              filters={filters}
              refreshKey={refreshKey}
              onNodeClick={handleSankeyNodeClickWithHost}
              activeFilter={sankeyFilter}
              hostIp={expandedRow?.ip}
              hostSearchInput={hostSearchInput}
              onHostSearchChange={setHostSearchInput}
              onHostSearch={handleHostSearch}
              onHostSearchClear={() => { setExpandedRow(null); setHostSearchInput('') }}
              dims={dims}
              setDims={setDims}
              topN={topN}
              setTopN={setTopN}
              onSaveView={handleSaveView}
              onLoadView={handleLoadView}
              savedViews={savedViews}
              onDeleteView={handleDeleteView}
              onRefreshViews={refreshSavedViews}
              onDataLoaded={handleSankeyDataLoaded}
              requestKey={sankeyRequestKey}
            />
          )}
          {activePanel === 'zone-matrix' && (
            <Suspense fallback={<div className="border border-gray-800 rounded-lg p-4 h-64 animate-pulse"><div className="h-4 w-32 bg-gray-800 rounded mb-3" /><div className="grid grid-cols-4 gap-2">{[...Array(12)].map((_, i) => <div key={i} className="h-8 bg-gray-800 rounded" />)}</div></div>}>
              <ZoneMatrix
                filters={filters}
                refreshKey={refreshKey}
                onCellClick={handleZoneCellClick}
                activeCell={zoneFilter}
              />
            </Suspense>
          )}
        </div>

        {/* Right: Top IP Pairs (40%) + slide-out host panel */}
        <div className="w-full flex-1 min-h-0 sm:flex-[2_1_0%] sm:h-auto min-w-0 overflow-hidden flex flex-col relative">
          <TopIPPairs
            filters={filters}
            refreshKey={refreshKey}
            sankeyFilter={sankeyFilter}
            onClearSankeyFilter={() => setSankeyFilter(null)}
            zoneFilter={zoneFilter}
            onClearZoneFilter={() => setZoneFilter(null)}
            onIpClick={handleIpClick}
            onSaveView={handleSaveView}
            onLoadView={handleLoadView}
            savedViews={savedViews}
            onDeleteView={handleDeleteView}
            onRefreshViews={refreshSavedViews}
            deferFetch={activePanel === 'sankey' && sankeyRequestKey !== sankeyFulfilledKey}
          />
          {expandedRow && (
            <HostSlidePanel
              ip={expandedRow.ip}
              refreshKey={refreshKey}
              filters={filters}
              onClose={() => { setExpandedRow(null); setHostSearchInput(''); setHostHistory([]) }}
              onPeerClick={(ip) => {
                setHostHistory(prev => { const next = [...prev, expandedRow.ip]; return next.length > 50 ? next.slice(next.length - 50) : next })
                setExpandedRow({ ip, rowIndex: -1 })
                setHostSearchInput(ip)
              }}
              canGoBack={hostHistory.length > 0}
              onBack={() => {
                const prev = hostHistory[hostHistory.length - 1]
                setHostHistory(h => h.slice(0, -1))
                setExpandedRow({ ip: prev, rowIndex: -1 })
                setHostSearchInput(prev)
              }}
            />
          )}
        </div>
      </div>
    </div>
  )
}
