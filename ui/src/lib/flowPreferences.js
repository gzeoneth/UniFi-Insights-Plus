import { readFilterRules } from './fieldFilterRules'
import { TIME_RANGES } from './preferences'

export const FLOW_PREFERENCE_KEY = 'flowview_filters'
export const FLOW_PAIR_LIMIT_KEY = 'unifi-log-insight:flow-pair-limit'
export const FLOW_ACTIONS = ['allow', 'block']
export const FLOW_DIRECTIONS = ['inbound', 'outbound', 'inter_vlan', 'nat', 'local', 'vpn']
export const FLOW_DIMENSIONS = ['src_ip', 'dst_ip', 'dst_port', 'protocol', 'service_name', 'direction', 'interface_in', 'interface_out']
const DEFAULT_DIMENSIONS = ['src_ip', 'dst_port', 'dst_ip']

const isRecord = value => value && typeof value === 'object' && !Array.isArray(value)
const boundedText = (value, max = 1024) => typeof value === 'string' && value.length <= max
const timestamp = value => boundedText(value, 64) && value.includes('T') && Number.isFinite(Date.parse(value)) ? value : null
const selection = (value, options) => Array.isArray(value) && value.length > 0 && value.length <= options.length && value.every(item => options.includes(item))
  ? [...new Set(value)] : [...options]

export function isFlowHostIp(value) {
  if (!boundedText(value, 45) || !value) return false
  if (!value.includes(':')) {
    const parts = value.split('.')
    return parts.length === 4 && parts.every(part => /^\d{1,3}$/.test(part) && Number(part) <= 255 && String(Number(part)) === part)
  }
  if (!/^[0-9a-f:.]+$/i.test(value)) return false
  try { return !!new URL(`http://[${value}]/`).hostname } catch { return false }
}

function sankeySelection(value) {
  if (!isRecord(value) || !FLOW_DIMENSIONS.includes(value.type) || !boundedText(value.value, 256) || !value.value || value.value === 'Other') return null
  if (['src_ip', 'dst_ip'].includes(value.type) && !isFlowHostIp(value.value)) return null
  if (value.type === 'direction' && !FLOW_DIRECTIONS.includes(value.value)) return null
  if (value.type === 'dst_port' && (!/^\d{1,5}$/.test(value.value) || Number(value.value) > 65535)) return null
  return { type: value.type, value: value.value }
}

function zoneSelection(value) {
  if (!isRecord(value) || !['interface_in', 'interface_out'].every(key => boundedText(value[key], 256) && value[key])) return null
  return {
    interface_in: value.interface_in, interface_out: value.interface_out,
    in_label: boundedText(value.in_label, 256) ? value.in_label : '',
    out_label: boundedText(value.out_label, 256) ? value.out_label : '',
  }
}

// Persist query controls only. Cached rows, row indices and navigation history
// are tied to an old result set and must be rebuilt after reload.
export function normalizeFlowPreferences(value) {
  const saved = isRecord(value) ? value : {}
  let timeFrom = timestamp(saved.timeFrom)
  let timeTo = timestamp(saved.timeTo)
  if (timeFrom && timeTo && Date.parse(timeFrom) > Date.parse(timeTo)) { timeFrom = null; timeTo = null }
  const zoneFilter = zoneSelection(saved.zoneFilter)
  return {
    activeActions: selection(saved.activeActions, FLOW_ACTIONS),
    activeDirections: selection(saved.activeDirections, FLOW_DIRECTIONS),
    dims: Array.isArray(saved.dims) && saved.dims.length === 3 && new Set(saved.dims).size === 3 && saved.dims.every(dim => FLOW_DIMENSIONS.includes(dim))
      ? saved.dims : [...DEFAULT_DIMENSIONS],
    topN: Number.isInteger(saved.topN) && saved.topN >= 3 && saved.topN <= 50 ? saved.topN : 15,
    activeViewName: boundedText(saved.activeViewName, 100) && saved.activeViewName ? saved.activeViewName : null,
    filter_rules: readFilterRules(saved.filter_rules),
    activePanel: saved.activePanel === 'zone-matrix' ? 'zone-matrix' : 'sankey',
    filtersExpanded: saved.filtersExpanded === true,
    advancedExpanded: typeof saved.advancedExpanded === 'boolean' ? saved.advancedExpanded : readFilterRules(saved.filter_rules).length > 0,
    sankeyFilter: zoneFilter ? null : sankeySelection(saved.sankeyFilter),
    zoneFilter,
    hostIp: isFlowHostIp(saved.hostIp) ? saved.hostIp : null,
    hostSearchInput: boundedText(saved.hostSearchInput, 64) ? saved.hostSearchInput : '',
    timeRange: TIME_RANGES.includes(saved.timeRange) ? saved.timeRange : null,
    timeFrom, timeTo,
  }
}
