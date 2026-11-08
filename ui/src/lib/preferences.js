import { TR_KEY } from '../utils'

export const TIME_RANGES = ['1h', '6h', '24h', '7d', '30d', '60d', '90d', '180d', '365d']
const MAX_BYTES = 65536

// Preferences contain user choices only. Response caches stay in sessionStorage.
export function readPreference(key, fallback, validate = () => true) {
  try {
    let raw = localStorage.getItem(key)
    const migrate = raw === null
    if (migrate) raw = sessionStorage.getItem(key)
    if (raw === null || raw.length > MAX_BYTES) return fallback
    let value
    try { value = JSON.parse(raw) } catch { value = raw }
    if (!validate(value)) return fallback
    if (migrate && writePreference(key, value)) {
      try { sessionStorage.removeItem(key) } catch { /* storage can be unavailable */ }
    }
    return value
  } catch { return fallback }
}

export function writePreference(key, value) {
  try {
    const raw = JSON.stringify(value)
    if (raw === undefined || raw.length > MAX_BYTES) return false
    localStorage.setItem(key, raw)
    return true
  } catch { return false }
}

// Preserve the legacy string encoding used by theme and the shared time range.
export function writeTextPreference(key, value) {
  try {
    if (typeof value !== 'string' || value.length > MAX_BYTES) return false
    localStorage.setItem(key, value)
    return true
  } catch { return false }
}

export function readTimeRange() {
  return readPreference(TR_KEY, '24h', value => TIME_RANGES.includes(value))
}

export function writeTimeRange(value) {
  if (!TIME_RANGES.includes(value)) return false
  return writeTextPreference(TR_KEY, value)
}
