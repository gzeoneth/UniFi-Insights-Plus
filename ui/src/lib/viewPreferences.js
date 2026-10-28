// Validators for browser-only view preferences. Query results and live actions
// stay in component state; these records contain only user selections.
export const isRecord = value => value !== null && typeof value === 'object' && !Array.isArray(value)
export const isBoolean = value => typeof value === 'boolean'
export const isShortText = value => typeof value === 'string' && value.length <= 1024
export const isOptionalDate = value => value === null || (typeof value === 'string' && value.length <= 64 && Number.isFinite(Date.parse(value)))

export function isDateWindow(value) {
  return isRecord(value) && Object.keys(value).every(key => ['from', 'to'].includes(key)) &&
    isOptionalDate(value.from) && isOptionalDate(value.to) &&
    (!value.from || !value.to || Date.parse(value.from) <= Date.parse(value.to))
}

export function isBooleanRecord(value, keys) {
  return isRecord(value) && Object.keys(value).length === keys.length &&
    keys.every(key => isBoolean(value[key]))
}

export function isMapCamera(value) {
  return isRecord(value) && Object.keys(value).every(key => ['center', 'zoom', 'bearing', 'pitch'].includes(key)) && Array.isArray(value.center) && value.center.length === 2 &&
    value.center.every(Number.isFinite) && Math.abs(value.center[0]) <= 180 && Math.abs(value.center[1]) <= 90 &&
    Number.isFinite(value.zoom) && value.zoom >= 0 && value.zoom <= 24 &&
    Number.isFinite(value.bearing) && Math.abs(value.bearing) <= 360 &&
    Number.isFinite(value.pitch) && value.pitch >= 0 && value.pitch <= 85
}
