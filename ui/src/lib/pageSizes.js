export const LOG_PAGE_SIZES = [50, 100, 200, 500, 1000]
export const LOG_PAGE_SIZE_KEY = 'unifi-log-insight:rows-per-page'

export function logPageSize(value) {
  const size = Number(value)
  return LOG_PAGE_SIZES.includes(size) ? size : 50
}
