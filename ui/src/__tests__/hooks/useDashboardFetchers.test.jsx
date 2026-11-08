import { StrictMode } from 'react'
import { act, cleanup, fireEvent, renderHook } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fetchStatsOverview, fetchStatsCharts, fetchStatsTables } from '../../api'
import useDashboardFetchers from '../../hooks/useDashboardFetchers'
import useDashboardTier from '../../hooks/useDashboardTier'
import { CACHE_TTL_MS, writeCache } from '../../lib/sessionCache'

vi.mock('../../api', () => ({
  fetchStatsOverview: vi.fn(), fetchStatsCharts: vi.fn(), fetchStatsTables: vi.fn(),
}))

const flush = async () => { await act(async () => { await Promise.resolve() }) }
const advance = async ms => { await act(async () => { await vi.advanceTimersByTimeAsync(ms) }) }
const visible = value => {
  Object.defineProperty(document, 'visibilityState', { configurable: true, value })
  fireEvent(document, new Event('visibilitychange'))
}
function useDashboard({ range = '24h', profile = null } = {}) {
  const fetchers = useDashboardFetchers()
  const overview = useDashboardTier('overview', range, profile, fetchers.overview)
  const charts = useDashboardTier('charts', range, profile, fetchers.charts, { ready: !overview.loading })
  const tables = useDashboardTier('tables', range, profile, fetchers.tables,
    { ready: !overview.loading && !charts.loading })
  return { overview, charts, tables }
}

let calls, active, peak
beforeEach(() => {
  vi.useFakeTimers(); vi.clearAllMocks(); sessionStorage.clear(); visible('visible')
  calls = []; active = 0; peak = 0
  for (const [name, fetcher] of [
    ['overview', fetchStatsOverview], ['charts', fetchStatsCharts], ['tables', fetchStatsTables],
  ]) {
    // Deliberately ignore AbortSignal to exercise real physical-slot ownership.
    fetcher.mockImplementation((range, params, options) => new Promise((resolve, reject) => {
      active++; peak = Math.max(peak, active)
      const finish = (value = { [name]: calls.length }, error = false) => {
        active--
        if (error) reject(value)
        else resolve(value)
      }
      calls.push({ name, range, params, options, finish })
    }))
  }
})
afterEach(() => { cleanup(); vi.useRealTimers() })
const finish = async (index, value, error) => { await act(async () => { calls[index].finish(value, error) }) }
const finishInitial = async () => {
  await flush()
  for (let i = 0; i < 3; i++) await finish(i)
}

describe('dashboard shared fetch scheduling', () => {
  it('serializes initial and simultaneous background tier requests while retaining loaded data', async () => {
    const { result } = renderHook(() => useDashboard())
    await flush()
    expect(calls.map(c => c.name)).toEqual(['overview'])
    await finishInitial()
    expect(calls.map(c => c.name)).toEqual(['overview', 'charts', 'tables'])
    await advance(CACHE_TTL_MS + 1)
    expect(calls.map(c => c.name)).toEqual(['overview', 'charts', 'tables', 'overview'])
    expect(Object.values(result.current).every(tier => !tier.loading && tier.status === 'loaded')).toBe(true)
    await finish(3)
    expect(calls[4].name).toBe('charts')
    await finish(4)
    expect(calls[5].name).toBe('tables')
    await finish(5)
    expect(peak).toBe(1)
    expect(calls.every(call => call.options.signal instanceof AbortSignal)).toBe(true)
  })

  it('starts remaining sections after an overview failure', async () => {
    const { result } = renderHook(() => useDashboard())
    await flush()
    await finish(0, new Error('unavailable'), true)
    expect(result.current.overview.status).toBe('error')
    expect(calls[1].name).toBe('charts')
    await finish(1)
    expect(calls[2].name).toBe('tables')
    await finish(2)
    expect(result.current.tables.status).toBe('loaded')
    expect(peak).toBe(1)
  })

  it('removes queued old filters and starts only the latest scope after an active obsolete fetch', async () => {
    const { result, rerender } = renderHook(props => useDashboard(props),
      { initialProps: { range: '24h', profile: null } })
    await finishInitial()
    await advance(CACHE_TTL_MS + 1)
    expect(calls).toHaveLength(4)
    rerender({ range: '7d', profile: 'first-profile' })
    rerender({ range: '1h', profile: 'latest-profile' })
    await flush()
    expect(calls[3].options.signal.aborted).toBe(true)
    expect(calls).toHaveLength(4)
    expect(result.current.overview.data).toBeNull()
    await finish(3, { overview: 'obsolete' })
    expect(calls[4]).toMatchObject({ name: 'overview', range: '1h', params: { exclude_groups: 'latest-profile' } })
    await finish(4)
    await finish(5)
    await finish(6)
    expect(calls.slice(4).map(c => [c.name, c.range])).toEqual([
      ['overview', '1h'], ['charts', '1h'], ['tables', '1h'],
    ])
    expect(result.current.overview.data).not.toEqual({ overview: 'obsolete' })
    expect(peak).toBe(1)
  })

  it('cancels waiting jobs while hidden and on unmount, without starting hidden work', async () => {
    const { unmount } = renderHook(() => useDashboard())
    await finishInitial()
    await advance(CACHE_TTL_MS + 1)
    visible('hidden'); await flush()
    expect(calls[3].options.signal.aborted).toBe(true)
    await finish(3)
    await advance(CACHE_TTL_MS * 2)
    expect(calls).toHaveLength(4)
    visible('visible'); await flush()
    expect(calls[4].name).toBe('overview')
    unmount()
    expect(calls[4].options.signal.aborted).toBe(true)
    await finish(4)
    await advance(CACHE_TTL_MS * 2)
    expect(calls).toHaveLength(5)
    expect(peak).toBe(1)
  })

  it('survives StrictMode effect replay and bypasses the queue for fresh cache hits', async () => {
    writeCache('dashboard', 'overview:24h:', { total: 5 })
    const { result } = renderHook(() => useDashboard(),
      { wrapper: ({ children }) => <StrictMode>{children}</StrictMode> })
    await flush()
    expect(calls.map(c => c.name)).toEqual(['charts'])
    expect(result.current.overview.data.total).toBe(5)
    await finish(0)
    await finish(1)
    expect(calls.map(c => c.name)).toEqual(['charts', 'tables'])
    expect(peak).toBe(1)
  })
})
