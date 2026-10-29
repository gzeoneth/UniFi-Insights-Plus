import { act, cleanup, fireEvent, renderHook } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import useDashboardTier from '../../hooks/useDashboardTier'
import { CACHE_TTL_MS, writeCache } from '../../lib/sessionCache'

const flush = async () => { await act(async () => { await Promise.resolve() }) }
const advance = async ms => { await act(async () => { await vi.advanceTimersByTimeAsync(ms) }) }
const visible = value => {
  Object.defineProperty(document, 'visibilityState', { configurable: true, value })
  fireEvent(document, new Event('visibilitychange'))
}
beforeEach(() => { vi.useFakeTimers(); sessionStorage.clear(); visible('visible') })
afterEach(() => { cleanup(); vi.useRealTimers() })

describe('dashboard tier scheduling', () => {
  it('reuses fresh cache then refreshes without overlapping a slow query', async () => {
    writeCache('dashboard', 'overview:1h:', { total: 5 })
    let finish
    const fetcher = vi.fn(() => new Promise(resolve => { finish = resolve }))
    const { result } = renderHook(() => useDashboardTier('overview', '1h', null, fetcher))
    await flush()
    expect(result.current.data.total).toBe(5)
    expect(fetcher).not.toHaveBeenCalled()
    await advance(CACHE_TTL_MS + 1)
    expect(fetcher).toHaveBeenCalledTimes(1)
    await advance(CACHE_TTL_MS * 2)
    expect(fetcher).toHaveBeenCalledTimes(1)
    await act(async () => finish({ total: 10 }))
    expect(result.current.data.total).toBe(10)
  })

  it('coalesces filter changes and keeps cached scopes separate', async () => {
    let finish
    const fetcher = vi.fn().mockImplementationOnce(() => new Promise(resolve => { finish = resolve }))
      .mockResolvedValue({ total: 7 })
    const { result, rerender } = renderHook(({ range }) => useDashboardTier('tables', range, null, fetcher),
      { initialProps: { range: '24h' } })
    rerender({ range: '7d' }); rerender({ range: '1h' })
    expect(fetcher).toHaveBeenCalledTimes(1)
    expect(result.current.data).toBeNull()
    await act(async () => finish({ total: 99 }))
    expect(fetcher).toHaveBeenCalledTimes(2)
    expect(fetcher.mock.lastCall[0]).toBe('1h')
    expect(result.current.data.total).toBe(7)
  })

  it('does not request hidden tabs and reports a failed refresh as stale', async () => {
    visible('hidden')
    const fetcher = vi.fn().mockResolvedValueOnce({ total: 7 }).mockRejectedValue(new Error('unavailable'))
    const { result } = renderHook(() => useDashboardTier('charts', '24h', null, fetcher))
    await advance(CACHE_TTL_MS * 2)
    expect(fetcher).not.toHaveBeenCalled()
    visible('visible'); await flush()
    expect(result.current.status).toBe('loaded')
    await advance(CACHE_TTL_MS + 1)
    expect(result.current.status).toBe('stale')
    expect(result.current.data.total).toBe(7)
  })
})
