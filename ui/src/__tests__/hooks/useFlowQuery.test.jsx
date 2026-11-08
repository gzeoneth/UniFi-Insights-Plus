import { act, cleanup, fireEvent, renderHook } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import useFlowQuery, { FLOW_CACHE_MS } from '../../hooks/useFlowQuery'

const flush = async () => { await act(async () => { await Promise.resolve() }) }
const visible = value => {
  Object.defineProperty(document, 'visibilityState', { configurable: true, value })
  fireEvent(document, new Event('visibilitychange'))
}
const filters = value => ({ time_range: '1h', filter_rules: JSON.stringify([
  { field: 'ip', operator: 'exclude', value },
]) })
beforeEach(() => { vi.useFakeTimers(); sessionStorage.clear(); visible('visible') })
afterEach(() => { cleanup(); vi.useRealTimers() })

describe('Flow request scheduling and cache', () => {
  it('coalesces pending filter changes without concurrent requests or stale results', async () => {
    let finish
    const fetcher = vi.fn().mockImplementationOnce(() => new Promise(resolve => { finish = resolve }))
      .mockResolvedValue({ pairs: ['latest'] })
    const { result, rerender } = renderHook(({ params }) => useFlowQuery('flow-test', params, fetcher),
      { initialProps: { params: filters('192.0.2.10') } })
    rerender({ params: filters('192.0.2.11') })
    rerender({ params: filters('198.51.100.0/24') })
    expect(fetcher).toHaveBeenCalledTimes(1)
    expect(result.current.data).toBeNull()
    await act(async () => finish({ pairs: ['old'] }))
    expect(fetcher).toHaveBeenCalledTimes(2)
    expect(fetcher.mock.lastCall[0]).toEqual(filters('198.51.100.0/24'))
    expect(fetcher.mock.lastCall[1].signal).toBeInstanceOf(AbortSignal)
    expect(result.current.data).toEqual({ pairs: ['latest'] })
  })

  it('waits for both panel readiness and tab visibility, without periodic queries', async () => {
    visible('hidden')
    const fetcher = vi.fn().mockResolvedValue({ pairs: [] })
    const { rerender } = renderHook(({ ready }) => useFlowQuery('flow-test', {}, fetcher, 0, ready),
      { initialProps: { ready: false } })
    visible('visible'); await flush()
    expect(fetcher).not.toHaveBeenCalled()
    visible('hidden')
    rerender({ ready: true }); await flush()
    expect(fetcher).not.toHaveBeenCalled()
    visible('visible'); await flush()
    expect(fetcher).toHaveBeenCalledOnce()
    await act(async () => vi.advanceTimersByTimeAsync(FLOW_CACHE_MS * 10))
    expect(fetcher).toHaveBeenCalledOnce()
  })

  it('keys cache by all filters, expires after 30 seconds and bypasses on manual refresh', async () => {
    const fetcher = vi.fn().mockResolvedValue({ pairs: [] })
    const props = { params: filters('192.0.2.10'), refreshKey: 0 }
    const view = renderHook(({ params, refreshKey }) => useFlowQuery('flow-test', params, fetcher, refreshKey),
      { initialProps: props })
    await flush()
    view.rerender({ ...props, params: filters('192.0.2.11') }); await flush()
    expect(fetcher).toHaveBeenCalledTimes(2)
    view.rerender(props); await flush()
    expect(fetcher).toHaveBeenCalledTimes(2)
    view.rerender({ ...props, refreshKey: 1 }); await flush()
    expect(fetcher).toHaveBeenCalledTimes(3)
    view.unmount()
    renderHook(() => useFlowQuery('flow-test', props.params, fetcher)); await flush()
    expect(fetcher).toHaveBeenCalledTimes(3)
    cleanup()
    await act(async () => vi.advanceTimersByTimeAsync(FLOW_CACHE_MS + 1))
    renderHook(() => useFlowQuery('flow-test', props.params, fetcher)); await flush()
    expect(fetcher).toHaveBeenCalledTimes(4)
  })

  it('invalidates an in-flight result when deferred and resumes with the current filter', async () => {
    let finish
    const fetcher = vi.fn().mockImplementationOnce(() => new Promise(resolve => { finish = resolve }))
      .mockResolvedValue({ count: 7 })
    const view = renderHook(({ ready, params }) => useFlowQuery('flow-test', params, fetcher, 0, ready),
      { initialProps: { ready: true, params: filters('192.0.2.10') } })
    view.rerender({ ready: false, params: filters('192.0.2.11') })
    await act(async () => finish({ count: 99 }))
    expect(fetcher).toHaveBeenCalledOnce()
    expect(view.result.current.data).toBeNull()
    view.rerender({ ready: true, params: filters('192.0.2.11') }); await flush()
    expect(fetcher).toHaveBeenCalledTimes(2)
    expect(view.result.current.data).toEqual({ count: 7 })
  })

  it('reports failed queries as errors instead of caching an empty success', async () => {
    const fetcher = vi.fn().mockRejectedValueOnce(new Error('Query timed out')).mockResolvedValue({ count: 3 })
    const view = renderHook(({ refreshKey }) => useFlowQuery('flow-test', {}, fetcher, refreshKey),
      { initialProps: { refreshKey: 0 } })
    await flush()
    expect(view.result.current.error.message).toBe('Query timed out')
    expect(view.result.current.data).toBeNull()
    view.rerender({ refreshKey: 1 }); await flush()
    expect(view.result.current.error).toBeNull()
    expect(view.result.current.data).toEqual({ count: 3 })
  })
})
