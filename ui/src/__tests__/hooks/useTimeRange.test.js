import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderHook, act } from '@testing-library/react'
import useTimeRange from '../../hooks/useTimeRange'
import { TR_KEY } from '../../utils'


beforeEach(() => {
  sessionStorage.clear()
  localStorage.clear()
})


describe('useTimeRange', () => {
  it('defaults to 24h when preferences are empty', () => {
    const { result } = renderHook(() => useTimeRange())
    const [timeRange] = result.current
    expect(timeRange).toBe('24h')
  })

  it('migrates the previous session selection to localStorage', () => {
    sessionStorage.setItem(TR_KEY, '7d')
    const { result } = renderHook(() => useTimeRange())
    expect(result.current[0]).toBe('7d')
    expect(JSON.parse(localStorage.getItem(TR_KEY))).toBe('7d')
    expect(sessionStorage.getItem(TR_KEY)).toBeNull()
  })

  it('retains a changed range after a new browser session', () => {
    const { result } = renderHook(() => useTimeRange())
    act(() => {
      result.current[1]('30d')
    })
    expect(result.current[0]).toBe('30d')
    expect(localStorage.getItem(TR_KEY)).toBe('30d')
    sessionStorage.clear()
    const next = renderHook(() => useTimeRange())
    expect(next.result.current[0]).toBe('30d')
  })

  it('ignores invalid ranges and prefers local over stale session settings', () => {
    localStorage.setItem(TR_KEY, '6h')
    sessionStorage.setItem(TR_KEY, '365d')
    const { result } = renderHook(() => useTimeRange())
    expect(result.current[0]).toBe('6h')
    act(() => result.current[1]('invalid'))
    expect(result.current[0]).toBe('6h')
  })

  it('falls back when stored data is corrupt', () => {
    localStorage.setItem(TR_KEY, '{broken')
    const { result } = renderHook(() => useTimeRange())
    expect(result.current[0]).toBe('24h')
  })

  it('returns visible ranges filtered by maxFilterDays', () => {
    const { result } = renderHook(() => useTimeRange(7))
    const visibleRanges = result.current[2]
    // Should include sub-day ranges + up to 7d + one ceiling
    expect(visibleRanges).toContain('1h')
    expect(visibleRanges).toContain('7d')
    // 60d and above should be excluded (30d is ceiling, 60d/90d/etc not)
    expect(visibleRanges).not.toContain('60d')
    expect(visibleRanges).not.toContain('90d')
  })

  it('returns all ranges when no maxFilterDays', () => {
    const { result } = renderHook(() => useTimeRange())
    expect(result.current[2]).toContain('365d')
  })
})
