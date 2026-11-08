import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest'
import { act, renderHook } from '@testing-library/react'
import { readPreference, writePreference } from '../lib/preferences'
import usePreference from '../hooks/usePreference'

beforeEach(() => { localStorage.clear(); sessionStorage.clear() })
afterEach(() => { vi.restoreAllMocks() })
const key = 'test:preference'
const valid = value => typeof value === 'boolean'

describe('browser preferences', () => {
  it('restores false instead of replacing it with a truthy default', () => {
    writePreference(key, false)
    expect(readPreference(key, true, valid)).toBe(false)
  })

  it('migrates valid session preferences once and prefers later local choices', () => {
    sessionStorage.setItem(key, JSON.stringify({ order: 'asc' }))
    const isOrder = v => v && ['asc', 'desc'].includes(v.order)
    expect(readPreference(key, null, isOrder)).toEqual({ order: 'asc' })
    expect(sessionStorage.getItem(key)).toBeNull()
    writePreference(key, { order: 'desc' })
    sessionStorage.setItem(key, JSON.stringify({ order: 'asc' }))
    expect(readPreference(key, null, isOrder)).toEqual({ order: 'desc' })
  })

  it.each([['broken JSON', '{broken'], ['null', 'null'], ['array', '[false]'], ['wrong type', '"yes"'], ['oversized', 'x'.repeat(65537)]])('rejects malformed or wrong-shape data: %s', (_label, raw) => {
    localStorage.setItem(key, raw)
    expect(readPreference(key, true, valid)).toBe(true)
  })

  it('keeps in-memory controls working when storage is blocked or full', () => {
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => { throw new Error('blocked') })
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => { throw new Error('full') })
    const { result } = renderHook(() => usePreference(key, true, valid))
    expect(result.current[0]).toBe(true)
    act(() => result.current[1](false))
    expect(result.current[0]).toBe(false)
  })

  it('does not delete a legacy selection if its durable write fails', () => {
    sessionStorage.setItem(key, 'false')
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => { throw new Error('full') })
    expect(readPreference(key, true, valid)).toBe(false)
    expect(sessionStorage.getItem(key)).toBe('false')
  })
})
