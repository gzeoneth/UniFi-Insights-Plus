import { describe, expect, it, vi } from 'vitest'
import { createRequestQueue } from '../lib/requestQueue'

const deferred = () => {
  let resolve, reject
  const promise = new Promise((yes, no) => { resolve = yes; reject = no })
  return { promise, resolve, reject }
}
const flush = async () => { for (let i = 0; i < 8; i++) await Promise.resolve() }

describe('per-dashboard request queue', () => {
  it('runs FIFO with one operation active and drains after failures', async () => {
    const enqueue = createRequestQueue(), first = deferred(), calls = []
    const a = enqueue(() => { calls.push('first'); return first.promise })
    const b = enqueue(() => { calls.push('second'); throw new Error('unavailable') })
    const rejected = expect(b).rejects.toThrow('unavailable')
    const c = enqueue(() => { calls.push('third'); return 3 })
    await flush()
    expect(calls).toEqual(['first'])
    first.resolve(1)
    await expect(a).resolves.toBe(1)
    await rejected
    await expect(c).resolves.toBe(3)
    expect(calls).toEqual(['first', 'second', 'third'])
  })

  it('rejects an aborted waiting job promptly without invoking it', async () => {
    const enqueue = createRequestQueue(), first = deferred()
    const controller = new AbortController(), skipped = vi.fn()
    const a = enqueue(() => first.promise)
    const b = enqueue(skipped, controller.signal)
    const rejected = expect(b).rejects.toMatchObject({ name: 'AbortError' })
    controller.abort()
    await rejected
    expect(skipped).not.toHaveBeenCalled()
    first.resolve(1)
    await a
    await flush()
    expect(skipped).not.toHaveBeenCalled()
  })

  it('settles active cancellation but holds the slot until its fetch really settles', async () => {
    const enqueue = createRequestQueue(), first = deferred()
    const controller = new AbortController(), next = vi.fn().mockResolvedValue(2)
    const a = enqueue(() => first.promise, controller.signal)
    const rejected = expect(a).rejects.toMatchObject({ name: 'AbortError' })
    const b = enqueue(next)
    await flush()
    controller.abort()
    await rejected
    await flush()
    expect(next).not.toHaveBeenCalled()
    first.resolve(1)
    await expect(b).resolves.toBe(2)
    expect(next).toHaveBeenCalledOnce()
  })

  it('does not enqueue an already aborted job and removes settled listeners', async () => {
    const enqueue = createRequestQueue(), controller = new AbortController()
    const remove = vi.spyOn(controller.signal, 'removeEventListener')
    await expect(enqueue(() => 1, controller.signal)).resolves.toBe(1)
    expect(remove).toHaveBeenCalledWith('abort', expect.any(Function))
    controller.abort()
    const skipped = vi.fn()
    await expect(enqueue(skipped, controller.signal)).rejects.toMatchObject({ name: 'AbortError' })
    expect(skipped).not.toHaveBeenCalled()
  })
})
