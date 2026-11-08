// One queue belongs to one mounted dashboard, rather than the whole browser.
// An aborted caller settles promptly, but an active operation keeps its slot
// until it settles so an abort-ignoring fetch cannot overlap the next request.
export function createRequestQueue() {
  const pending = []
  let active = false
  const aborted = () => new DOMException('Request cancelled', 'AbortError')

  const pump = () => {
    if (active) return
    const job = pending.shift()
    if (!job) return
    active = true
    job.started = true
    Promise.resolve().then(() => {
      if (job.signal?.aborted) throw aborted()
      return job.operation()
    }).then(job.resolve, job.reject).finally(() => {
      active = false
      pump()
    })
  }

  return (operation, signal) => {
    if (signal?.aborted) return Promise.reject(aborted())
    return new Promise((resolve, reject) => {
      const job = { operation, signal, started: false }
      const settle = callback => value => {
        signal?.removeEventListener('abort', onAbort)
        callback(value)
      }
      const onAbort = () => {
        if (!job.started) {
          const position = pending.indexOf(job)
          if (position !== -1) pending.splice(position, 1)
        }
        job.reject(aborted())
      }
      job.resolve = settle(resolve)
      job.reject = settle(reject)
      signal?.addEventListener('abort', onAbort, { once: true })
      pending.push(job)
      pump()
    })
  }
}
