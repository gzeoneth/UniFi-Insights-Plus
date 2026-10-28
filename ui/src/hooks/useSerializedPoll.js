import { useCallback, useEffect, useRef, useState } from 'react'

// A changed filter invalidates the response, but waits for the request to settle
// before starting another. Aborting fetch alone does not cancel a database query.
export default function useSerializedPoll({ params, fetcher, enabled = true, intervalMs = 5000 }) {
  const key = JSON.stringify(params)
  const latest = useRef(null)
  latest.current = { params, fetcher, enabled, intervalMs, key }
  const state = useRef({ active: false, inflight: null, pending: null, timer: null, revision: 0 })
  const [result, setResult] = useState({ data: null, error: null, loading: true, key: null, loadedAt: null })
  const [visible, setVisible] = useState(() => document.visibilityState !== 'hidden')
  const pump = useRef(() => {})

  const request = useCallback((overrides = {}, { background = false } = {}) => {
    const s = state.current
    clearTimeout(s.timer)
    const current = latest.current
    s.pending = { params: { ...current.params, ...overrides }, key: current.key,
      revision: ++s.revision, background }
    if (!background) setResult(previous => ({ ...previous, loading: true, error: null }))
    pump.current()
  }, [])

  pump.current = () => {
    const s = state.current
    if (!s.active || s.inflight || document.visibilityState === 'hidden') return
    const job = s.pending
    if (!job) return
    s.pending = null
    const controller = new AbortController()
    s.inflight = controller
    const operation = (async () => latest.current.fetcher(job.params, { signal: controller.signal }))()
    operation
      .then(data => {
        if (s.active && job.revision === s.revision && job.key === latest.current.key) {
          setResult({ data, error: null, loading: false, key: job.key, loadedAt: new Date() })
        }
      }).catch(error => {
        if (s.active && job.revision === s.revision && job.key === latest.current.key && error.name !== 'AbortError') {
          setResult(previous => ({ ...previous, error, loading: false, key: job.key,
            data: job.background && previous.key === job.key ? previous.data : null }))
        }
      }).finally(() => {
        if (s.inflight === controller) s.inflight = null
        if (!s.active) return
        if (s.pending) pump.current()
        else if (latest.current.enabled && document.visibilityState !== 'hidden') {
          s.timer = setTimeout(() => request({}, { background: true }), latest.current.intervalMs)
        }
      })
  }

  useEffect(() => {
    const s = state.current
    s.active = true
    const onVisibility = () => {
      const nextVisible = document.visibilityState !== 'hidden'
      setVisible(nextVisible)
      clearTimeout(s.timer)
      if (nextVisible) {
        if (s.pending) pump.current()
        else if (latest.current.enabled && !s.inflight) request({}, { background: true })
      }
    }
    document.addEventListener('visibilitychange', onVisibility)
    return () => {
      s.active = false
      s.revision++
      s.pending = null
      clearTimeout(s.timer)
      s.inflight?.abort()
      document.removeEventListener('visibilitychange', onVisibility)
    }
  }, [request])

  useEffect(() => { request() }, [key, request])
  useEffect(() => {
    const s = state.current
    clearTimeout(s.timer)
    if (enabled && !s.inflight && !s.pending && document.visibilityState !== 'hidden') {
      s.timer = setTimeout(() => request({}, { background: true }), intervalMs)
    }
    return () => clearTimeout(s.timer)
  }, [enabled, intervalMs, request])

  return { ...result, data: result.key === key ? result.data : null,
    error: result.key === key ? result.error : null, loadedAt: result.key === key ? result.loadedAt : null,
    loading: result.key !== key || result.loading, refresh: request, visible }
}
