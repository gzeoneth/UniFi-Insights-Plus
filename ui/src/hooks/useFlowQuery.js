import { useRef } from 'react'
import useSerializedPoll from './useSerializedPoll'
import { readCache, writeCache } from '../lib/sessionCache'

export const FLOW_CACHE_MS = 30_000

// Flow panels query on filter changes or explicit refresh, without a timer.
// The shared worker serializes changes and waits while the tab is hidden.
export default function useFlowQuery(prefix, params, fetcher, refreshKey = 0, ready = true) {
  const completedRefresh = useRef(0)
  const query = useSerializedPoll({
    params: { query: params, refreshKey }, enabled: false, ready,
    fetcher: async (request, options) => {
      const discriminator = JSON.stringify(request.query)
      const force = request.refreshKey !== completedRefresh.current
      const cached = !force && readCache(prefix, discriminator, FLOW_CACHE_MS)
      if (cached) return cached
      const data = await fetcher(request.query, options)
      writeCache(prefix, discriminator, data)
      completedRefresh.current = request.refreshKey
      return data
    },
  })
  return { ...query, loading: !ready || query.loading }
}
