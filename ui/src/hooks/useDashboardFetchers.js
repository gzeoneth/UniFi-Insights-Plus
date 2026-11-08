import { useMemo } from 'react'
import { fetchStatsOverview, fetchStatsCharts, fetchStatsTables } from '../api'
import { createRequestQueue } from '../lib/requestQueue'

// Include background refreshes in the same FIFO without changing tier loading
// states. Tier cleanup aborts queued jobs when the dashboard leaves the page.
export default function useDashboardFetchers() {
  return useMemo(() => {
    const enqueue = createRequestQueue()
    const wrap = fetcher => (timeRange, params, options = {}) =>
      enqueue(() => fetcher(timeRange, params, options), options.signal)
    return {
      overview: wrap(fetchStatsOverview),
      charts: wrap(fetchStatsCharts),
      tables: wrap(fetchStatsTables),
    }
  }, [])
}
