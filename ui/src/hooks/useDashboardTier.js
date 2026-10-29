import useSerializedPoll from './useSerializedPoll'
import { readCache, writeCache, CACHE_TTL_MS } from '../lib/sessionCache'

// Each tier has one request at a time, including across filter changes.
// Independent tiers still render as soon as their own result is available.
export default function useDashboardTier(tier, timeRange, excludeGroups, fetcher) {
  const discriminator = `${tier}:${timeRange}:${excludeGroups || ''}`
  const cached = readCache('dashboard', discriminator)
  const poll = useSerializedPoll({
    params: { timeRange, excludeGroups, discriminator },
    intervalMs: CACHE_TTL_MS,
    fetcher: async (params, options) => {
      const hit = readCache('dashboard', params.discriminator)
      if (hit) return hit
      const data = await fetcher(params.timeRange, { exclude_groups: params.excludeGroups }, options)
      writeCache('dashboard', params.discriminator, data)
      return data
    },
  })
  const data = poll.data || cached
  return { data, status: poll.error ? (data ? 'stale' : 'error') : data ? 'loaded' : 'loading' }
}
