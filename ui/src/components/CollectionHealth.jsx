import { useEffect, useState } from 'react'
import { apiFetch } from '../api'

const PROVIDERS = [
  ['geoip', 'GeoIP'], ['asn', 'ASN'], ['rdns', 'Reverse DNS'],
  ['abuseipdb', 'AbuseIPDB'], ['unifi', 'UniFi controller'],
]
const LABELS = {
  ready: 'Ready', not_configured: 'Not configured', missing: 'Files missing',
  error: 'Error', pending: 'Pending', stalled: 'Worker stalled', unknown: 'Unknown',
  unavailable: 'Unavailable', stale: 'Stale', fresh: 'Fresh',
}
const COLORS = {
  ready: 'text-emerald-400', fresh: 'text-emerald-400',
  error: 'text-red-400', stalled: 'text-red-400',
  pending: 'text-amber-300', missing: 'text-amber-300', stale: 'text-amber-300',
}
const number = value => typeof value === 'number' ? value.toLocaleString() : '—'
const age = seconds => seconds == null ? 'Not observed' : seconds < 60
  ? `${Math.floor(seconds)}s ago` : seconds < 3600 ? `${Math.floor(seconds / 60)}m ago`
    : `${Math.floor(seconds / 3600)}h ago`
const bytes = value => typeof value === 'number' ? `${(value / 1048576).toFixed(1)} MiB` : '—'

function Metric({ label, value, detail, state }) {
  return (
    <div className="border border-gray-800 rounded-lg p-3 min-w-0">
      <dt className="text-xs text-gray-400">{label}</dt>
      <dd className={`text-lg font-semibold mt-1 ${COLORS[state] || 'text-gray-200'}`}>
        {value}
        {detail && <p className="text-xs font-normal text-gray-500 mt-1">{detail}</p>}
      </dd>
    </div>
  )
}

export default function CollectionHealth() {
  const [health, setHealth] = useState(null)
  const [ingestion, setIngestion] = useState(null)
  const [databaseError, setDatabaseError] = useState(false)
  const [snapshotError, setSnapshotError] = useState(false)
  const [loaded, setLoaded] = useState(false)
  const [refresh, setRefresh] = useState(0)

  useEffect(() => {
    let active = true
    let timer
    let controller
    let timeout
    const load = async () => {
      controller = new AbortController()
      timeout = setTimeout(() => controller.abort(), 15000)
      const [database, collector] = await Promise.allSettled([
        apiFetch('/api/health', { signal: controller.signal }),
        apiFetch('/api/health/ingest', { signal: controller.signal }),
      ])
      clearTimeout(timeout)
      if (!active) return
      setLoaded(true)
      setDatabaseError(database.status !== 'fulfilled')
      setSnapshotError(collector.status !== 'fulfilled')
      setHealth(database.status === 'fulfilled' ? database.value : null)
      setIngestion(collector.status === 'fulfilled' ? collector.value : null)
      timer = setTimeout(tick, 10000)
    }
    const tick = () => {
      if (document.visibilityState === 'visible') load()
      else timer = setTimeout(tick, 10000)
    }
    load()
    return () => {
      active = false
      clearTimeout(timer)
      clearTimeout(timeout)
      controller?.abort()
    }
  }, [refresh])

  const stats = ingestion?.stats || {}
  const queue = ingestion?.queue || {}
  const spool = ingestion?.spool || {}
  const state = snapshotError ? 'unavailable' : ingestion?.state || 'unknown'
  const fresh = ingestion?.status === 'fresh'

  return (
    <section aria-label="Collection health" className="border border-gray-800 rounded-lg p-4 space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h2 className="text-sm font-semibold text-gray-200">Collection health</h2>
          <p className="text-xs text-gray-500 mt-1">Current receiver session · refreshes every 10 seconds</p>
        </div>
        <button type="button" onClick={() => setRefresh(value => value + 1)}
          className="text-xs text-teal-400 hover:text-teal-300 underline">Refresh health</button>
      </div>
      {!loaded ? <p role="status" className="text-sm text-gray-400">Loading collection health…</p> : <>
        {(databaseError || snapshotError || !fresh) && (
          <p role="alert" className="text-sm text-amber-300">
            {databaseError && 'Database health is unavailable. '}
            {snapshotError ? 'Receiver health could not be loaded.' : !fresh
              ? `Receiver snapshot is ${ingestion?.status || 'unavailable'}; current collection cannot be confirmed.` : ''}
          </p>
        )}
        <dl className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          <Metric label="Receiver" value={LABELS[state] || state} state={state}
            detail={ingestion?.updated_at ? `Snapshot ${age(ingestion.age_seconds)}` : 'No receiver snapshot'} />
          <Metric label="Last packet received" value={age(ingestion?.receive_age_seconds)}
            detail={ingestion?.last_receive_at ? new Date(ingestion.last_receive_at * 1000).toLocaleString() : 'No UDP packet observed this session'} />
          <Metric label="Waiting in memory" value={`${number(queue.depth)} / ${number(queue.capacity)}`}
            detail={queue.depth > 0 ? `Oldest packet ${age(queue.oldest_age_seconds)}` : 'No packets waiting'} />
          <Metric label="Saved for retry" value={number(spool.rows)} state={spool.failed ? 'error' : undefined}
            detail={`${bytes(spool.bytes)} / ${bytes(spool.max_bytes)}${spool.failed ? ' · storage error' : ''}`} />
        </dl>
        <dl className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4">
          {[
            ['received', 'Packets received'], ['inserted', 'Rows committed'],
            ['duplicates', 'Replays acknowledged'], ['filtered', 'Filtered by settings'],
            ['failed', 'Unparseable packets'], ['dropped', 'Known dropped rows/packets'],
          ].map(([key, label]) => (
            <div key={key}><dt className="text-xs text-gray-400">{label}</dt>
              <dd className={`text-lg font-semibold ${key === 'dropped' && stats[key] ? 'text-red-400' : 'text-gray-200'}`}>{number(stats[key])}</dd>
            </div>
          ))}
        </dl>
        <p className="text-xs text-gray-500">
          Queue overflow: {number(stats.queue_dropped)} · Retry storage overflow/failure: {number(stats.spool_dropped)} ·
          {' '}Database write failures: {number(stats.flush_errors)} · Parser exceptions: {number(stats.parse_exceptions)}
        </p>
        <div className="border-t border-gray-800 pt-4">
          <h3 className="text-xs font-medium text-gray-300 mb-3">Enrichment providers</h3>
          <dl className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
            {PROVIDERS.map(([key, label]) => {
              const providerState = fresh ? ingestion?.providers?.[key]?.status || 'unknown' : 'unknown'
              return <div key={key}><dt className="text-xs text-gray-400">{label}</dt>
                <dd className={`text-sm mt-1 ${COLORS[providerState] || 'text-gray-400'}`}>{LABELS[providerState] || providerState}</dd>
              </div>
            })}
          </dl>
          <p className="text-xs text-gray-500 mt-3">
            Provider states come from local configuration, loaded files and background work. This page does not run live provider checks.
            First events can arrive before DNS or reputation data is available.
          </p>
        </div>
        <p className="text-xs text-gray-500 border-t border-gray-800 pt-3">
          Database rows: {health ? `approximately ${number(health.total_logs)}` : 'unavailable'}.
          {' '}Counters reset when the receiver restarts. UDP cannot confirm every event sent by the gateway; packets lost before reaching this process are not counted.
        </p>
      </>}
    </section>
  )
}
