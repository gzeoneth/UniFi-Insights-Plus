import useSerializedPoll from '../hooks/useSerializedPoll'
import { apiFetch } from '../api'
import { collectionStatus } from '../lib/collectionStatus'

const PROVIDERS = [
  ['geoip', 'GeoIP'], ['asn', 'ASN'], ['rdns', 'Reverse DNS'],
  ['abuseipdb', 'AbuseIPDB'], ['unifi', 'UniFi controller'],
]
const LABELS = {
  ready: 'Ready', not_configured: 'Not configured', missing: 'Files missing',
  error: 'Error', pending: 'Pending', stalled: 'Worker stalled', unknown: 'Unknown',
  unavailable: 'Unavailable', stale: 'Stale', fresh: 'Fresh',
  processing: 'Processing', delayed: 'Delayed',
}
const COLORS = {
  ready: 'text-emerald-400', fresh: 'text-emerald-400',
  error: 'text-red-400', stalled: 'text-red-400',
  pending: 'text-amber-300', missing: 'text-amber-300', stale: 'text-amber-300',
  delayed: 'text-amber-300', processing: 'text-gray-200',
}
const number = value => typeof value === 'number' ? value.toLocaleString() : '—'
const age = seconds => seconds == null ? 'Not observed' : seconds < 60
  ? `${Math.floor(seconds)}s ago` : seconds < 3600 ? `${Math.floor(seconds / 60)}m ago`
    : `${Math.floor(seconds / 3600)}h ago`
const bytes = value => typeof value === 'number' ? `${(value / 1048576).toFixed(1)} MiB` : '—'
const milliseconds = value => typeof value === 'number' && Number.isFinite(value) ? `${value.toFixed(1)} ms` : 'Unknown'
const STAGES = [
  ['parse', 'Parse packet'], ['enrich', 'Enrichment lookup'], ['spool_stage', 'Save retry batch'],
  ['spool_read', 'Read retry batch'], ['db_insert', 'Commit database batch'], ['spool_ack', 'Acknowledge retry batch'],
]
const PHASES = {
  idle: 'Idle', spool_open: 'Opening retry storage', parse_enrich: 'Parsing and enriching',
  spool_stage: 'Saving retry batch', spool_read: 'Reading retry batch',
  db_insert: 'Committing database batch', spool_ack: 'Acknowledging retry batch',
}

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

const fetchDatabaseHealth = (_params, options) => apiFetch('/api/health', options)
const fetchReceiverHealth = (_params, options) => apiFetch('/api/health/ingest', options)

export default function CollectionHealth() {
  // PostgreSQL can be the stalled component. Its slower summary must never
  // hold up current receiver metrics or the next receiver-only refresh.
  const collectorPoll = useSerializedPoll({ params: {}, fetcher: fetchReceiverHealth, intervalMs: 10000 })
  const databasePoll = useSerializedPoll({ params: {}, fetcher: fetchDatabaseHealth, intervalMs: 60000 })
  const health = databasePoll.error ? null : databasePoll.data
  const ingestion = collectorPoll.error ? null : collectorPoll.data
  const databaseError = Boolean(databasePoll.error)
  const snapshotError = Boolean(collectorPoll.error)
  const loaded = Boolean(collectorPoll.data || collectorPoll.error)

  const stats = ingestion?.stats || {}
  const queue = ingestion?.queue || {}
  const spool = ingestion?.spool || {}
  const enrichment = ingestion?.enrichment || {}
  const collection = collectionStatus(ingestion)
  const state = snapshotError ? 'unavailable' : collection.receiverState
  const fresh = ingestion?.status === 'fresh'
  const rates = fresh ? ingestion?.rates || {} : {}
  const rate = value => typeof value === 'number' && Number.isFinite(value) ? `${value.toFixed(1)}/s` : 'Unknown'
  const reasons = collection.activeReasons
  const parseLoss = stats.failed > 0 || stats.parse_exceptions > 0
  const timings = fresh ? ingestion?.timings || {} : {}
  const batch = fresh ? ingestion?.batch || {} : {}

  return (
    <section aria-label="Collection health" className="border border-gray-800 rounded-lg p-4 space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h2 className="text-sm font-semibold text-gray-200">Collection health</h2>
          <p className="text-xs text-gray-500 mt-1">Current receiver session · refreshes while this tab is visible</p>
        </div>
        <button type="button" onClick={() => {
          collectorPoll.refresh()
          if (!databasePoll.loading) databasePoll.refresh()
        }} disabled={collectorPoll.loading}
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
        {stats.dropped > 0 && <p role="alert" className="text-sm text-amber-300">
          Known collection loss this receiver session: {number(stats.dropped)} dropped rows/packets. This is a cumulative counter; it does not by itself indicate that collection is currently failing.
        </p>}
        {collection.processing && !collection.attentionRequired && <p role="status" className="text-sm text-gray-400">
          Processing recent events. New events are being collected and written; this is normal.
        </p>}
        {(reasons.length > 0 || parseLoss) && <p role="alert" className="text-sm text-amber-300">
          Results may be incomplete: {reasons.includes('backlog_lag') ? 'events are taking longer than expected to be written. ' : ''}
          {reasons.includes('queue_pressure') ? 'The receiver queue is nearing capacity. ' : ''}
          {reasons.includes('delivery_retry') ? 'Database delivery is retrying after a failure. ' : ''}
          {parseLoss ? 'Some packets could not be parsed and are missing from searchable events. ' : ''}
          {reasons.some(reason => ['worker_error', 'storage_error', 'worker_stalled'].includes(reason)) ? 'A collection worker or retry store needs attention. ' : ''}
          {reasons.some(reason => ['stale_snapshot', 'unavailable_snapshot'].includes(reason)) ? 'Current receiver status cannot be confirmed. ' : ''}
          An empty result does not prove that no matching traffic occurred.
        </p>}
        <dl className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          <Metric label="Incoming rate" value={rate(rates.received_per_second)}
            detail="UDP packets received" />
          <Metric label="Write rate" value={rate(rates.inserted_per_second)}
            detail="New rows committed to PostgreSQL" />
          <Metric label="Current loss rate" value={rate(rates.dropped_per_second)}
            state={rates.dropped_per_second > 0 ? 'error' : undefined}
            detail="Dropped rows/packets during the sampled window" />
          <Metric label="Rate window" value={rates.window_seconds == null ? 'Unknown' : `${Math.round(rates.window_seconds)} seconds`}
            detail="Packets and rows differ when events are filtered or retried. A zero loss rate does not erase historical loss." />
        </dl>
        <dl className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          <Metric label="Receiver" value={LABELS[state] || state} state={state}
            detail={ingestion?.updated_at ? `Snapshot ${age(ingestion.age_seconds)}` : 'No receiver snapshot'} />
          <Metric label="Last packet received" value={age(ingestion?.receive_age_seconds)}
            detail={ingestion?.last_receive_at ? new Date(ingestion.last_receive_at * 1000).toLocaleString() : 'No UDP packet observed this session'} />
          <Metric label="Waiting in memory" value={`${number(queue.depth)} / ${number(queue.capacity)}`}
            detail={queue.depth > 0 ? `Oldest packet ${age(queue.oldest_age_seconds)}` : queue.depth === 0 ? 'No packets waiting' : 'Queue depth unavailable'} />
          <Metric label="Saved for retry" value={number(spool.rows)} state={spool.failed ? 'error' : undefined}
            detail={`${bytes(spool.bytes)} / ${bytes(spool.max_bytes)}${spool.failed ? ' · storage error' : ''}${spool.rows > 0 ? ` · oldest row ${age(spool.oldest_age_seconds)}` : ''}`} />
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
        <dl className="grid grid-cols-2 gap-3">
          <Metric label="Database batch sends" value={number(stats.delivery_attempts)}
            detail="All delivery attempts, including retries. This counts batches, not rows." />
          <Metric label="Retry batch sends" value={stats.retry_attempts == null ? 'Unknown' : number(stats.retry_attempts)}
            detail={stats.retry_attempts == null ? 'This snapshot does not report a separate retry count.' : 'Sends containing rows from a previously failed delivery.'} />
        </dl>
        <dl className="grid grid-cols-2 gap-3">
          {Object.entries({ producer: 'Packet processing worker', delivery: 'Database delivery worker' }).map(([key, label]) => {
            const worker = fresh ? ingestion?.workers?.[key] : null
            const workerState = worker?.failed ? 'error' : worker?.alive === true ? 'ready' : worker?.alive === false ? 'stalled' : 'unknown'
            return <Metric key={key} label={label} value={LABELS[workerState]} state={workerState}
              detail={PHASES[worker?.phase] || (worker?.busy_since ? 'Working on a batch' : undefined)} />
          })}
        </dl>
        <details className="border border-gray-800 rounded-lg p-3">
          <summary className="text-sm text-gray-300 cursor-pointer">Collection performance details</summary>
          <p className="text-xs text-gray-500 mt-3">Timings describe this receiver session. Parsing and enrichment run per event; retry storage and database timings run per batch. Compare each stage with itself over time.</p>
          <dl className="grid grid-cols-2 lg:grid-cols-4 gap-3 my-3">
            <Metric label="Staging rate" value={rate(rates.staged_per_second)} detail="Rows saved to durable retry storage" />
            <Metric label="Batch size" value={number(batch.size)} detail={batch.flush_interval_seconds == null ? 'Flush interval unknown' : `Flush after ${batch.flush_interval_seconds} seconds`} />
            <Metric label="Pending batch rows" value={number(batch.pending)} detail="Parsed rows awaiting durable staging" />
            <Metric label="In-flight rows" value={number(batch.inflight)} detail="Rows currently being processed; not yet durable" />
          </dl>
          <div className="overflow-x-auto">
            <table className="w-full text-xs text-left" aria-label="Collection stage timings">
              <thead className="text-gray-400"><tr><th className="py-2">Stage</th><th>Samples</th><th>Mean</th><th>Last</th><th>Maximum</th><th>Maximum observed</th></tr></thead>
              <tbody className="text-gray-300">{STAGES.map(([key, label]) => <tr key={key} className="border-t border-gray-800">
                <th scope="row" className="py-2 font-normal">{label}</th><td>{number(timings[key]?.count)}</td>
                <td>{milliseconds(timings[key]?.mean_ms)}</td><td>{milliseconds(timings[key]?.last_ms)}</td><td>{milliseconds(timings[key]?.max_ms)}</td>
                <td>{timings[key]?.max_at ? new Date(timings[key].max_at * 1000).toLocaleString() : 'Unknown'}</td>
              </tr>)}</tbody>
            </table>
          </div>
          {fresh && ingestion?.slow_operations?.length > 0 && <div className="mt-4">
            <h3 className="text-xs font-medium text-gray-300">Recent operations over one second</h3>
            <p className="text-xs text-gray-500 mt-1">Last 32 completed operations this session; a past delay does not mean collection is currently stalled.</p>
            <ul className="text-xs text-gray-400 mt-2 space-y-1">{ingestion.slow_operations.slice(-32).reverse().map((operation, index) => (
              <li key={`${operation.finished_at}-${index}`}>
                {new Date(operation.finished_at * 1000).toLocaleString()} · {STAGES.find(([key]) => key === operation.stage)?.[1] || 'Collection operation'} · {milliseconds(operation.duration_ms)}
              </li>
            ))}</ul>
          </div>}
        </details>
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
          <p className={`text-xs mt-2 ${enrichment.dropped > 0 ? 'text-amber-300' : 'text-gray-500'}`}>
            Skipped enrichment jobs: {number(enrichment.dropped)}. This counts skipped enrichment work, not dropped log rows. Missing enrichment can leave DNS or reputation fields unavailable.
          </p>
        </div>
        <p className="text-xs text-gray-500 border-t border-gray-800 pt-3">
          Database rows: {health ? `approximately ${number(health.total_logs)}` : databasePoll.loading ? 'loading' : 'unavailable'}.
          {' '}Database summary refreshes every minute; receiver metrics refresh independently every ten seconds.
          {' '}Counters reset when the receiver restarts. UDP cannot confirm every event sent by the gateway; packets lost before reaching this process are not counted.
        </p>
      </>}
    </section>
  )
}
