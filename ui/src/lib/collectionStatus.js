// Presentation is shared by the header and health panel. New receivers classify
// attention separately from pending work; the fallback supports older snapshots.
export function collectionStatus(ingestion) {
  const collection = ingestion?.collection || {}
  const stats = ingestion?.stats || {}
  const reasons = new Set(collection.attention_reasons || (collection.reasons || []).filter(reason => !['backlog', 'processing'].includes(reason)))
  const pending = (ingestion?.queue?.depth || 0) + (ingestion?.spool?.rows || 0)
    + (ingestion?.batch?.pending || 0) + (ingestion?.batch?.inflight || 0)
  const historicalLoss = stats.dropped > 0 || stats.failed > 0 || stats.parse_exceptions > 0 || reasons.has('historical_loss')

  if (typeof collection.attention_required !== 'boolean') {
    const threshold = Math.max(10, 2 * (ingestion?.batch?.flush_interval_seconds || 0))
    const snapshotAge = ingestion?.age_seconds || 0
    const ages = [ingestion?.queue, ingestion?.spool, ingestion?.batch]
      .filter(group => group && (group.depth > 0 || group.rows > 0 || group.pending > 0 || group.inflight > 0))
      .map(group => group.oldest_age_seconds == null ? 0 : group.oldest_age_seconds + snapshotAge)
    const busySince = ingestion?.workers?.producer?.busy_since
    if (pending > 0 && busySince && ingestion?.updated_at) ages.push(ingestion.updated_at + snapshotAge - busySince)
    if (Math.max(0, ...ages) > threshold) reasons.add('backlog_lag')
    if (ingestion?.queue?.capacity > 0 && ingestion.queue.depth / ingestion.queue.capacity >= 0.8) reasons.add('queue_pressure')
    if (ingestion?.retry?.consecutive_failures > 0) reasons.add('delivery_retry')
    if (ingestion?.spool?.failed) reasons.add('storage_error')
    if (ingestion?.state === 'stalled') reasons.add('worker_stalled')
    if (ingestion?.state === 'error' || Object.values(ingestion?.workers || {}).some(worker => worker?.failed || worker?.alive === false)) reasons.add('worker_error')
    if (ingestion?.status && ingestion.status !== 'fresh') reasons.add(`${ingestion.status === 'stale' ? 'stale' : 'unavailable'}_snapshot`)
    else if (ingestion?.state === 'unknown') reasons.add('unavailable_snapshot')
  }
  if (historicalLoss) reasons.add('historical_loss')
  const attentionRequired = Boolean(collection.attention_required || reasons.size)
  const processing = collection.state === 'processing' || (!attentionRequired && (pending > 0 || ingestion?.state === 'pending'))
  const activeReasons = [...reasons].filter(reason => reason !== 'historical_loss')
  // Historical loss does not describe the current worker's state.
  let receiverState = collection.state && collection.state !== 'loss'
    ? collection.state : ingestion?.state === 'pending' ? 'processing' : ingestion?.state || 'unknown'
  if (!collection.state || collection.state === 'loss') {
    if (activeReasons.some(reason => ['stale_snapshot', 'unavailable_snapshot'].includes(reason))) receiverState = 'unknown'
    else if (activeReasons.some(reason => ['worker_error', 'storage_error', 'worker_stalled'].includes(reason))) receiverState = 'error'
    else if (activeReasons.some(reason => ['backlog_lag', 'queue_pressure', 'delivery_retry'].includes(reason))) receiverState = 'delayed'
  }

  return { attentionRequired, processing, historicalLoss, activeReasons, receiverState }
}
