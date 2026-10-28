import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react'
import CollectionHealth from '../components/CollectionHealth'
import { apiFetch } from '../api'

vi.mock('../api', () => ({ apiFetch: vi.fn() }))

const ingestion = {
  status: 'fresh', state: 'ready', updated_at: 1793100000, age_seconds: 1,
  receive_age_seconds: 3, last_receive_at: 1793099998,
  stats: { received: 100, inserted: 90, duplicates: 2, filtered: 3, failed: 1, dropped: 4 },
  queue: { depth: 2, capacity: 4096, oldest_age_seconds: 1 },
  spool: { rows: 5, bytes: 5120, max_bytes: 67108864 },
  providers: { geoip: { status: 'missing' }, abuseipdb: { status: 'not_configured' } },
}

beforeEach(() => vi.clearAllMocks())
afterEach(() => {
  cleanup(); vi.useRealTimers()
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' })
})

describe('CollectionHealth', () => {
  it('shows cumulative collection loss alongside a ready receiver and separates retries from delivery attempts', async () => {
    apiFetch.mockImplementation(url => Promise.resolve(url.endsWith('/ingest')
      ? { ...ingestion, stats: { ...ingestion.stats, delivery_attempts: 25, retry_attempts: 3 }, enrichment: { dropped: 9 } }
      : { total_logs: 100 }))
    render(<CollectionHealth />)
    const warning = await screen.findByText(/Known collection loss this receiver session/)
    expect(warning).toHaveTextContent('4 dropped rows/packets')
    expect(warning).toHaveTextContent('does not by itself indicate that collection is currently failing')
    expect(screen.getByText('Ready')).toBeTruthy()
    expect(within(screen.getByText('Database batch sends').parentElement).getByText('25')).toBeTruthy()
    expect(within(screen.getByText('Retry batch sends').parentElement).getByText('3')).toBeTruthy()
    expect(screen.getByText(/Skipped enrichment jobs: 9/)).toHaveTextContent('not dropped log rows')
  })

  it('does not call skipped enrichment collection loss and keeps legacy retry counts unknown', async () => {
    apiFetch.mockImplementation(url => Promise.resolve(url.endsWith('/ingest')
      ? { ...ingestion, stats: { ...ingestion.stats, dropped: 0, delivery_attempts: 25, retry_attempts: null }, enrichment: { dropped: 7 } }
      : { total_logs: 100 }))
    render(<CollectionHealth />)
    await screen.findByText(/Skipped enrichment jobs: 7/)
    expect(screen.queryByText(/Known collection loss/)).toBeNull()
    expect(within(screen.getByText('Retry batch sends').parentElement).getByText('Unknown')).toBeTruthy()
    expect(screen.getByText(/does not report a separate retry count/)).toBeTruthy()
    expect(screen.getByText(/Results may be incomplete/)).toHaveTextContent('Some packets could not be parsed')
  })

  it('retains ingestion evidence when the database health request fails', async () => {
    apiFetch.mockImplementation(url => url.endsWith('/ingest')
      ? Promise.resolve(ingestion) : Promise.reject(new Error('database down')))
    render(<CollectionHealth />)
    await screen.findByText(/Database health is unavailable/)
    const received = screen.getByText('Packets received').parentElement
    expect(within(received).getByText('100')).toBeTruthy()
    expect(screen.getByText('Files missing')).toBeTruthy()
    expect(screen.getByText('Not configured')).toBeTruthy()
    expect(screen.getByText(/packets lost before reaching this process are not counted/)).toBeTruthy()
  })

  it('labels database counts as estimates and stale provider states as unknown', async () => {
    apiFetch.mockImplementation(url => Promise.resolve(url.endsWith('/ingest')
      ? { ...ingestion, status: 'stale', state: 'unknown', providers: { geoip: { status: 'ready' } } }
      : { total_logs: 12345 }))
    render(<CollectionHealth />)
    await screen.findByText(/snapshot is stale/)
    expect(screen.getByText(/approximately 12,345/)).toBeTruthy()
    expect(screen.queryByText('Ready')).toBeNull()
    const geoip = screen.getByText('GeoIP').parentElement
    expect(within(geoip).getByText('Unknown')).toBeTruthy()
  })

  it('aborts both requests when unmounted', async () => {
    apiFetch.mockImplementation(() => new Promise(() => {}))
    const { unmount } = render(<CollectionHealth />)
    const signals = apiFetch.mock.calls.map(([, options]) => options.signal)
    unmount()
    expect(signals).toHaveLength(2)
    expect(signals.every(signal => signal.aborted)).toBe(true)
  })

  it('distinguishes current rates, backlog and historical loss without implying a complete record', async () => {
    apiFetch.mockImplementation(url => Promise.resolve(url.endsWith('/ingest') ? {
      ...ingestion, rates: { window_seconds: 60, received_per_second: 120.5, inserted_per_second: 80.5, dropped_per_second: 0 },
      spool: { ...ingestion.spool, oldest_age_seconds: 125 },
      collection: { incomplete: true, reasons: ['historical_loss', 'backlog'] },
      workers: { producer: { alive: true }, delivery: { alive: false, failed: true } },
    } : { total_logs: 100 }))
    render(<CollectionHealth />)
    await screen.findByText('120.5/s')
    expect(within(screen.getByText('Write rate').parentElement).getByText('80.5/s')).toBeTruthy()
    expect(within(screen.getByText('Current loss rate').parentElement).getByText('0.0/s')).toBeTruthy()
    expect(screen.getByText(/Results may be incomplete/)).toHaveTextContent('events are taking longer than expected to be written')
    expect(screen.getByText(/Results may be incomplete/)).toHaveTextContent('empty result does not prove')
    expect(screen.getByText(/oldest row 2m ago/)).toBeTruthy()
    expect(within(screen.getByText('Database delivery worker').parentElement).getByText('Error')).toBeTruthy()
  })

  it('keeps missing and stale rates unknown instead of showing zero throughput', async () => {
    apiFetch.mockImplementation(url => Promise.resolve(url.endsWith('/ingest') ? {
      ...ingestion, status: 'stale', rates: { received_per_second: 100, inserted_per_second: 100, dropped_per_second: 0 },
    } : { total_logs: 100 }))
    render(<CollectionHealth />)
    await screen.findByText(/snapshot is stale/)
    for (const label of ['Incoming rate', 'Write rate', 'Current loss rate']) {
      expect(within(screen.getByText(label).parentElement).getByText('Unknown')).toBeTruthy()
    }
    expect(screen.queryByText('100.0/s')).toBeNull()
    expect(screen.queryByText('0.0/s')).toBeNull()
  })

  it.each([
    { incomplete: true, reasons: ['processing'], attention_required: false, attention_reasons: [], state: 'processing' },
    { incomplete: true, reasons: ['backlog'] },
  ])('shows ordinary batching as neutral processing with snapshot %o', async collection => {
    apiFetch.mockImplementation(url => Promise.resolve(url.endsWith('/ingest') ? {
      ...ingestion, state: 'pending', stats: { received: 100, inserted: 90, failed: 0, dropped: 0 },
      queue: { depth: 0, capacity: 4096, oldest_age_seconds: 0 },
      spool: { rows: 0, oldest_age_seconds: 0 },
      batch: { pending: 10, inflight: 5, flush_interval_seconds: 1 }, collection,
    } : {}))
    render(<CollectionHealth />)
    const message = await screen.findByText(/Processing recent events/)
    expect(message).toHaveAttribute('role', 'status')
    expect(message).not.toHaveClass('text-amber-300')
    expect(screen.queryByRole('alert')).toBeNull()
    expect(within(screen.getByText('Receiver').parentElement).getByText('Processing')).toBeTruthy()
  })

  it('keeps historical loss distinct from a current delivery problem', async () => {
    apiFetch.mockImplementation(url => Promise.resolve(url.endsWith('/ingest') ? {
      ...ingestion, stats: { dropped: 4, failed: 0 }, queue: { depth: 0 }, spool: { rows: 0 },
      collection: { state: 'loss', attention_required: true, attention_reasons: ['historical_loss'] },
    } : {}))
    render(<CollectionHealth />)
    await screen.findByText(/Known collection loss/)
    expect(screen.queryByText(/Results may be incomplete/)).toBeNull()
    expect(screen.queryByText(/Processing recent events/)).toBeNull()
    expect(within(screen.getByText('Receiver').parentElement).getByText('Ready')).toBeTruthy()
  })

  it('shows actionable delay and failure reasons without treating them as normal processing', async () => {
    apiFetch.mockImplementation(url => Promise.resolve(url.endsWith('/ingest') ? {
      ...ingestion, stats: { dropped: 0, failed: 0 },
      collection: { state: 'error', attention_required: true,
        attention_reasons: ['backlog_lag', 'queue_pressure', 'delivery_retry', 'worker_stalled'] },
    } : {}))
    render(<CollectionHealth />)
    const alert = await screen.findByText(/Results may be incomplete/)
    expect(alert).toHaveTextContent('taking longer than expected')
    expect(alert).toHaveTextContent('nearing capacity')
    expect(alert).toHaveTextContent('retrying after a failure')
    expect(alert).toHaveTextContent('needs attention')
    expect(screen.queryByText(/Processing recent events/)).toBeNull()
  })

  it('detects an aged partial batch from an older snapshot without a queue backlog', async () => {
    apiFetch.mockImplementation(url => Promise.resolve(url.endsWith('/ingest') ? {
      ...ingestion, state: 'pending', stats: { dropped: 0, failed: 0 },
      queue: { depth: 0 }, spool: { rows: 0 }, batch: { pending: 2, oldest_age_seconds: 25, flush_interval_seconds: 1 },
      collection: { incomplete: true, reasons: ['backlog'] },
    } : {}))
    render(<CollectionHealth />)
    expect(await screen.findByText(/Results may be incomplete/)).toHaveTextContent('taking longer than expected')
    expect(screen.queryByText(/Processing recent events/)).toBeNull()
    expect(within(screen.getByText('Receiver').parentElement).getByText('Delayed')).toBeTruthy()
  })

  it('shows batch and stage diagnostics on demand with missing timings left unknown', async () => {
    apiFetch.mockImplementation(url => Promise.resolve(url.endsWith('/ingest') ? {
      ...ingestion, rates: { staged_per_second: 75.5 },
      batch: { size: 50, flush_interval_seconds: 1, pending: 3, inflight: 2 },
      timings: { db_insert: { count: 4, mean_ms: 12.5, last_ms: 10, max_ms: 20 } },
    } : {}))
    render(<CollectionHealth />)
    const summary = await screen.findByText('Collection performance details')
    expect(summary.parentElement).not.toHaveAttribute('open')
    fireEvent.click(summary)
    expect(summary.parentElement).toHaveAttribute('open')
    expect(screen.getByText('75.5/s')).toBeTruthy()
    expect(within(screen.getByText('Batch size').parentElement).getByText('50')).toBeTruthy()
    expect(within(screen.getByText('In-flight rows').parentElement).getByText('2')).toBeTruthy()
    const commit = screen.getByRole('row', { name: /Commit database batch/ })
    expect(commit).toHaveTextContent('12.5 ms')
    expect(commit).toHaveTextContent('10.0 ms')
    expect(commit).toHaveTextContent('20.0 ms')
    expect(screen.getByRole('row', { name: /Parse packet/ })).toHaveTextContent('Unknown')
  })

  it('serializes a requested refresh behind slow health calls and stops polling while hidden', async () => {
    vi.useFakeTimers()
    const completions = []
    apiFetch.mockImplementation(url => new Promise(resolve => completions.push(() => resolve(url.endsWith('/ingest') ? ingestion : {}))))
    render(<CollectionHealth />)
    await act(async () => { await vi.advanceTimersByTimeAsync(30000) })
    expect(apiFetch).toHaveBeenCalledTimes(2)
    expect(screen.getByText('Refresh health')).toBeDisabled()
    await act(async () => completions.forEach(done => done()))
    Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'hidden' })
    fireEvent(document, new Event('visibilitychange'))
    await act(async () => { await vi.advanceTimersByTimeAsync(30000) })
    expect(apiFetch).toHaveBeenCalledTimes(2)
  })
})
