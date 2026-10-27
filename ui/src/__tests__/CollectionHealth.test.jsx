import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'
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
})
