import { act, cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import LogStream from '../components/LogStream'
import { fetchLogs, fetchLog } from '../api'

vi.mock('../api', () => ({
  fetchLogs: vi.fn(), fetchLog: vi.fn(), fetchLogCountsByType: vi.fn(), getExportUrl: () => '/api/export',
}))
vi.mock('../components/FilterBar', () => ({ default: ({ filters, onChange }) => <>
  <input aria-label="Source IP" value={filters.src_ip || ''} onChange={e => onChange({ ...filters, src_ip: e.target.value })} />
</> }))
vi.mock('../components/FieldFilters', () => ({ default: () => null, FILTER_FIELDS: [] }))
vi.mock('../components/LogTable', () => ({ default: ({ logs, loading, onToggleExpand }) => <div>
  <output data-testid="rows">{loading ? 'Loading' : logs.map(row => row.id).join(',')}</output>
  <button onClick={() => onToggleExpand('row-a')}>Toggle detail</button>
</div> }))

const pageResult = (id = 'row-a', overrides = {}) => ({
  data: [{ id }], total: null, pages: null, view_counts: null, has_more: true,
  page_cursor: 'start-token', next_cursor: 'next-token', ...overrides,
})
const flush = async () => { await act(async () => { await Promise.resolve() }) }
const advance = async ms => { await act(async () => { await vi.advanceTimersByTimeAsync(ms) }) }
const visible = value => {
  Object.defineProperty(document, 'visibilityState', { configurable: true, value })
  fireEvent(document, new Event('visibilitychange'))
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.useFakeTimers()
  localStorage.clear(); sessionStorage.clear()
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' })
  fetchLogs.mockResolvedValue(pageResult())
  fetchLog.mockResolvedValue({ id: 'row-a' })
})
afterEach(() => { cleanup(); vi.useRealTimers() })

describe('Log Stream request scheduling', () => {
  it('waits for a slow request to finish before starting the next polling delay', async () => {
    let resolve
    fetchLogs.mockImplementationOnce(() => new Promise(done => { resolve = done }))
    render(<LogStream />)
    expect(fetchLogs).toHaveBeenCalledTimes(1)
    expect(fetchLogs.mock.calls[0][0]).toMatchObject({ count_mode: 'none', pagination: 'cursor' })
    await advance(30000)
    expect(fetchLogs).toHaveBeenCalledTimes(1)
    await act(async () => resolve(pageResult()))
    await advance(4999)
    expect(fetchLogs).toHaveBeenCalledTimes(1)
    await advance(1)
    expect(fetchLogs).toHaveBeenCalledTimes(2)
  })

  it('stops requests while paused, including the former background count request', async () => {
    render(<LogStream />); await flush()
    fireEvent.click(screen.getByRole('button', { name: 'Live' }))
    await advance(60000)
    expect(fetchLogs).toHaveBeenCalledTimes(1)
    expect(screen.getByText('Automatic requests stopped')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: /Refresh/ }))
    await flush()
    expect(fetchLogs).toHaveBeenCalledTimes(2)
    expect(fetchLogs.mock.lastCall[0].count_mode).toBe('none')
    await advance(10000)
    expect(fetchLogs).toHaveBeenCalledTimes(2)
  })

  it('pauses polling for expanded rows and resumes only after collapse', async () => {
    render(<LogStream />); await flush()
    fireEvent.click(screen.getByText('Toggle detail')); await flush()
    await advance(20000)
    expect(fetchLogs).toHaveBeenCalledTimes(1)
    expect(fetchLog).toHaveBeenCalledTimes(1)
    fireEvent.click(screen.getByText('Toggle detail'))
    await advance(5000)
    expect(fetchLogs).toHaveBeenCalledTimes(2)
  })

  it('does not load or poll hidden tabs and resumes once visible', async () => {
    visible('hidden')
    render(<LogStream />)
    await advance(15000)
    expect(fetchLogs).not.toHaveBeenCalled()
    visible('visible'); await flush()
    expect(fetchLogs).toHaveBeenCalledTimes(1)
    visible('hidden'); await advance(15000)
    expect(fetchLogs).toHaveBeenCalledTimes(1)
    visible('visible'); await flush()
    expect(fetchLogs).toHaveBeenCalledTimes(2)
  })

  it('coalesces filter changes behind one request and never shows its stale result', async () => {
    let resolve
    fetchLogs.mockImplementationOnce(() => new Promise(done => { resolve = done }))
    fetchLogs.mockResolvedValue(pageResult('current-row'))
    render(<LogStream />)
    fireEvent.change(screen.getByLabelText('Source IP'), { target: { value: '192.0.2.10' } })
    fireEvent.change(screen.getByLabelText('Source IP'), { target: { value: '192.0.2.20' } })
    await advance(10000)
    expect(fetchLogs).toHaveBeenCalledTimes(1)
    // Keeping the first request alive avoids assuming abort cancels PostgreSQL work.
    expect(fetchLogs.mock.calls[0][1].signal.aborted).toBe(false)
    await act(async () => resolve(pageResult('stale-row')))
    expect(fetchLogs).toHaveBeenCalledTimes(2)
    expect(fetchLogs.mock.lastCall[0].src_ip).toBe('192.0.2.20')
    expect(screen.getByTestId('rows')).toHaveTextContent('current-row')
    expect(screen.getByTestId('rows')).not.toHaveTextContent('stale-row')
  })

  it('aborts an outstanding browser request on unmount', async () => {
    fetchLogs.mockImplementation(() => new Promise(() => {}))
    const { unmount } = render(<LogStream />)
    const signal = fetchLogs.mock.calls[0][1].signal
    unmount()
    expect(signal.aborted).toBe(true)
  })
})

describe('count-free cursor browsing', () => {
  it('explains DNS query logging only for an empty DNS-only view', async () => {
    localStorage.setItem('unifi-log-insight:log-types', 'dns')
    fetchLogs.mockResolvedValue(pageResult(null, { data: [], has_more: false }))
    render(<LogStream />); await flush()
    expect(screen.getByRole('complementary', { name: 'DNS logging help' })).toHaveTextContent('Firewall flows on port 53 do not contain the queried domain names')
    expect(screen.getByRole('link', { name: 'DNS logging guide' })).toHaveAttribute('href', expect.stringContaining('docs/dns-logging.md'))
    fireEvent.change(screen.getByLabelText('Source IP'), { target: { value: '192.0.2.10' } }); await flush()
    expect(screen.queryByRole('complementary', { name: 'DNS logging help' })).toBeNull()
  })

  it.each(['firewall,dns', 'firewall', ''])('does not show DNS configuration guidance for empty %s views', async logType => {
    localStorage.setItem('unifi-log-insight:log-types', logType)
    fetchLogs.mockResolvedValue(pageResult(null, { data: [], has_more: false }))
    render(<LogStream />); await flush()
    expect(screen.queryByRole('complementary', { name: 'DNS logging help' })).toBeNull()
  })

  it('does not show DNS configuration guidance when records exist or the query failed', async () => {
    localStorage.setItem('unifi-log-insight:log-types', 'dns')
    render(<LogStream />); await flush()
    expect(screen.queryByRole('complementary', { name: 'DNS logging help' })).toBeNull()
    fetchLogs.mockRejectedValue(new Error('temporarily unavailable'))
    fireEvent.click(screen.getByRole('button', { name: /Refresh/ })); await flush()
    expect(screen.getByRole('alert')).toHaveTextContent('Could not load events')
    expect(screen.queryByRole('complementary', { name: 'DNS logging help' })).toBeNull()
  })

  it('offers larger pages and discards the old cursor and count when page size changes', async () => {
    render(<LogStream />); await flush()
    const size = screen.getByRole('combobox', { name: 'Rows per page' })
    expect([...size.options].map(option => option.value)).toEqual(['50', '100', '200', '500', '1000'])
    fireEvent.click(screen.getByRole('button', { name: 'Next page' })); await flush()
    expect(fetchLogs.mock.lastCall[0]).toMatchObject({ page: 2, cursor: 'next-token', per_page: 50 })
    fireEvent.change(size, { target: { value: '1000' } }); await flush()
    expect(fetchLogs.mock.lastCall[0]).toMatchObject({ page: 1, cursor: null, per_page: 1000, count_mode: 'none' })
    expect(screen.getByText('Page 1')).toBeTruthy()
    expect(localStorage.getItem('unifi-log-insight:rows-per-page')).toBe('1000')
    fireEvent.change(screen.getByLabelText('Source IP'), { target: { value: '192.0.2.10' } }); await flush()
    expect(fetchLogs.mock.lastCall[0]).toMatchObject({ src_ip: '192.0.2.10', per_page: 1000, cursor: null })
  })

  it('restores a supported page size on remount and preserves pause while changing it', async () => {
    localStorage.setItem('unifi-log-insight:rows-per-page', '500')
    const { unmount } = render(<LogStream />); await flush()
    expect(fetchLogs.mock.lastCall[0].per_page).toBe(500)
    fireEvent.click(screen.getByRole('button', { name: 'Live' }))
    fireEvent.change(screen.getByRole('combobox', { name: 'Rows per page' }), { target: { value: '200' } }); await flush()
    expect(fetchLogs.mock.lastCall[0].per_page).toBe(200)
    expect(screen.getByRole('button', { name: 'Paused' })).toBeTruthy()
    const calls = fetchLogs.mock.calls.length
    await advance(10000)
    expect(fetchLogs).toHaveBeenCalledTimes(calls)
    unmount()
    render(<LogStream />); await flush()
    expect(fetchLogs.mock.lastCall[0].per_page).toBe(200)
  })

  it.each(['999999', 'NaN', '-1', '0', '1000.5', '75'])('ignores invalid persisted page size %s', async value => {
    localStorage.setItem('unifi-log-insight:rows-per-page', value)
    render(<LogStream />); await flush()
    expect(fetchLogs.mock.lastCall[0].per_page).toBe(50)
    expect(screen.getByRole('combobox', { name: 'Rows per page' })).toHaveValue('50')
  })

  it('uses next and previous page tokens, freezes recounts, and refreshes to the newest page', async () => {
    fetchLogs.mockImplementation(async params => params.cursor === 'next-token'
      ? pageResult('second-row', { page_cursor: 'next-token', next_cursor: null, has_more: false })
      : pageResult('first-row', params.count_mode === 'exact' ? { total: 2, pages: 1 } : {}))
    render(<LogStream />); await flush()
    expect(screen.getByText('1–1 · total not counted')).toBeTruthy()
    expect(screen.queryByText('No results')).toBeNull()
    expect(screen.queryByRole('button', { name: 'Last page' })).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Next page' })); await flush()
    expect(fetchLogs.mock.lastCall[0]).toMatchObject({ cursor: 'next-token', page: 2, count_mode: 'none' })
    expect(screen.getByTestId('rows')).toHaveTextContent('second-row')
    expect(screen.getByRole('button', { name: 'Next page' })).toBeDisabled()
    await advance(10000)
    expect(fetchLogs).toHaveBeenCalledTimes(2)
    fireEvent.click(screen.getByRole('button', { name: 'Previous page' })); await flush()
    expect(fetchLogs.mock.lastCall[0]).toMatchObject({ cursor: 'start-token', page: 1 })
    fireEvent.click(screen.getByRole('button', { name: 'Count matching events' })); await flush()
    expect(fetchLogs.mock.lastCall[0]).toMatchObject({ cursor: 'start-token', count_mode: 'exact' })
    expect(screen.getByText('1–2 of 2')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: /Refresh/ })); await flush()
    expect(fetchLogs.mock.lastCall[0]).toMatchObject({ cursor: null, page: 1, count_mode: 'none' })
  })

  it('discards old cursors on a filter change and distinguishes unknown from a counted zero', async () => {
    fetchLogs.mockImplementation(async params => pageResult('first-row', params.src_ip
      ? { data: [], total: params.count_mode === 'exact' ? 0 : null, has_more: false, next_cursor: null } : {}))
    render(<LogStream />); await flush()
    fireEvent.click(screen.getByRole('button', { name: 'Next page' })); await flush()
    fireEvent.change(screen.getByLabelText('Source IP'), { target: { value: '192.0.2.10' } }); await flush()
    expect(fetchLogs.mock.lastCall[0]).toMatchObject({ cursor: null, page: 1, src_ip: '192.0.2.10' })
    expect(screen.getByText('No events on this page · total not counted')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Count matching events' })); await flush()
    expect(screen.getByText('No results')).toBeTruthy()
  })
})
