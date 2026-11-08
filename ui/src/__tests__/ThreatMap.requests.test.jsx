import { act, cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import ThreatMap from '../components/ThreatMap'
import { fetchThreatGeo } from '../api'

const maps = vi.hoisted(() => [])
vi.mock('maplibre-gl', () => ({ default: {
  setWorkerUrl() {}, NavigationControl: class {}, AttributionControl: class {},
  Popup: class { remove() {} },
  Map: class {
    constructor(options) { this.options = options; this.source = null; this.layers = new Set(); this.handlers = {}; maps.push(this) }
    on(event, handler) { if (typeof handler === 'function') this.handlers[event] = handler } once() {} off() {} addControl() {} remove() {} triggerRepaint() {}
    isStyleLoaded() { return true }
    getSource() { return this.source }
    addSource(_id, value) { this.source = value }
    removeSource() { this.source = null }
    getLayer(id) { return this.layers.has(id) }
    addLayer(layer) { this.layers.add(layer.id) }
    removeLayer(id) { this.layers.delete(id) }
    setLayoutProperty() {}
    getCenter() { return { lng: 25, lat: 35 } }
    getZoom() { return 4 }
    getBearing() { return 10 }
    getPitch() { return 20 }
  },
} }))
vi.mock('../api', () => ({ fetchThreatGeo: vi.fn() }))
vi.mock('../components/ThreatSidebar', () => ({ default: () => null }))
vi.mock('../components/DateRangePicker', () => ({ default: () => null }))
const data = { type: 'FeatureCollection', features: [{ type: 'Feature', geometry: { type: 'Point', coordinates: [0, 0] }, properties: { count: 1, max_score: 80 } }], summary: { total_points: 1, total_events: 1 } }
const advance = async ms => { await act(async () => { await vi.advanceTimersByTimeAsync(ms) }) }
const flush = async () => { await act(async () => { await Promise.resolve() }) }
const visible = value => {
  Object.defineProperty(document, 'visibilityState', { configurable: true, value })
  fireEvent(document, new Event('visibilitychange'))
}
beforeEach(() => { vi.clearAllMocks(); vi.useFakeTimers(); localStorage.clear(); sessionStorage.clear(); maps.length = 0; visible('visible') })
afterEach(() => { cleanup(); vi.useRealTimers() })

describe('Threat Map queries', () => {
  it('waits for a slow query and does not query hidden tabs', async () => {
    let finish
    fetchThreatGeo.mockImplementationOnce(() => new Promise(resolve => { finish = resolve })).mockResolvedValue(data)
    render(<ThreatMap />)
    await advance(180000)
    expect(fetchThreatGeo).toHaveBeenCalledTimes(1)
    await act(async () => finish(data))
    visible('hidden'); await advance(180000)
    expect(fetchThreatGeo).toHaveBeenCalledTimes(1)
    visible('visible'); await flush()
    expect(fetchThreatGeo).toHaveBeenCalledTimes(2)
  })

  it('clears old-scope points and exposes errors/retry outside the mobile toggle', async () => {
    fetchThreatGeo.mockResolvedValueOnce(data).mockRejectedValueOnce(new Error('timeout')).mockResolvedValue(data)
    render(<ThreatMap />); await flush()
    expect(maps[0].source).not.toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Blocked Outbound' })); await flush()
    expect(maps[0].source).toBeNull()
    expect(screen.getByRole('alert')).toHaveTextContent('Results are unavailable')
    const retry = screen.getByRole('button', { name: 'Retry' })
    expect(retry.parentElement.closest('button')).toBeNull()
    expect(retry.closest('.lg\\:hidden')).toBeNull()
    fireEvent.click(retry); await flush()
    expect(maps[0].source).not.toBeNull()
    expect(screen.queryByRole('alert')).toBeNull()
  })
})

  it('restores map filters, custom dates, display mode and camera after reopening', async () => {
    fetchThreatGeo.mockResolvedValue(data)
    localStorage.setItem('unifi-log-insight:map-date-window', JSON.stringify({ from: '2026-01-01T10:00:00Z', to: '2026-01-01T11:00:00Z' }))
    const first = render(<ThreatMap />); await flush()
    fireEvent.click(screen.getByRole('button', { name: 'Blocked Outbound' }))
    fireEvent.click(screen.getByRole('button', { name: 'Clusters' }))
    fireEvent.click(screen.getByRole('button', { name: /Filters/ }))
    maps[0].handlers.moveend()
    await flush(); first.unmount(); sessionStorage.clear(); fetchThreatGeo.mockClear()
    render(<ThreatMap />); await flush()
    expect(fetchThreatGeo.mock.calls[0][0]).toEqual({ time_range: null, time_from: '2026-01-01T10:00:00Z', time_to: '2026-01-01T11:00:00Z', mode: 'blocked_outbound' })
    expect(screen.getByRole('button', { name: 'Clusters' })).toHaveAttribute('aria-pressed', 'true')
    expect(screen.getByRole('button', { name: /Filters/ })).toHaveAttribute('aria-expanded', 'true')
    expect(maps[1].options).toMatchObject({ center: [25, 35], zoom: 4, bearing: 10, pitch: 20 })
    fireEvent.click(screen.getByRole('button', { name: '24h' })); await flush()
    expect(fetchThreatGeo.mock.lastCall[0]).toMatchObject({ time_range: '24h', time_from: null, time_to: null })
  })

  it('discards invalid map preferences before requesting data', async () => {
    fetchThreatGeo.mockResolvedValue(data)
    localStorage.setItem('unifi-log-insight:map-mode', JSON.stringify(['blocked_outbound']))
    localStorage.setItem('unifi-log-insight:map-date-window', JSON.stringify({ from: 'not a date', to: null }))
    localStorage.setItem('unifi-log-insight:map-camera', JSON.stringify({ center: [900, 900], zoom: 999 }))
    render(<ThreatMap />); await flush()
    expect(fetchThreatGeo.mock.calls[0][0]).toMatchObject({ time_range: '24h', time_from: null, time_to: null, mode: 'threats' })
    expect(maps[0].options).toMatchObject({ center: [20, 20], zoom: 1.5 })
  })
