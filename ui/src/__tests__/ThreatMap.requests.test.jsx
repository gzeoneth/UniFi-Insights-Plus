import { act, cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import ThreatMap from '../components/ThreatMap'
import { fetchThreatGeo } from '../api'

const maps = vi.hoisted(() => [])
vi.mock('maplibre-gl', () => ({ default: {
  setWorkerUrl() {}, NavigationControl: class {}, AttributionControl: class {},
  Popup: class { remove() {} },
  Map: class {
    constructor() { this.source = null; this.layers = new Set(); maps.push(this) }
    on() {} once() {} off() {} addControl() {} remove() {} triggerRepaint() {}
    isStyleLoaded() { return true }
    getSource() { return this.source }
    addSource(_id, value) { this.source = value }
    removeSource() { this.source = null }
    getLayer(id) { return this.layers.has(id) }
    addLayer(layer) { this.layers.add(layer.id) }
    removeLayer(id) { this.layers.delete(id) }
    setLayoutProperty() {}
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
beforeEach(() => { vi.clearAllMocks(); vi.useFakeTimers(); localStorage.clear(); maps.length = 0; visible('visible') })
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
