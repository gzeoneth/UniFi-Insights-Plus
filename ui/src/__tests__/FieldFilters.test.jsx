import { useState } from 'react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import FieldFilters, { readFilterRules, isValidFilterRules } from '../components/FieldFilters'
import { createSavedView, deleteSavedView, fetchSavedViews } from '../api'
import { LOG_PRESETS, buildLogPresetFilters } from '../lib/logPresets'

vi.mock('../api', () => ({ createSavedView: vi.fn(), deleteSavedView: vi.fn(), fetchSavedViews: vi.fn() }))

const initial = { time_range: '24h', rule_name: 'Example rule', protocol: 'tcp',
  filter_rules: null, page: 4, per_page: 100, sort: 'timestamp', order: 'desc' }
const rules = [{ field: 'ip', operator: 'exclude', value: '10.0.0.0/24' }]

function Controlled({ change, filters = initial }) {
  const [value, setValue] = useState(filters)
  return <FieldFilters filters={value} onChange={next => { change(next); setValue(next) }} />
}

beforeEach(() => {
  vi.clearAllMocks()
  localStorage.clear(); sessionStorage.clear()
  fetchSavedViews.mockResolvedValue({ views: [] })
  createSavedView.mockResolvedValue({ id: 1 })
  deleteSavedView.mockResolvedValue({ success: true })
})

describe('FieldFilters controlled drafts and saved views', () => {
  it('remembers the saved-view selection only while its filter scope still matches', async () => {
    const saved = { time_range: '7d', src_ip: '192.0.2.10', filter_rules: rules }
    fetchSavedViews.mockResolvedValue({ views: [{ id: 8, name: 'Example hosts', filters: { ...saved, view_type: 'logs' } }] })
    const change = vi.fn()
    const first = render(<Controlled change={change} />)
    await screen.findByRole('option', { name: 'Example hosts' })
    fireEvent.change(screen.getByLabelText('Saved log view'), { target: { value: '8' } })
    const applied = change.mock.lastCall[0]
    expect(screen.getByLabelText('Saved log view').value).toBe('8')
    first.unmount(); sessionStorage.clear()
    const beforeOtherView = localStorage.getItem('unifi-log-insight:log-view-selection')
    const other = render(<FieldFilters filters={initial} onChange={() => {}} selectionStorageKey="unifi-log-insight:rule-usage-view-selection" />)
    await screen.findByRole('option', { name: 'Example hosts' })
    other.unmount()
    expect(localStorage.getItem('unifi-log-insight:log-view-selection')).toBe(beforeOtherView)
    const restored = render(<Controlled change={change} filters={applied} />)
    await screen.findByRole('option', { name: 'Example hosts' })
    expect(screen.getByLabelText('Saved log view').value).toBe('8')
    restored.unmount()
    render(<Controlled change={change} filters={{ ...applied, dst_ip: '203.0.113.20' }} />)
    await screen.findByRole('option', { name: 'Example hosts' })
    expect(screen.getByLabelText('Saved log view').value).toBe('')
    expect(screen.queryByRole('button', { name: 'Delete saved view' })).toBeNull()
    expect(JSON.parse(localStorage.getItem('unifi-log-insight:log-view-selection')).selected).toBe('')
  })

  it('remembers a built-in view badge without reapplying its filters on reload', async () => {
    let applied
    const presetSelected = vi.fn()
    function Presets({ initialFilters = initial }) {
      const [filters, setFilters] = useState(initialFilters)
      return <FieldFilters filters={filters} onChange={setFilters} presets={LOG_PRESETS} onPresetSelect={preset => {
        presetSelected()
        applied = buildLogPresetFilters(preset, filters, initial)
        setFilters(applied)
        return applied
      }} />
    }
    const first = render(<Presets />)
    fireEvent.change(screen.getByLabelText('Log view'), { target: { value: 'builtin:blocks' } })
    expect(screen.getByLabelText('Selected log view scope')).toBeTruthy()
    first.unmount(); sessionStorage.clear()
    render(<Presets initialFilters={applied} />)
    expect(screen.getByLabelText('Log view').value).toBe('builtin:blocks')
    expect(screen.getByLabelText('Selected log view scope')).toBeTruthy()
    expect(presetSelected).toHaveBeenCalledOnce()
    await waitFor(() => expect(fetchSavedViews).toHaveBeenCalledTimes(2))
  })

  it('rejects malformed persisted rules and accepts bounded exact-field rules', () => {
    for (const invalid of [[null], [{ field: 'ip', operator: 'exclude', value: {} }],
      [{ field: 'unknown', operator: 'include', value: 'example' }],
      [{ field: 'ip', operator: 'ignore', value: '192.0.2.1' }],
      [{ field: 'ip', operator: 'exclude', value: ' ' }],
      [{ field: 'hostname', operator: 'include', value: 'x'.repeat(1025) }],
      [{ field: 'ip', operator: 'missing', token: 'not-a-setting' }],
      Array.from({ length: 16 }, () => ({ field: 'hostname', operator: 'include', value: 'x'.repeat(1024) })),
      Array.from({ length: 25 }, () => ({ field: 'ip', operator: 'present' })), '{broken']) {
      expect(readFilterRules(invalid)).toEqual([])
    }
    const exact = [{ field: 'rule_name_exact', operator: 'include', value: 'Example, exact' }, { field: 'hostname', operator: 'missing' }]
    expect(isValidFilterRules(exact)).toBe(true)
    expect(readFilterRules(JSON.stringify(exact))).toEqual(exact)
  })
  it('keeps edits local until Apply and resets pagination without losing basic filters', async () => {
    const change = vi.fn()
    render(<Controlled change={change} />)
    fireEvent.click(screen.getByRole('button', { name: 'Add condition' }))
    expect(screen.getByRole('button', { name: 'Apply filters' }).disabled).toBe(true)
    fireEvent.change(screen.getByLabelText('Value 1'), { target: { value: '10.0.0.0/24' } })
    expect(change).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'Apply filters' }))
    expect(change).toHaveBeenCalledWith({ ...initial, filter_rules: JSON.stringify(rules), page: 1 })
    await waitFor(() => expect(fetchSavedViews).toHaveBeenCalledOnce())
  })

  it('Save persists the edited draft and basic filters, then applies after server success', async () => {
    const change = vi.fn()
    let resolveSave
    createSavedView.mockImplementationOnce(() => new Promise(resolve => { resolveSave = resolve }))
    render(<Controlled change={change} />)
    fireEvent.click(screen.getByRole('button', { name: 'Add condition' }))
    fireEvent.change(screen.getByLabelText('Value 1'), { target: { value: '10.0.0.0/24' } })
    fireEvent.change(screen.getByLabelText('New view name'), { target: { value: 'Exclude lab' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save view' }))
    expect(createSavedView).toHaveBeenCalledWith('Exclude lab', {
      time_range: '24h', rule_name: 'Example rule', protocol: 'tcp', view_type: 'logs', filter_rules: rules,
    })
    expect(change).not.toHaveBeenCalled()
    resolveSave({ id: 1 })
    await waitFor(() => expect(change).toHaveBeenCalledOnce())
    expect(screen.getByLabelText('New view name').value).toBe('')
  })

  it('saves a custom interval without injecting a conflicting relative range', async () => {
    const change = vi.fn()
    render(<Controlled change={change} filters={{ ...initial,
      time_from: '2026-01-10T10:00:00Z', time_to: '2026-01-10T11:00:00Z' }} />)
    fireEvent.change(screen.getByLabelText('New view name'), { target: { value: 'Example interval' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save view' }))
    await waitFor(() => expect(createSavedView).toHaveBeenCalledOnce())
    expect(createSavedView.mock.lastCall[1]).toMatchObject({ time_range: null,
      time_from: '2026-01-10T10:00:00Z', time_to: '2026-01-10T11:00:00Z' })
    expect(change.mock.lastCall[0].time_range).toBeNull()
    expect(JSON.parse(localStorage.getItem('unifi-log-insight:log-view-selection')).selected).toBe('1')
  })

  it('restores a legacy custom-date view and keeps its matching selection', async () => {
    fetchSavedViews.mockResolvedValue({ views: [{ id: 9, name: 'Example custom dates', filters: {
      view_type: 'logs', time_range: '24h', time_from: '2026-01-10T10:00:00Z',
      time_to: '2026-01-10T11:00:00Z', filter_rules: [],
    } }] })
    const change = vi.fn()
    const first = render(<Controlled change={change} />)
    await screen.findByRole('option', { name: 'Example custom dates' })
    fireEvent.change(screen.getByLabelText('Saved log view'), { target: { value: '9' } })
    const applied = change.mock.lastCall[0]
    expect(applied.time_range).toBeNull()
    expect(screen.getByLabelText('Saved log view').value).toBe('9')
    first.unmount(); sessionStorage.clear()
    render(<Controlled change={change} filters={applied} />)
    await screen.findByRole('option', { name: 'Example custom dates' })
    expect(screen.getByLabelText('Saved log view').value).toBe('9')
  })

  it.each([rules, JSON.stringify(rules)])('loads array or JSON rules with basic filters intact', async stored => {
    const change = vi.fn()
    fetchSavedViews.mockResolvedValue({ views: [
      { id: 1, name: 'Saved exclusions', filters: { view_type: 'logs', filter_rules: stored, src_ip: '10.0.0.1', time_range: '7d' } },
      { id: 2, name: 'Flow view', filters: { dims: ['src_ip', 'dst_ip', 'service'] } },
    ] })
    render(<Controlled change={change} />)
    await screen.findByRole('option', { name: 'Saved exclusions' })
    expect(screen.queryByRole('option', { name: 'Flow view' })).toBeNull()
    fireEvent.change(screen.getByLabelText('Saved log view'), { target: { value: '1' } })
    expect(change).toHaveBeenLastCalledWith({ filter_rules: JSON.stringify(rules), src_ip: '10.0.0.1', time_range: '7d', page: 1, per_page: 100 })
    expect(screen.getByLabelText('Value 1').value).toBe('10.0.0.0/24')
  })

  it('preserves the draft after a failed server save', async () => {
    createSavedView.mockRejectedValueOnce(new Error('View name already exists'))
    const change = vi.fn()
    render(<Controlled change={change} filters={{ ...initial, filter_rules: JSON.stringify(rules) }} />)
    fireEvent.change(screen.getByLabelText('New view name'), { target: { value: 'Duplicate' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save view' }))
    await screen.findByText('View name already exists')
    expect(screen.getByLabelText('Value 1').value).toBe('10.0.0.0/24')
    expect(change).not.toHaveBeenCalled()
  })
})
