import { useState } from 'react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import FieldFilters from '../components/FieldFilters'
import { createSavedView, deleteSavedView, fetchSavedViews } from '../api'

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
  fetchSavedViews.mockResolvedValue({ views: [] })
  createSavedView.mockResolvedValue({ id: 1 })
  deleteSavedView.mockResolvedValue({ success: true })
})

describe('FieldFilters controlled drafts and saved views', () => {
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
