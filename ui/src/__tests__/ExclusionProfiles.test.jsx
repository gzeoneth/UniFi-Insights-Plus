import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import ExclusionProfiles, { EXCLUSION_DEFAULT_KEY, EXCLUSION_SELECTION_KEY, ExclusionCounts, ExclusionProfileProvider, ruleExclusionGroup, useExclusionProfile, validExclusionGroups } from '../components/ExclusionProfiles'
import RuleUsage from '../components/RuleUsage'
import SecuritySummary from '../components/SecuritySummary'
import { apiFetch, createSavedView, deleteSavedView, fetchExclusionPreview, fetchSavedViews, fetchSecuritySummary } from '../api'

vi.mock('../api', () => ({ apiFetch: vi.fn(), createSavedView: vi.fn(), deleteSavedView: vi.fn(), fetchExclusionPreview: vi.fn(), fetchSavedViews: vi.fn(), fetchSecuritySummary: vi.fn() }))

const row = { rule_action: 'allow', rule_name: 'RULE,EXAMPLE', rule_desc: 'Example allow', hostname: 'gateway.example.test' }
const groups = [ruleExclusionGroup(row)]
const profile = { id: 7, name: 'Routine events', filters: { view_type: 'exclusions', exclude_groups: groups } }
const preview = { view_counts: { total: 12, visible: 9, hidden: 3 }, examples: [{ ...row, id: 1 }] }

function Probe() {
  const { excludeGroups, openDraft } = useExclusionProfile()
  return <><output data-testid="applied-groups">{excludeGroups || 'none'}</output><button onClick={() => openDraft(row, { time_range: '7d', rule_name: 'Example' })}>Seed rule draft</button></>
}
function Harness({ children }) {
  return <ExclusionProfileProvider><ExclusionProfiles activeTab="logs" /><Probe />{children}</ExclusionProfileProvider>
}

beforeEach(() => {
  vi.clearAllMocks(); localStorage.clear(); sessionStorage.clear()
  fetchSavedViews.mockResolvedValue({ views: [profile, { id: 8, name: 'Other log view', filters: { view_type: 'logs' } }] })
  fetchExclusionPreview.mockResolvedValue(preview)
  apiFetch.mockResolvedValue({ data: [], notice: 'Observed events.', view_counts: preview.view_counts })
  fetchSecuritySummary.mockResolvedValue({ ips_blocked: 1, top_signatures: [] })
})

describe('exclusion profiles', () => {
  it('remembers a previewed unsaved profile and Show all across browser sessions', async () => {
    const first = render(<Harness />)
    fireEvent.click(screen.getByText('Seed rule draft'))
    fireEvent.click(screen.getByRole('button', { name: 'Preview matches' }))
    await screen.findByLabelText('View event counts')
    fireEvent.click(screen.getByRole('button', { name: 'Apply previewed profile' }))
    expect(JSON.parse(localStorage.getItem(EXCLUSION_SELECTION_KEY)).groups).toEqual(groups)
    fireEvent.click(screen.getByLabelText('Show all (ignore profile)'))
    first.unmount(); sessionStorage.clear()
    render(<Harness />)
    await screen.findByRole('option', { name: 'Routine events' })
    expect(screen.getByLabelText('Show all (ignore profile)')).toBeChecked()
    expect(screen.getByTestId('applied-groups')).toHaveTextContent('none')
    fireEvent.click(screen.getByLabelText('Show all (ignore profile)'))
    expect(screen.getByTestId('applied-groups')).toHaveTextContent(JSON.stringify(groups))
  })

  it('reloads saved profiles by ID and leaves deleted definitions unapplied', async () => {
    localStorage.setItem(EXCLUSION_SELECTION_KEY, JSON.stringify({ id: '7' }))
    const first = render(<Harness />)
    await waitFor(() => expect(screen.getByTestId('applied-groups')).toHaveTextContent(JSON.stringify(groups)))
    first.unmount()
    fetchSavedViews.mockResolvedValue({ views: [] })
    render(<Harness />)
    await screen.findByText(/profile is unavailable/)
    expect(screen.getByTestId('applied-groups')).toHaveTextContent('none')
  })

  it('does not apply malformed stored exclusion conditions', async () => {
    localStorage.setItem(EXCLUSION_SELECTION_KEY, JSON.stringify({ name: 'Bad profile', groups: [null] }))
    render(<Harness />)
    await screen.findByRole('option', { name: 'Routine events' })
    expect(screen.getByTestId('applied-groups')).toHaveTextContent('none')
  })

  it('rejects a stored saved ID mixed with unvalidated local groups', async () => {
    localStorage.setItem(EXCLUSION_SELECTION_KEY, JSON.stringify({ id: '7', groups: [null] }))
    render(<Harness />)
    expect(screen.getByTestId('applied-groups')).toHaveTextContent('none')
    await screen.findByRole('option', { name: 'Routine events' })
    expect(screen.getByTestId('applied-groups')).toHaveTextContent('none')
  })

  it('does not display omitted profile counts as zero', () => {
    const { rerender } = render(<ExclusionCounts counts={null} unknown />)
    expect(screen.getByLabelText('View event counts')).toHaveTextContent('visible and hidden totals not counted')
    expect(screen.queryByText(/0 hidden/)).toBeNull()
    rerender(<ExclusionCounts counts={{ total: null, visible: null, hidden: null }} />)
    expect(screen.getByLabelText('View event counts')).toHaveTextContent('Not counted hidden by profile')
    rerender(<ExclusionCounts counts={{ total: 0, visible: 0, hidden: 0 }} />)
    expect(screen.getByLabelText('View event counts')).toHaveTextContent('0 hidden by profile')
  })
  it('requires preview before applying an exact scoped rule and invalidates it after edits', async () => {
    render(<Harness />)
    await screen.findByRole('option', { name: 'Routine events' })
    expect(screen.queryByRole('option', { name: 'Other log view' })).toBeNull()
    fireEvent.click(screen.getByText('Seed rule draft'))
    expect(screen.getByRole('button', { name: 'Apply previewed profile' })).toBeDisabled()
    expect(screen.getByLabelText('Group 1 value 1')).toHaveValue('RULE,EXAMPLE')
    expect(screen.getByText(/last 7d, with the source view’s filters/)).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Preview matches' }))
    await screen.findByLabelText('View event counts')
    expect(fetchExclusionPreview.mock.calls[0][0]).toEqual({ time_range: '7d', rule_name: 'Example', exclude_groups: JSON.stringify(groups) })
    expect(screen.getByRole('button', { name: 'Apply previewed profile' })).toBeEnabled()
    fireEvent.change(screen.getByLabelText('Group 1 value 2'), { target: { value: 'other.example.test' } })
    expect(screen.getByRole('button', { name: 'Apply previewed profile' })).toBeDisabled()
    expect(screen.getByTestId('applied-groups')).toHaveTextContent('none')
  })

  it('ignores a preview that finishes after its draft changed', async () => {
    let finish
    fetchExclusionPreview.mockImplementationOnce(() => new Promise(resolve => { finish = resolve }))
    render(<Harness />)
    fireEvent.click(screen.getByText('Seed rule draft'))
    fireEvent.click(screen.getByRole('button', { name: 'Preview matches' }))
    fireEvent.change(screen.getByLabelText('Group 1 value 1'), { target: { value: 'OTHER-RULE' } })
    await act(async () => finish(preview))
    expect(screen.queryByLabelText('View event counts')).toBeNull()
    expect(screen.getByRole('button', { name: 'Apply previewed profile' })).toBeDisabled()
  })

  it.each(['success', 'failure'])('preserves a user-applied draft after a late initial profile fetch: %s', async outcome => {
    let finish
    localStorage.setItem(EXCLUSION_DEFAULT_KEY, '7')
    fetchSavedViews.mockImplementationOnce(() => new Promise((resolve, reject) => { finish = outcome === 'success' ? resolve : reject }))
    render(<Harness />)
    fireEvent.click(screen.getByText('Seed rule draft'))
    fireEvent.change(screen.getByLabelText('Group 1 value 1'), { target: { value: 'NEW-RULE' } })
    fireEvent.click(screen.getByRole('button', { name: 'Preview matches' }))
    await screen.findByLabelText('View event counts')
    fireEvent.click(screen.getByRole('button', { name: 'Apply previewed profile' }))
    expect(screen.getByTestId('applied-groups')).toHaveTextContent('NEW-RULE')
    await act(async () => finish(outcome === 'success' ? { views: [profile] } : new Error('unavailable')))
    expect(screen.getByTestId('applied-groups')).toHaveTextContent('NEW-RULE')
    expect(screen.queryByText(/Showing all events/)).toBeNull()
  })

  it('loads a browser default, bypasses reversibly, and keeps Security independent', async () => {
    localStorage.setItem(EXCLUSION_DEFAULT_KEY, '7')
    render(<Harness><RuleUsage /><SecuritySummary /></Harness>)
    await screen.findByRole('option', { name: 'Routine events — default in this browser' })
    await waitFor(() => expect(screen.getByTestId('applied-groups')).toHaveTextContent(JSON.stringify(groups)))
    await waitFor(() => expect(apiFetch.mock.calls.some(([url]) => new URL(url, 'https://example.test').searchParams.get('exclude_groups') === JSON.stringify(groups))).toBe(true))
    expect(fetchSecuritySummary.mock.calls.every(([params]) => !('exclude_groups' in params))).toBe(true)
    fireEvent.click(screen.getByLabelText('Show all (ignore profile)'))
    expect(screen.getByTestId('applied-groups')).toHaveTextContent('none')
    await waitFor(() => expect(new URL(apiFetch.mock.lastCall[0], 'https://example.test').searchParams.has('exclude_groups')).toBe(false))
    fireEvent.click(screen.getByLabelText('Show all (ignore profile)'))
    expect(screen.getByTestId('applied-groups')).toHaveTextContent(JSON.stringify(groups))
    await waitFor(() => expect(new URL(apiFetch.mock.lastCall[0], 'https://example.test').searchParams.get('exclude_groups')).toBe(JSON.stringify(groups)))
    expect(localStorage.getItem(EXCLUSION_DEFAULT_KEY)).toBe('7')
  })

  it('loads a saved profile into a draft, applies only after preview, and stores only its ID as default', async () => {
    render(<Harness />)
    await screen.findByRole('option', { name: 'Routine events' })
    fireEvent.change(screen.getByLabelText('Exclusion profile'), { target: { value: '7' } })
    fireEvent.click(screen.getByRole('button', { name: 'Load and preview' }))
    expect(screen.getByTestId('applied-groups')).toHaveTextContent('none')
    fireEvent.click(screen.getByRole('button', { name: 'Preview matches' }))
    await screen.findByLabelText('View event counts')
    fireEvent.click(screen.getByRole('button', { name: 'Apply previewed profile' }))
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(screen.getByTestId('applied-groups')).toHaveTextContent(JSON.stringify(groups))
    fireEvent.click(screen.getByRole('button', { name: 'Make default in this browser' }))
    expect(localStorage.getItem(EXCLUSION_DEFAULT_KEY)).toBe('7')
    expect(createSavedView).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'Delete profile' }))
    await waitFor(() => expect(screen.getByTestId('applied-groups')).toHaveTextContent('none'))
    expect(deleteSavedView).toHaveBeenCalledWith('7')
    expect(localStorage.getItem(EXCLUSION_DEFAULT_KEY)).toBeNull()
  })

  it('saves only reviewed groups and leaves a missing browser default unapplied', async () => {
    localStorage.setItem(EXCLUSION_DEFAULT_KEY, '404')
    render(<Harness />)
    await screen.findByText('The browser default profile is unavailable. Showing all events.')
    expect(screen.getByTestId('applied-groups')).toHaveTextContent('none')
    fireEvent.click(screen.getByText('Seed rule draft'))
    fireEvent.change(screen.getByLabelText('Exclusion profile name'), { target: { value: 'Routine events' } })
    expect(screen.getByRole('button', { name: 'Save as new profile and apply' })).toBeDisabled()
    fireEvent.click(screen.getByRole('button', { name: 'Preview matches' }))
    await screen.findByLabelText('View event counts')
    fireEvent.click(screen.getByRole('button', { name: 'Save as new profile and apply' }))
    await waitFor(() => expect(createSavedView).toHaveBeenCalledWith('Routine events', { view_type: 'exclusions', exclude_groups: groups }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
  })

  it('does not clear a newer selection or browser default after an older profile finishes deleting', async () => {
    let finishDelete
    const secondGroups = [{ conditions: [{ field: 'rule_name_exact', operator: 'include', value: 'SECOND-RULE' }] }]
    const secondProfile = { id: 9, name: 'Second profile', filters: { view_type: 'exclusions', exclude_groups: secondGroups } }
    localStorage.setItem(EXCLUSION_DEFAULT_KEY, '7')
    fetchSavedViews.mockResolvedValue({ views: [profile, secondProfile] })
    deleteSavedView.mockImplementationOnce(() => new Promise(resolve => { finishDelete = resolve }))
    render(<Harness />)
    await screen.findByRole('option', { name: 'Second profile' })
    fireEvent.change(screen.getByLabelText('Exclusion profile'), { target: { value: '7' } })
    fireEvent.click(screen.getByRole('button', { name: 'Delete profile' }))
    fireEvent.change(screen.getByLabelText('Exclusion profile'), { target: { value: '9' } })
    fireEvent.click(screen.getByRole('button', { name: 'Load and preview' }))
    fireEvent.click(screen.getByRole('button', { name: 'Preview matches' }))
    await screen.findByLabelText('View event counts')
    fireEvent.click(screen.getByRole('button', { name: 'Apply previewed profile' }))
    fireEvent.click(screen.getByRole('button', { name: 'Make default in this browser' }))
    await act(async () => finishDelete({ success: true }))
    expect(screen.getByTestId('applied-groups')).toHaveTextContent('SECOND-RULE')
    expect(screen.getByLabelText('Exclusion profile')).toHaveValue('9')
    expect(localStorage.getItem(EXCLUSION_DEFAULT_KEY)).toBe('9')
  })

  it('does not seed broad exclusions from unknown rules, blocks or detections', () => {
    for (const patch of [{ rule_name: null }, { hostname: '' }, { rule_action: 'block' }, { event_source: 'ips' }, { event_source: 'unifi_ips' }, { ips_signature_id: '123' }]) {
      expect(ruleExclusionGroup({ ...row, ...patch })).toBeNull()
    }
    expect(groups[0].conditions).toContainEqual({ field: 'rule_desc_exact', operator: 'include', value: 'Example allow' })
    expect(validExclusionGroups(groups)).toBe(true)
    expect(validExclusionGroups([null])).toBe(false)
    expect(validExclusionGroups(Array(13).fill(groups[0]))).toBe(false)
  })
})
