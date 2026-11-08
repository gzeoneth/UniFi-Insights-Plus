import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import RetentionPolicy from '../components/RetentionPolicy'
import { apiFetch } from '../api'

vi.mock('../api', () => ({ apiFetch: vi.fn() }))

const defaults = () => ({
  enabled: false,
  type_days: {},
  security_days: null,
  firewall_allow_days: null,
  summaries_enabled: false,
  summary_group_by_rule: false,
  summary_retention_days: 365,
  archives_enabled: false,
  archive_directory: '/data/archives',
  archive_max_bytes: 20 * 1024 ** 3,
  archive_max_files: 100000,
  archive_min_free_bytes: 1024 ** 3,
  batch_size: 1000,
  max_batches: 1000,
})

const response = policy => ({
  policy,
  inherited_general_days: 120,
  inherited_dns_days: 30,
  archive_deletion_enabled: false,
})

beforeEach(() => vi.resetAllMocks())

describe('RetentionPolicy', () => {
  it('shows inherited defaults with every feature disabled and performs no writes', async () => {
    apiFetch.mockResolvedValue(response(defaults()))
    render(<RetentionPolicy />)

    expect(await screen.findByRole('checkbox', { name: 'Enable retention overrides' })).not.toBeChecked()
    expect(screen.getByRole('checkbox', { name: 'Keep daily summaries' })).not.toBeChecked()
    expect(screen.getByRole('checkbox', { name: 'Archive expired records before deletion' })).not.toBeChecked()
    expect(screen.getByLabelText('Security events: days')).toHaveValue(null)
    expect(screen.getByLabelText('Allowed firewall events: days')).toHaveValue(null)
    expect(screen.getByLabelText('dns retention days')).toHaveValue(null)
    expect(screen.getByText(/general 120 days; DNS 30 days/)).toBeInTheDocument()
    expect(screen.getByText(/does not immediately delete data/)).toBeInTheDocument()
    expect(apiFetch).toHaveBeenCalledExactlyOnceWith('/api/config/retention/policy')
  })

  it('saves edited fields while preserving unrelated and hidden policy settings', async () => {
    const saved = {
      ...defaults(), enabled: true, security_days: 365, firewall_allow_days: 45,
      type_days: { dns: 14, system: 90 }, summaries_enabled: true,
      summary_group_by_rule: true, archives_enabled: true,
      archive_max_files: 4321, archive_min_free_bytes: 4 * 1024 ** 3,
      batch_size: 250, max_batches: 75,
    }
    apiFetch.mockImplementation((url, options) => Promise.resolve(response(
      options?.method === 'PUT' ? JSON.parse(options.body) : saved,
    )))
    render(<RetentionPolicy />)
    await screen.findByRole('checkbox', { name: 'Enable retention overrides' })

    fireEvent.change(screen.getByLabelText('Security events: days'), { target: { value: '540' } })
    fireEvent.change(screen.getByLabelText('dns retention days'), { target: { value: '' } })
    fireEvent.change(screen.getByLabelText('Archive budget GiB'), { target: { value: '40' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save policy' }))

    expect(await screen.findByRole('status')).toHaveTextContent('Policy saved.')
    const [, request] = apiFetch.mock.calls.find(([, options]) => options?.method === 'PUT')
    expect(JSON.parse(request.body)).toEqual({
      ...saved, security_days: 540, type_days: { system: 90 }, archive_max_bytes: 40 * 1024 ** 3,
    })
    expect(request.headers).toEqual({ 'Content-Type': 'application/json' })
    expect(saved.type_days).toEqual({ dns: 14, system: 90 })
    expect(apiFetch.mock.calls.every(([url]) => url === '/api/config/retention/policy')).toBe(true)
    expect(screen.getByLabelText('Security events: days')).toHaveValue(540)

    fireEvent.change(screen.getByLabelText('Security events: days'), { target: { value: '600' } })
    expect(screen.queryByRole('status')).not.toBeInTheDocument()
  })

  it('shows a server validation error, keeps edits, and permits a successful retry', async () => {
    apiFetch.mockResolvedValueOnce(response(defaults()))
      .mockRejectedValueOnce(new Error('security_days must exceed firewall_allow_days'))
      .mockImplementationOnce((url, options) => Promise.resolve(response(JSON.parse(options.body))))
    render(<RetentionPolicy />)
    await screen.findByRole('checkbox', { name: 'Enable retention overrides' })
    fireEvent.click(screen.getByRole('checkbox', { name: 'Enable retention overrides' }))
    fireEvent.change(screen.getByLabelText('Security events: days'), { target: { value: '10' } })
    fireEvent.change(screen.getByLabelText('Allowed firewall events: days'), { target: { value: '30' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save policy' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('security_days must exceed firewall_allow_days')
    expect(screen.queryByRole('status')).not.toBeInTheDocument()
    expect(screen.getByLabelText('Security events: days')).toHaveValue(10)
    expect(screen.getByRole('button', { name: 'Save policy' })).not.toBeDisabled()

    fireEvent.change(screen.getByLabelText('Security events: days'), { target: { value: '180' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save policy' }))
    expect(await screen.findByRole('status')).toHaveTextContent('Policy saved.')
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    expect(apiFetch).toHaveBeenCalledTimes(3)
  })

  it('does not permit a duplicate save while the first request is pending', async () => {
    let finishSave
    apiFetch.mockResolvedValueOnce(response(defaults()))
      .mockImplementationOnce(() => new Promise(resolve => { finishSave = resolve }))
    render(<RetentionPolicy />)
    const save = await screen.findByRole('button', { name: 'Save policy' })
    fireEvent.click(save)
    expect(save).toBeDisabled()
    fireEvent.click(save)
    expect(apiFetch).toHaveBeenCalledTimes(2)
    finishSave(response(defaults()))
    await screen.findByRole('status')
    expect(save).not.toBeDisabled()
  })

  it('reports policy load failure without inventing a default editable policy', async () => {
    apiFetch.mockRejectedValue(new Error('Saved retention policy is invalid'))
    render(<RetentionPolicy />)
    expect(await screen.findByRole('alert')).toHaveTextContent('Saved retention policy is invalid')
    expect(screen.queryByRole('button', { name: 'Save policy' })).not.toBeInTheDocument()
    expect(screen.queryByRole('checkbox')).not.toBeInTheDocument()
  })

  it('requests the chosen UTC summary window and reports truncation', async () => {
    apiFetch.mockResolvedValueOnce(response(defaults())).mockResolvedValueOnce({
      summaries: [{ day: '2026-10-01', log_type: 'firewall', rule_action: 'allow',
        source: 'syslog', event_source: 'unifi_ips', grouped_by_rule: true,
        rule_name: 'IDS rule', event_count: 8 }],
      truncated: true,
    })
    render(<RetentionPolicy />)
    await screen.findByRole('button', { name: 'Save policy' })
    fireEvent.change(screen.getByLabelText('Summary start date'), { target: { value: '2026-10-01' } })
    fireEvent.change(screen.getByLabelText('Summary end date'), { target: { value: '2026-10-07' } })
    fireEvent.click(screen.getByRole('button', { name: 'Load summaries' }))

    expect(await screen.findByText('IDS rule')).toBeInTheDocument()
    expect(apiFetch).toHaveBeenLastCalledWith('/api/retention/summaries?start=2026-10-01&end=2026-10-07')
    expect(screen.getByText('unifi_ips')).toBeInTheDocument()
    expect(screen.getByText('8')).toBeInTheDocument()
    expect(screen.getByText(/Results truncated/)).toBeInTheDocument()
    expect(screen.getByText(/do not include current raw records/)).toBeInTheDocument()
    await waitFor(() => expect(screen.getByRole('button', { name: 'Load summaries' })).not.toBeDisabled())
  })
})
