import { act, cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import FilterBar from '../components/FilterBar'

vi.mock('../api', () => ({
  fetchServices: () => Promise.resolve({ services: [] }),
  fetchInterfaces: () => Promise.resolve({ interfaces: [] }),
  fetchProtocols: () => Promise.resolve({ protocols: [] }),
}))
vi.mock('../components/DateRangePicker', () => ({ default: () => null }))
const props = { filters: { time_range: '24h' }, onChange: () => {} }
const flush = async () => { await act(async () => { await Promise.resolve() }) }
beforeEach(() => { localStorage.clear(); sessionStorage.clear() })
afterEach(cleanup)
it('remembers the filter panel expansion across browser sessions', async () => {
  const first = render(<FilterBar {...props} />); await flush()
  const toggle = screen.getByRole('button', { name: 'Filters' })
  expect(toggle).toHaveAttribute('aria-expanded', 'false')
  fireEvent.click(toggle)
  first.unmount(); sessionStorage.clear()
  render(<FilterBar {...props} />); await flush()
  expect(screen.getByRole('button', { name: 'Filters' })).toHaveAttribute('aria-expanded', 'true')
})
