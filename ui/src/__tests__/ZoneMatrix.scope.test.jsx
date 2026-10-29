import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import ZoneMatrix from '../components/ZoneMatrix'
import { fetchZoneMatrix } from '../api'

vi.mock('../api', () => ({ fetchZoneMatrix: vi.fn() }))
beforeEach(() => {
  vi.clearAllMocks(); sessionStorage.clear()
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' })
})
afterEach(cleanup)

it('keeps unnamed-interface counts visible without offering a broader cross-filter', async () => {
  fetchZoneMatrix.mockResolvedValue({ interfaces: ['', 'br20', 'br30'], labels: {}, cells: [
    { interface_in: 'br20', interface_out: '', total: 7, allow_count: 2, block_count: 5, unique_pairs: 1 },
    { interface_in: 'br20', interface_out: 'br30', total: 9, allow_count: 9, block_count: 0, unique_pairs: 1 },
  ] })
  const select = vi.fn()
  render(<ZoneMatrix filters={{ time_range: '1h' }} onCellClick={select} />)
  const unnamed = await screen.findByRole('button', { name: '7', exact: true })
  expect(unnamed.disabled).toBe(true)
  expect(screen.getByText('Cells with an unnamed interface show event counts but cannot be selected as flow filters.')).toBeTruthy()
  fireEvent.click(unnamed)
  expect(select).not.toHaveBeenCalled()
  fireEvent.click(screen.getByRole('button', { name: '9', exact: true }))
  expect(select).toHaveBeenCalledWith({ interface_in: 'br20', interface_out: 'br30', in_label: 'br20', out_label: 'br30' })
})
