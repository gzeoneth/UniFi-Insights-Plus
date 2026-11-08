import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import IPCell from '../components/IPCell'

describe('IPCell identity evidence', () => {
  it('keeps the address visible and labels an inventory name as unverified', () => {
    render(<IPCell ip="192.0.2.10" deviceName="Player" />)
    expect(screen.getByText('192.0.2.10')).toBeTruthy()
    expect(screen.getByText('Player').title).toContain('has not been independently verified')
  })

  it('describes a configured WAN identity without claiming endpoint verification', () => {
    render(<IPCell ip="203.0.113.7" deviceName="Gateway" identitySource="wan_configuration" />)
    expect(screen.getByText('Gateway').title).toContain('current WAN configuration')
  })
})
