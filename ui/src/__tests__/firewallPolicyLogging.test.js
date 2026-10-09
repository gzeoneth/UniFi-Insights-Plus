import { describe, it, expect } from 'vitest'
import { isControllablePolicy } from '../lib/firewallPolicyLogging'

const ID = '11111111-2222-4333-8444-555555555555'

describe('isControllablePolicy', () => {
  it('accepts a user-defined, enabled policy with an id', () => {
    expect(isControllablePolicy({ id: ID, enabled: true, metadata: { origin: 'USER_DEFINED' } })).toBe(true)
  })

  it('rejects a policy without an id (#112)', () => {
    expect(isControllablePolicy({ enabled: true, metadata: { origin: 'USER_DEFINED' } })).toBe(false)
    expect(isControllablePolicy({ id: '', enabled: true })).toBe(false)
  })

  it('rejects derived and disabled policies', () => {
    expect(isControllablePolicy({ id: ID, metadata: { origin: 'DERIVED' } })).toBe(false)
    expect(isControllablePolicy({ id: ID, enabled: false })).toBe(false)
  })

  it('rejects a missing policy', () => {
    expect(isControllablePolicy(null)).toBe(false)
  })
})
