import { describe, it, expect } from 'vitest'
import { isControllablePolicy, isPostureCandidate } from '../lib/firewallPolicyLogging'

const ID = '11111111-2222-4333-8444-555555555555'

describe('isPostureCandidate / isControllablePolicy', () => {
  it('normal enabled policy with an id: both', () => {
    const p = { id: ID, enabled: true, metadata: { origin: 'USER_DEFINED' } }
    expect(isPostureCandidate(p)).toBe(true)
    expect(isControllablePolicy(p)).toBe(true)
  })

  it('id-less enabled policy (#112): posture candidate, not controllable', () => {
    for (const p of [
      { enabled: true, metadata: { origin: 'USER_DEFINED' } },
      { id: '', enabled: true },
      { id: null, enabled: true },
    ]) {
      expect(isPostureCandidate(p)).toBe(true)
      expect(isControllablePolicy(p)).toBe(false)
    }
  })

  it('disabled policy: neither', () => {
    for (const p of [{ id: ID, enabled: false }, { enabled: false }]) {
      expect(isPostureCandidate(p)).toBe(false)
      expect(isControllablePolicy(p)).toBe(false)
    }
  })

  it('DERIVED policy: neither', () => {
    for (const p of [{ id: ID, metadata: { origin: 'DERIVED' } }, { metadata: { origin: 'DERIVED' } }]) {
      expect(isPostureCandidate(p)).toBe(false)
      expect(isControllablePolicy(p)).toBe(false)
    }
  })

  it('missing policy: neither', () => {
    expect(isPostureCandidate(null)).toBe(false)
    expect(isControllablePolicy(undefined)).toBe(false)
  })
})
