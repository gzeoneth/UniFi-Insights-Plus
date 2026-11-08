import { describe, it, expect } from 'vitest'
import { isNewerVersion } from '../components/ReleaseNotesModal'

describe('fork release comparison', () => {
  it('does not suggest replacing a fork revision with its upstream base', () => {
    expect(isNewerVersion('v3.7.2', '3.7.2-gzeon.1')).toBe(false)
    expect(isNewerVersion('v3.7.2-beta.9', '3.7.2-gzeon.1')).toBe(false)
    expect(isNewerVersion('v3.7.3', '3.7.2-gzeon.1')).toBe(true)
  })
  it('retains stable versus beta behavior for upstream releases', () => {
    expect(isNewerVersion('v3.7.2', '3.7.2-beta.1')).toBe(true)
    expect(isNewerVersion('v3.7.2-beta.2', '3.7.2-beta.1')).toBe(true)
  })
})
