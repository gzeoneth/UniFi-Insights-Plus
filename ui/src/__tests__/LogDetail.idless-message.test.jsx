/**
 * Rule Logging message for a log whose only matching policy has no id (#112):
 * name first, and "Troubleshooting on the docs site" as a real link.
 */

import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { IdlessPolicyMessage } from '../components/LogDetail'

const MESSAGE = 'The UniFi controller returned this policy without an id, so its logging cannot be '
  + 'toggled here. Toggle syslog for this rule in the UniFi Network app, or see '
  + 'Troubleshooting on the docs site.'
const DOCS = 'https://insightsplus.dev/docs/troubleshooting#firewall-policies-without-an-id'

describe('IdlessPolicyMessage', () => {
  it('puts the policy name first and links the docs phrase', () => {
    const { container } = render(<IdlessPolicyMessage name="Block IoT" message={MESSAGE} />)

    expect(container.textContent).toBe(`Legacy rule Block IoT: ${MESSAGE}`)
    const link = screen.getByRole('link', { name: /Troubleshooting on the docs site/ })
    expect(link.getAttribute('href')).toBe(DOCS)
    expect(link.getAttribute('target')).toBe('_blank')
    expect(link.getAttribute('rel')).toBe('noopener noreferrer')
  })

  it('still links the docs when the message lacks the phrase', () => {
    const { container } = render(<IdlessPolicyMessage name="" message="No id." />)

    expect(container.textContent).toBe('Legacy rule: No id. Troubleshooting on the docs site')
    expect(screen.getByRole('link').getAttribute('href')).toBe(DOCS)
  })
})
