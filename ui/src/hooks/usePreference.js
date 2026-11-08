import { useEffect, useState } from 'react'
import { readPreference, writePreference } from '../lib/preferences'

// Keys are fixed for the lifetime of the component, like a useState initializer.
export default function usePreference(key, initial, validate) {
  const [value, setValue] = useState(() => readPreference(key, initial, validate))
  useEffect(() => { writePreference(key, value) }, [key, value])
  return [value, setValue]
}
