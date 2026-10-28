import { useState, useEffect, useMemo, useCallback } from 'react'
import { timeRangeToDays, filterVisibleRanges } from '../utils'
import { TIME_RANGES, readTimeRange, writeTimeRange } from '../lib/preferences'

export default function useTimeRange(maxFilterDays) {
  const [timeRange, setTimeRangeState] = useState(readTimeRange)

  const setTimeRange = useCallback((tr) => {
    if (!TIME_RANGES.includes(tr)) return
    setTimeRangeState(tr)
    writeTimeRange(tr)
  }, [])

  const visibleRanges = useMemo(() => filterVisibleRanges(TIME_RANGES, maxFilterDays), [maxFilterDays])

  // Auto-correct selected range if it exceeds visible ranges (respects ceiling).
  // Depends on [maxFilterDays] only — including visibleRanges/timeRange would
  // create an infinite loop (effect sets timeRange → re-render → new array ref → repeat).
  useEffect(() => {
    if (maxFilterDays == null || visibleRanges.length === 0) return
    if (visibleRanges.includes(timeRange)) return
    const largest = visibleRanges.findLast(tr => timeRangeToDays(tr) >= 1) || visibleRanges[visibleRanges.length - 1]
    if (largest && largest !== timeRange) setTimeRange(largest)
  }, [maxFilterDays]) // eslint-disable-line react-hooks/exhaustive-deps

  return [timeRange, setTimeRange, visibleRanges]
}
