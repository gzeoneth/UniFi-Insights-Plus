import { useEffect, useState } from 'react'
import { fetchSecuritySummary } from '../api'
import { formatNumber } from '../utils'
import { CACHE_TTL_MS } from '../lib/sessionCache'

const COUNTERS = [
  ['ips_blocked', 'IPS blocked', 'text-red-400'],
  ['ips_allowed', 'IPS allowed', 'text-amber-400'],
  ['ips_unknown', 'IPS action unknown', 'text-gray-300'],
  ['firewall_blocks', 'Firewall blocks', 'text-red-300'],
  ['reputation_alerts', 'IP reputation >50', 'text-orange-400'],
]

export default function SecuritySummary({ timeRange = '24h', timeFrom, timeTo }) {
  const [data, setData] = useState(null)
  const [error, setError] = useState(false)
  const [refresh, setRefresh] = useState(0)

  useEffect(() => {
    const interval = setInterval(() => {
      if (document.visibilityState === 'visible') setRefresh(value => value + 1)
    }, CACHE_TTL_MS)
    return () => clearInterval(interval)
  }, [])

  useEffect(() => {
    const controller = new AbortController()
    let active = true
    setData(null)
    setError(false)
    fetchSecuritySummary({ time_range: timeRange, time_from: timeFrom, time_to: timeTo },
      { signal: controller.signal })
      .then(value => { if (active) setData(value) })
      .catch(() => { if (active) setError(true) })
    return () => { active = false; controller.abort() }
  }, [timeRange, timeFrom, timeTo, refresh])

  return (
    <section aria-label="Security events" className="border border-gray-800 rounded-lg p-4">
      <h2 className="text-xs text-gray-400 uppercase tracking-wider mb-3">Security events</h2>
      {error ? (
        <div role="alert" className="text-sm text-red-400 flex items-center gap-3">
          <span>Security summary could not be loaded.</span>
          <button type="button" onClick={() => setRefresh(value => value + 1)}
            className="text-teal-400 underline hover:text-teal-300">Retry</button>
        </div>
      ) : !data ? (
        <div role="status" className="text-sm text-gray-400">Loading security events…</div>
      ) : (
        <>
          {data.unparsed_cef_threats > 0 && <p role="alert" className="text-sm text-amber-300 mb-3">
            {formatNumber(data.unparsed_cef_threats)} retained CEF threat candidates have not been parsed into IPS fields and are not included in the IPS counters below. Search Log Stream for “CEF:” with all log types selected to inspect them. Historical records need a reparse or backfill before their threat details can be confirmed.
          </p>}
          <dl className="grid grid-cols-2 sm:grid-cols-3 xl:grid-cols-5 gap-4">
            {COUNTERS.map(([key, label, color]) => (
              <div key={key}>
                <dt className="text-xs text-gray-400">{label}</dt>
                <dd className={`text-xl font-semibold mt-1 ${color}`}>{formatNumber(data[key] ?? 0)}</dd>
              </div>
            ))}
          </dl>
          <p className="text-xs text-gray-500 mt-3">
            Firewall blocks exclude IPS events. IP reputation counts logs with an AbuseIPDB score above 50 and can overlap with IPS events.
          </p>
          <h3 className="text-xs text-gray-400 uppercase tracking-wider mt-5 mb-2">Top IPS signatures</h3>
          {!data.top_signatures?.length ? (
            <p className="text-sm text-gray-500">{data.unparsed_cef_threats > 0 ? 'No parsed IPS signatures in this time range.' : 'No IPS events in this time range.'}</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-xs text-left">
                <thead className="text-gray-400">
                  <tr>
                    <th scope="col" className="pb-2 pr-3 font-medium">Signature</th>
                    <th scope="col" className="pb-2 pr-3 font-medium">Events</th>
                    <th scope="col" className="pb-2 pr-3 font-medium">Latest risk / severity</th>
                    <th scope="col" className="pb-2 font-medium">Last seen</th>
                  </tr>
                </thead>
                <tbody className="text-gray-300">
                  {data.top_signatures.map(item => (
                    <tr key={JSON.stringify([item.ips_signature_id, item.ips_signature])} className="border-t border-gray-800/70">
                      <td className="py-2 pr-3 max-w-md break-words">
                        <div>{item.ips_signature || 'Signature not supplied'}</div>
                        {item.ips_signature_id && <div className="text-gray-500 mt-0.5">ID {item.ips_signature_id}</div>}
                      </td>
                      <td className="py-2 pr-3 tabular-nums">{formatNumber(item.count)}</td>
                      <td className="py-2 pr-3">
                        {item.ips_risk || 'Unknown'} / {item.ips_severity == null ? 'Unknown' : `${item.ips_severity}/10`}
                      </td>
                      <td className="py-2 whitespace-nowrap">
                        {item.last_seen ? <time dateTime={item.last_seen}>{new Date(item.last_seen).toLocaleString()}</time> : 'Unknown'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </section>
  )
}
