import { useEffect, useState } from 'react'
import { analyzeIncident } from '../api'
import { IncidentReport } from './ServerLogWorkspace'

// Keep stale responses from a previous dump or source attachment out of the report.
export function startIncident({ log, heap, thread, gc, sourceSession, windowSeconds }, { onResult, onError, onBusy }) {
  let current = true
  onBusy(true)
  analyzeIncident(log.analysis_id, heap?.analysis_id, thread?.analysis_id, gc?.analysis_id, sourceSession?.session_id, windowSeconds)
    .then(value => { if (current) onResult(value) })
    .catch(error => { if (current) onError(error.message) })
    .finally(() => { if (current) onBusy(false) })
  return () => { current = false; onBusy(false) }
}

/** The normal dump workflow owns correlation; attachments need no analyze action. */
export default function AutomaticIncident({ enabled, pending, log, heap, thread, gc, sourceSession, onBusyChange }) {
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  // Leaks accumulate for hours before a capture, so wider windows are offered.
  const [windowSeconds, setWindowSeconds] = useState(300)
  useEffect(() => {
    setResult(null); setError(null); setBusy(false)
    if (!enabled || pending || !log || !(heap || thread)) {
      onBusyChange(false)
      return
    }
    return startIncident({ log, heap, thread, gc, sourceSession, windowSeconds }, {
      onResult: setResult, onError: setError,
      onBusy: value => { setBusy(value); onBusyChange(value) },
    })
  }, [enabled, pending, log, heap, thread, gc, sourceSession?.session_id, windowSeconds, onBusyChange])

  if (!enabled || pending || !log || !(heap || thread)) return null
  return <div className="max-w-7xl mx-auto mt-6 space-y-4">
    <label className="text-sm flex items-center gap-2">Log events within
      <select className="bg-ink-950 border rounded p-1" value={windowSeconds} disabled={busy} onChange={e => setWindowSeconds(Number(e.target.value))}>
        {[[300, '±5 minutes'], [1800, '±30 minutes'], [7200, '±2 hours'], [21600, '±6 hours'], [86400, '±24 hours']].map(([value, label]) =>
          <option key={value} value={value}>{label}</option>)}
      </select>
      of each dump capture
    </label>
    {busy && <p className="panel p-5" role="status">Analyzing the dump with attached server log and source…</p>}
    {error && <p className="panel p-5 text-flag-critical" role="alert">Server-log correlation failed: {error}. The dump analysis remains available. Return to attachments to check the selected log and source.</p>}
    {result && <IncidentReport result={result} sourceSession={sourceSession} />}
  </div>
}
