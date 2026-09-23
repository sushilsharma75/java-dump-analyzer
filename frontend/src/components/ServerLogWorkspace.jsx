import { useEffect, useRef, useState } from 'react'
import Investigation from './Investigation'
import Findings from './Findings'
import SourceSnippet from './SourceSnippet'
import RetentionTrace from './RetentionTrace'
import LLMPanel from './LLMPanel'
import { fmtBytes } from '../report'
import { uploadServerLog, getJob, deleteJob, analyzeIncident } from '../api'

async function get(path) {
  const response = await fetch(path)
  const data = await response.json()
  if (!response.ok) throw new Error(data.detail || `Request failed (${response.status})`)
  return data
}

export function LogEvent({ event }) {
  return <div className="panel-inset p-3 space-y-2">
    <p className="font-mono text-xs">{event.evidence_id} · {event.level} · lines {event.start_line}–{event.end_line}</p>
    <p>{event.timestamp || event.raw_timestamp || 'Timestamp unavailable'} · {event.thread || 'Thread unavailable'}</p>
    {(event.trace_id || event.request_id) && <p>Trace: {event.trace_id || '—'} · Request: {event.request_id || '—'}</p>}
    <pre className="overflow-x-auto text-xs whitespace-pre-wrap">{event.excerpt}</pre>
    {!!event.truncated && <p>Excerpt or frame list truncated; see analysis coverage.</p>}
    {event.frames?.length > 0 && <details><summary>Logged stack → source ({event.frames.length} frames)</summary>
      {event.frames.map((frame, i) => <div key={i} className="my-2">
        <p className="font-mono text-xs">{frame.class_name}.{frame.method} ({frame.file}:{frame.line || '?'})</p>
        {frame.source ? <>
          <SourceSnippet location={frame.source} />
          {frame.source.context?.method && <details><summary>Complete method context</summary>
            <SourceSnippet location={{ ...frame.source, snippet: frame.source.context.method }} />
            {frame.source.context.method.truncated && <p>Method context truncated.</p>}
          </details>}
        </> : <p className="text-xs text-bone-500">Source unresolved; open event with matching source attached.</p>}
      </div>)}
    </details>}
  </div>
}

export function incidentReportHTML(result) {
  const escape = value => String(value ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]))
  const matches = (result.matches || []).map(m => `<article><h2>${escape(m.event.evidence_id)} · ${escape(m.event.level)}</h2><p>Log lines ${m.event.start_line}–${m.event.end_line} · ${escape(m.event.timestamp || m.event.raw_timestamp)}</p><pre>${escape(m.event.excerpt)}</pre><h3>Evidence links and source</h3><pre>${escape(JSON.stringify({ links: m.links, frames: m.event.frames, aligned_with: m.aligned_with }, null, 2))}</pre></article>`).join('')
  return `<!doctype html><html lang="en"><meta charset="utf-8"><title>Combined JVM investigation</title><style>body{font:15px system-ui;max-width:1100px;margin:40px auto;padding:20px}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#eee;padding:16px}article{border-top:1px solid #aaa;margin-top:24px}</style><h1>Combined JVM investigation</h1><p>${escape(result.summary)}</p><h2>Coverage and limitations</h2><pre>${escape(JSON.stringify({ inputs: result.inputs, coverage: result.coverage, limitations: result.limitations }, null, 2))}</pre><h2>Dump findings</h2><pre>${escape(JSON.stringify(result.findings || [], null, 2))}</pre><h2>Heap reference chains</h2><pre>${escape(JSON.stringify(result.heap?.dominators || [], null, 2))}</pre>${matches}</html>`
}

function exportHTML(result) {
  const url = URL.createObjectURL(new Blob([incidentReportHTML(result)], { type: 'text/html;charset=utf-8' }))
  const a = document.createElement('a'); a.href = url; a.download = 'combined-jvm-investigation.html'; a.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

export function IncidentReport({ result, sourceSession }) {
  const [limit, setLimit] = useState(10)
  return <section className="panel p-5 space-y-4">
    <h3 className="font-display text-lg">Combined JVM investigation</h3>
    <p>{result.summary}</p>
    <div className="flex flex-wrap gap-3">
      {result.analysis_id && <a className="btn-secondary" href={`/api/analyses/${result.analysis_id}`} download>Download combined JSON</a>}
      <button className="btn-secondary" onClick={() => exportHTML(result)}>Export combined HTML</button>
    </div>
    <details open={result.status === 'incompatible'}><summary>Input identities, coverage and limitations</summary>
      <pre className="text-xs overflow-x-auto whitespace-pre-wrap">{JSON.stringify({ inputs: result.inputs, coverage: result.coverage, limitations: result.limitations }, null, 2)}</pre>
    </details>
    {!!result.findings?.length && <Findings findings={result.findings} />}
    {!!result.heap?.dominators?.length && <details><summary>Heap reference chains and source</summary>
      {result.heap.dominators.filter(entry => entry.root_paths?.paths?.length).map(entry => <div key={entry.object_id} className="my-3">
        <h4>{entry.class_name} @ {entry.object_id} · {fmtBytes(entry.retained_bytes)} retained</h4>
        <RetentionTrace data={entry.root_paths} />
      </div>)}
    </details>}
    {(result.matches || []).slice(0, limit).map(match => <details key={match.event.evidence_id} className="panel-inset p-3">
      <summary>{match.event.level} · {match.event.exception || match.event.message?.slice(0, 120)} · {match.event.evidence_id}</summary>
      <p className="my-2">Time aligned with: {match.aligned_with.join(', ') || 'unverified'} · Confidence: {match.confidence}</p>
      <p>These links identify shared context; they do not prove an allocation or retaining call.</p>
      <pre className="text-xs overflow-x-auto whitespace-pre-wrap">{JSON.stringify(match.links, null, 2)}</pre>
      {!!match.links_omitted && <p>{match.links_omitted} additional links omitted.</p>}
      <LogEvent event={match.event} />
    </details>)}
    {(result.matches || []).length > limit && <button className="btn-secondary" onClick={() => setLimit(limit + 10)}>Show more matching events</button>}
    {result.status !== 'incompatible' && <LLMPanel kind="unified" sourceSession={sourceSession}
      analysis={{ heap: result.heap, thread: result.thread, gc: result.gc, server_log: result.server_log, correlation: result.correlation, incident: result }} />}
  </section>
}

function LogBrowser({ analysis, sourceSession }) {
  const [filters, setFilters] = useState({ level: '', query: '', thread: '', trace_id: '', request_id: '', since: '', until: '' })
  const [page, setPage] = useState(null)
  const [selected, setSelected] = useState(null)
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  const generation = useRef(0)
  useEffect(() => { generation.current++; setSelected(null); setBusy(false) }, [sourceSession?.session_id])
  const search = async (after = 0) => {
    const token = ++generation.current
    setBusy(true); setError(null); setSelected(null)
    try {
      const params = new URLSearchParams({ after, ...Object.fromEntries(Object.entries(filters).filter(([, v]) => v)) })
      const result = await get(`/api/server-logs/${analysis.analysis_id}/events?${params}`)
      if (token === generation.current) setPage(result)
    } catch (e) { if (token === generation.current) setError(e.message) }
    finally { if (token === generation.current) setBusy(false) }
  }
  const inspect = async event => {
    const token = ++generation.current
    setBusy(true); setError(null)
    try {
      const params = new URLSearchParams(sourceSession ? { source_session: sourceSession.session_id } : {})
      const result = await get(`/api/server-logs/${analysis.analysis_id}/events/${event.id}?${params}`)
      if (token === generation.current) setSelected(result)
    } catch (e) { if (token === generation.current) setError(e.message) }
    finally { if (token === generation.current) setBusy(false) }
  }
  return <details className="space-y-3"><summary>Search log events and inspect source</summary>
    <form className="space-y-3 mt-3" onSubmit={e => { e.preventDefault(); search() }}>
      <label>Level <select className="bg-ink-950 border rounded p-2" value={filters.level} onChange={e => setFilters({ ...filters, level: e.target.value })}>
        {['', 'ERROR', 'FATAL', 'WARN', 'INFO', 'DEBUG', 'TRACE', 'UNKNOWN'].map(v => <option key={v} value={v}>{v || 'All levels'}</option>)}
      </select></label>
      <div className="grid md:grid-cols-2 gap-2">{Object.entries({ query: 'Text in retained excerpt', thread: 'Exact thread name', trace_id: 'Trace ID', request_id: 'Request ID', since: 'Since (ISO timestamp with offset)', until: 'Until (ISO timestamp with offset)' }).map(([key, label]) => <label className="text-sm" key={key}>{label}
        <input className="w-full bg-ink-950 border rounded p-2" value={filters[key]} onChange={e => setFilters({ ...filters, [key]: e.target.value })} />
      </label>)}</div>
      <button className="btn-secondary" disabled={busy}>Search events</button>
    </form>
    {error && <p role="alert">{error}</p>}
    {page?.events.length === 0 && <p>No matching events.</p>}
    {(page?.events || analysis.sample_events || []).map(event => <button key={event.id} disabled={busy} className="block text-left text-sm py-2" onClick={() => inspect(event)}>
      {event.level} · line {event.start_line} · {event.exception || event.message?.slice(0, 160)}
    </button>)}
    {page?.next_cursor && <button className="btn-secondary" disabled={busy} onClick={() => search(page.next_cursor)}>Next events</button>}
    {selected && <LogEvent event={selected} />}
  </details>
}

export default function ServerLogWorkspace({ log, onLog, heap, thread, gc, sourceSession, onDetach }) {
  const [busy, setBusy] = useState(false)
  const [phase, setPhase] = useState('')
  const [progress, setProgress] = useState(null)
  const [offset, setOffset] = useState('')
  const [error, setError] = useState(null)
  const [result, setResult] = useState(null)
  const [combining, setCombining] = useState(false)
  const controller = useRef(null)
  const job = useRef(null)
  const timer = useRef(null)
  const generation = useRef(0)
  const incidentGeneration = useRef(0)
  useEffect(() => { incidentGeneration.current++; setResult(null); setCombining(false) }, [log, heap, thread, gc, sourceSession?.session_id])
  useEffect(() => () => {
    generation.current++; controller.current?.abort(); clearTimeout(timer.current)
    if (job.current) deleteJob(job.current).catch(() => {})
  }, [])
  const cancel = () => {
    generation.current++; controller.current?.abort(); clearTimeout(timer.current)
    if (job.current) deleteJob(job.current).catch(() => {})
    job.current = null; setBusy(false); setPhase('Cancelled')
  }
  const upload = async file => {
    if (!file) return
    if (file.size > 5 * 1024 ** 3) { setError('Server log exceeds the 5 GiB limit'); return }
    if (!file.size) { setError('Server log is empty'); return }
    const token = ++generation.current
    setBusy(true); setError(null); setResult(null); setPhase('Uploading server log')
    setProgress({ loaded: 0, total: file.size }); controller.current = new AbortController()
    try {
      const initial = await uploadServerLog(file, offset || null, p => { if (token === generation.current) setProgress(p) }, controller.current.signal)
      if (token !== generation.current) { deleteJob(initial.job_id).catch(() => {}); return }
      job.current = initial.job_id; setPhase('Queued for log scan')
      const poll = async () => {
        if (token !== generation.current) return
        try {
          const status = await getJob(initial.job_id)
          if (token !== generation.current) return
          setPhase(status.stage); setProgress({ loaded: status.bytes_processed, total: status.bytes_total })
          if (status.status === 'done') {
            job.current = null; setBusy(false); onLog(status.result); return
          }
          if (status.status === 'error') throw new Error(status.error || 'Server log analysis failed')
          timer.current = setTimeout(poll, 750)
        } catch (e) { if (token === generation.current) { setError(e.message); setBusy(false); job.current = null } }
      }
      timer.current = setTimeout(poll, 100)
    } catch (e) { if (token === generation.current) { setError(e.message); setBusy(false) } }
  }
  const combine = async () => {
    const token = ++incidentGeneration.current
    setCombining(true); setError(null)
    try {
      const combined = await analyzeIncident(log.analysis_id, heap?.analysis_id, thread?.analysis_id, gc?.analysis_id, sourceSession?.session_id)
      if (token === incidentGeneration.current) setResult(combined)
    }
    catch (e) { if (token === incidentGeneration.current) setError(e.message) }
    finally { if (token === incidentGeneration.current) setCombining(false) }
  }
  return <div className="max-w-7xl mx-auto mt-6 space-y-5">
    <section className="panel p-5 space-y-4">
      <h2 className="font-display text-xl">Server log · combined investigation</h2>
      <p className="text-sm text-bone-400">Upload server.log up to 5 GiB. Analyze it with the selected heap/thread dumps and source. The full file is scanned; long event excerpts and frame lists have visible limits.</p>
      <div className="flex flex-wrap items-center gap-3">
        <label className="btn-secondary">{busy ? 'Processing log…' : 'Upload server.log'}
          <input className="block text-sm" type="file" accept=".log,.txt,.json,.jsonl,text/plain,application/octet-stream" disabled={busy} onChange={e => { upload(e.target.files?.[0]); e.target.value = '' }} />
        </label>
        <label className="text-sm">Timezone for timestamps without an offset
          <input className="block bg-ink-950 border rounded p-2" placeholder="Unknown, or +05:30" value={offset} disabled={busy} onChange={e => setOffset(e.target.value)} />
        </label>
        {busy && <button className="btn-secondary" onClick={cancel}>Cancel log upload / scan</button>}
      </div>
      {busy && <div role="status"><p>{phase} · {fmtBytes(progress?.loaded || 0)} / {fmtBytes(progress?.total || 0)}</p><progress className="w-full" value={progress?.loaded || 0} max={progress?.total || 1} /></div>}
      {error && <p role="alert" className="text-flag-critical">{error}</p>}
      <div className="text-sm space-y-1">
        <p>Server log: {log ? `${log.filename || 'Saved log'} · ${log.analysis_id}` : 'not attached'}</p>
        <p>Heap: {heap?.analysis_id || 'not attached'} · Thread: {thread?.analysis_id || 'not attached'}</p>
        <p>Source: {sourceSession?.root_dir || 'not attached'} · GC: {gc?.analysis_id || 'not attached'}</p>
        {onDetach && <div className="flex gap-2">{[['heap', heap], ['thread', thread], ['gc', gc]].filter(([, value]) => value).map(([kind]) => <button className="btn-secondary" key={kind} onClick={() => onDetach(kind)}>Detach {kind}</button>)}</div>}
      </div>
      <button className="btn-primary" disabled={!log || !(heap || thread) || combining || busy} onClick={combine}>{combining ? 'Combining evidence…' : 'Analyze all attached evidence'}</button>
      {log && <>
        <p>{log.summary}</p>
        <div className="flex gap-3"><a className="btn-secondary" href={`/api/analyses/${log.analysis_id}`} download>Download log analysis JSON</a><button className="btn-secondary" onClick={() => onLog(null)}>Detach log</button></div>
        <details><summary>Log scan coverage, exceptions and limits</summary><pre className="text-xs overflow-x-auto whitespace-pre-wrap">{JSON.stringify({ counts: log.counts, levels: log.levels, exceptions: log.exceptions, time_range: log.time_range, coverage: log.parse_coverage, limitations: log.limitations }, null, 2)}</pre></details>
        <LogBrowser key={log.analysis_id} analysis={log} sourceSession={sourceSession} />
        <details><summary>Log capture identity</summary><Investigation analysis={log} sourceSession={sourceSession} onUpdate={onLog} /></details>
      </>}
    </section>
    {result && <IncidentReport result={result} sourceSession={sourceSession} />}
  </div>
}
