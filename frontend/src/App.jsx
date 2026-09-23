import AutomaticIncident from './components/AutomaticIncident'
import ServerLogWorkspace, { IncidentReport } from './components/ServerLogWorkspace'
import DatabaseAnalysis from './components/DatabaseAnalysis'
import AnalysisHistory from './components/AnalysisHistory'
import { useState, useCallback, useEffect, useRef } from 'react'
import Hero from './components/Hero'
import ThreadAnalysis from './components/ThreadAnalysis'
import HeapAnalysis from './components/HeapAnalysis'
import GCAnalysis from './components/GCAnalysis'
import HeapProgress from './components/HeapProgress'
import CorrelationPanel from './components/CorrelationPanel'
import ComparisonPanel from './components/ComparisonPanel'
import { ReportProvider } from './reportContext'
import {
  analyzeThreadDump,
  analyzeHeapDumpSync,
  analyzeHeapDumpAsync,
  analyzeHeapDumpPath,
  analyzeGCLog,
  getJob,
  deleteJob,
} from './api'

// Files smaller than this go through the synchronous endpoint; larger get the
// async pipeline with job polling.
const ASYNC_HEAP_THRESHOLD = 150 * 1024 * 1024 // 150 MB
const POLL_INTERVAL_MS = 500

export default function App() {
  const [section, setSection] = useState('jvm')
  const [view, setView] = useState('landing')   // landing | thread | heap | gc | heap_progress
  const [analysis, setAnalysis] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [filename, setFilename] = useState('')

  // Latest analysis of each kind, retained so we can cross-correlate when the
  // user has supplied both a thread dump and a heap dump.
  const [threadAnalysis, setThreadAnalysis] = useState(null)
  const [heapAnalysis, setHeapAnalysis] = useState(null)
  const [gcAnalysis, setGcAnalysis] = useState(null)
  const [serverLog, setServerLog] = useState(null)
  const [sourceBusy, setSourceBusy] = useState(false)
  const [logBusy, setLogBusy] = useState(false)
  const [incidentBusy, setIncidentBusy] = useState(false)

  // Pinned baselines for delta comparison ({ analysis, name } or null).
  const [heapBaseline, setHeapBaseline] = useState(null)
  const [threadBaseline, setThreadBaseline] = useState(null)

  // Source repo session — persisted across reloads
  const [sourceSession, setSourceSession] = useState(null)

  // Async heap state
  const [heapPhase, setHeapPhase] = useState(null)  // 'uploading' | 'parsing' | 'done'
  const [uploadProgress, setUploadProgress] = useState({ loaded: 0, total: 0 })
  const [jobStatus, setJobStatus] = useState(null)
  const activeJobRef = useRef(null)
  const pollTimerRef = useRef(null)

  // On mount, see if we have a persisted source session
  useEffect(() => {
    try {
      const sid = localStorage.getItem('postmortem.source_session')
      if (sid) {
        // We only have the ID; we don't restore the full metadata.
        // Just record what we know — the user can disconnect and re-attach if needed.
        setSourceSession({ session_id: sid, root_dir: '(previously attached)',
                           files_indexed: 0, classes_indexed: 0, languages: {} })
      }
    } catch {}
  }, [])

  const handleDatabaseUpload = useCallback(async (file, baseline) => {
    setLoading(true); setError(null); setFilename(file.name)
    try {
      const body = new FormData(); body.append('file', file)
      if (baseline) body.append('baseline', baseline)
      const response = await fetch('/api/analyze/database', { method: 'POST', body })
      if (!response.ok) throw new Error(`Database analysis failed: ${await response.text()}`)
      setAnalysis(await response.json()); setView('database')
    } catch (e) { setError(e.message) } finally { setLoading(false) }
  }, [])

  // --- Thread upload ---
  const handleThreadUpload = useCallback(async (file) => {
    setLoading(true); setError(null); setFilename(file.name)
    try {
      const result = await analyzeThreadDump(
        file, sourceSession?.session_id || null
      )
      setAnalysis(result)
      setThreadAnalysis(result)
      setView('thread')
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [sourceSession])

  // --- GC log upload (synchronous; GC logs are text) ---
  const handleGCUpload = useCallback(async (file) => {
    setLoading(true); setError(null); setFilename(file.name)
    try {
      const result = await analyzeGCLog(file)
      setAnalysis(result)
      setGcAnalysis(result)
      setView('gc')
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [])

  // --- Heap upload (sync or async based on size) ---
  const handleHeapUpload = useCallback(async (file, quick = false, deep = false) => {
    setError(null)
    setFilename(file.name)

    // Small files → simple synchronous path
    if (file.size < ASYNC_HEAP_THRESHOLD) {
      setLoading(true)
      try {
        const result = await analyzeHeapDumpSync(file, quick, sourceSession?.session_id || null, deep)
        setAnalysis(result)
        setHeapAnalysis(result)
        setView('heap')
      } catch (e) {
        setError(e.message)
      } finally {
        setLoading(false)
      }
      return
    }

    // Big files → upload with progress, then poll the job
    setView('heap_progress')
    setHeapPhase('uploading')
    setUploadProgress({ loaded: 0, total: file.size })
    setJobStatus(null)
    try {
      const initial = await analyzeHeapDumpAsync(file, quick, (p) => {
        setUploadProgress(p)
      }, sourceSession?.session_id || null, deep)
      activeJobRef.current = initial.job_id
      setHeapPhase('parsing')
      setJobStatus(initial)
      startPolling(initial.job_id)
    } catch (e) {
      setError(e.message)
      setView('landing')
      setHeapPhase(null)
    }
  }, [sourceSession])

  // --- Server-side heap path ---
  const handleHeapPath = useCallback(async (path, quick = false, deep = false) => {
    setError(null)
    setFilename(path)
    setView('heap_progress')
    setHeapPhase('parsing')  // no upload phase for server-side path
    setUploadProgress({ loaded: 1, total: 1 })  // mark upload as complete
    setJobStatus(null)
    try {
      const initial = await analyzeHeapDumpPath(path, quick, sourceSession?.session_id || null, deep)
      activeJobRef.current = initial.job_id
      setJobStatus(initial)
      startPolling(initial.job_id)
    } catch (e) {
      setError(e.message)
      setView('landing')
      setHeapPhase(null)
    }
  }, [sourceSession])

  const startPolling = (jobId) => {
    if (pollTimerRef.current) clearTimeout(pollTimerRef.current)
    const tick = async () => {
      // Bail if the job has been abandoned
      if (activeJobRef.current !== jobId) return
      try {
        const j = await getJob(jobId)
        setJobStatus(j)
        if (j.status === 'done' && j.result) {
          setAnalysis(j.result)
          setHeapAnalysis(j.result)
          setHeapPhase('done')
          setView('heap')
          activeJobRef.current = null
          return
        }
        if (j.status === 'error') {
          setError(j.error || 'Heap parse failed')
          setView('landing')
          setHeapPhase(null)
          activeJobRef.current = null
          return
        }
        pollTimerRef.current = setTimeout(tick, POLL_INTERVAL_MS)
      } catch (e) {
        setError(e.message)
        activeJobRef.current = null
      }
    }
    pollTimerRef.current = setTimeout(tick, POLL_INTERVAL_MS)
  }

  const reset = useCallback(() => {
    // If a heap job is in flight, abandon it server-side
    if (activeJobRef.current) {
      const jid = activeJobRef.current
      activeJobRef.current = null
      deleteJob(jid).catch(() => {})
    }
    if (pollTimerRef.current) clearTimeout(pollTimerRef.current)
    setView('landing')
    setAnalysis(null)
    setError(null)
    setFilename('')
    setHeapPhase(null)
    setUploadProgress({ loaded: 0, total: 0 })
    setJobStatus(null)
  }, [])

  // Cleanup polling on unmount
  useEffect(() => {
    return () => {
      if (pollTimerRef.current) clearTimeout(pollTimerRef.current)
    }
  }, [])

  const updateAnalysis = updated => {
    setAnalysis(updated)
    if (view === 'thread') setThreadAnalysis(updated)
    if (view === 'heap') setHeapAnalysis(updated)
    if (view === 'gc') setGcAnalysis(updated)
  }

  const preparationBusy = loading || sourceBusy || logBusy || ['uploading', 'parsing'].includes(heapPhase)
  const workflowBusy = preparationBusy || incidentBusy

  return (
    <ReportProvider>
    <div className="min-h-screen">
      <Header onReset={reset} hasAnalysis={view !== 'landing'} section={section}
        loading={loading || sourceBusy || logBusy || incidentBusy} onNavigate={next => { reset(); setSection(next) }} />

      <main className="px-4 md:px-8 pb-24">
        {view === 'landing' && <AnalysisHistory disabled={workflowBusy} section={section} onOpen={({ kind, analysis: saved }) => {
          setAnalysis(saved); setView(kind); setFilename(saved.analysis_id)
          setSection(kind === 'database' ? 'database' : 'jvm')
          if (kind === 'thread') setThreadAnalysis(saved)
          if (kind === 'heap') setHeapAnalysis(saved)
          if (kind === 'gc') setGcAnalysis(saved)
          if (kind === 'server_log') { setServerLog(saved); setView('landing'); setAnalysis(null) }
        }} />}
        {view === 'landing' && section === 'jvm' && (threadAnalysis || heapAnalysis) && !(threadAnalysis && heapAnalysis) && (
          <div className="max-w-3xl mx-auto pt-8">
            <div className="panel border-flag-ok/30 bg-flag-ok/[0.02] p-4 flex items-center gap-3 text-sm">
              <span className="text-flag-ok font-mono">⌖</span>
              <span className="text-bone-300">
                {threadAnalysis ? 'Thread dump analyzed.' : 'Heap dump analyzed.'} Add a{' '}
                <span className="text-bone-100 font-medium">{threadAnalysis ? 'heap dump' : 'thread dump'}</span>{' '}
                to compare heap ownership and thread activity as investigation leads.
              </span>
            </div>
          </div>
        )}
        {view === 'landing' && (
          <Hero
            section={section}
            onThreadUpload={handleThreadUpload}
            onHeapUpload={handleHeapUpload}
            onHeapPath={handleHeapPath}
            onGCUpload={handleGCUpload}
            onDatabaseUpload={handleDatabaseUpload}
            sourceSession={sourceSession}
            onSourceSession={setSourceSession}
            onSourceBusyChange={setSourceBusy}
            serverLogAttachment={<ServerLogWorkspace log={serverLog} onLog={setServerLog}
              sourceSession={sourceSession} disabled={loading || sourceBusy || incidentBusy} onBusyChange={setLogBusy} />}
            loading={workflowBusy}
            error={error}
          />
        )}
        <AutomaticIncident enabled={section === 'jvm' && ['thread', 'heap', 'gc'].includes(view)}
          pending={preparationBusy} log={serverLog} heap={heapAnalysis} thread={threadAnalysis}
          gc={gcAnalysis} sourceSession={sourceSession} onBusyChange={setIncidentBusy} />
        {view === 'incident' && analysis && <div className="max-w-7xl mx-auto mt-6"><IncidentReport result={analysis} sourceSession={sourceSession} /></div>}
        {view === 'database' && analysis && <DatabaseAnalysis key={analysis.analysis_id} analysis={analysis} threadAnalysis={threadAnalysis} />}
        {view === 'heap_progress' && (
          <HeapProgress
            phase={heapPhase}
            uploadProgress={uploadProgress}
            jobStatus={jobStatus}
            filename={filename}
          />
        )}
        {view === 'thread' && analysis && (
          <>
            {!serverLog && heapAnalysis && threadAnalysis && (
              <div className="max-w-7xl mx-auto pt-8">
                <CorrelationPanel heap={heapAnalysis} thread={threadAnalysis} gc={gcAnalysis} sourceSession={sourceSession} />
              </div>
            )}
            <div className="max-w-7xl mx-auto pt-8 space-y-6">
              <BaselineBar
                kind="thread" baseline={threadBaseline} current={analysis}
                onPin={() => setThreadBaseline({ analysis, name: filename })}
                onClear={() => setThreadBaseline(null)}
              />
              {threadBaseline && threadBaseline.analysis !== analysis && (
                <ComparisonPanel
                  kind="thread" before={threadBaseline.analysis} beforeName={threadBaseline.name}
                  after={analysis} afterName={filename}
                />
              )}
            </div>
            <ThreadAnalysis
              analysis={analysis}
              onUpdate={updateAnalysis}
              filename={filename}
              sourceSession={sourceSession}
            />
          </>
        )}
        {view === 'heap' && analysis && (
          <>
            {!serverLog && heapAnalysis && threadAnalysis && (
              <div className="max-w-7xl mx-auto pt-8">
                <CorrelationPanel heap={heapAnalysis} thread={threadAnalysis} gc={gcAnalysis} sourceSession={sourceSession} />
              </div>
            )}
            <div className="max-w-7xl mx-auto pt-8 space-y-6">
              <BaselineBar
                kind="heap" baseline={heapBaseline} current={analysis}
                onPin={() => setHeapBaseline({ analysis, name: filename })}
                onClear={() => setHeapBaseline(null)}
              />
              {heapBaseline && heapBaseline.analysis !== analysis && (
                <ComparisonPanel
                  kind="heap" before={heapBaseline.analysis} beforeName={heapBaseline.name}
                  after={analysis} afterName={filename} sourceSession={sourceSession}
                />
              )}
            </div>
            <HeapAnalysis analysis={analysis} filename={filename} sourceSession={sourceSession} onUpdate={updateAnalysis} />
          </>
        )}
        {view === 'gc' && analysis && (
          <>
            {!serverLog && heapAnalysis && threadAnalysis && (
              <div className="max-w-7xl mx-auto pt-8">
                <CorrelationPanel heap={heapAnalysis} thread={threadAnalysis} gc={gcAnalysis} sourceSession={sourceSession} />
              </div>
            )}
            <GCAnalysis analysis={analysis} filename={filename} onUpdate={updateAnalysis} />
          </>
        )}
      </main>
    </div>
    </ReportProvider>
  )
}

function BaselineBar({ kind, baseline, current, onPin, onClear }) {
  const isBaseline = baseline && baseline.analysis === current
  return (
    <div className="panel p-3 flex items-center gap-3 text-sm flex-wrap">
      <span className="label">// compare</span>
      {!baseline && (
        <>
          <span className="text-bone-400">
            Pin this {kind} dump as a baseline, then analyze another to see exactly what changed.
          </span>
          <button onClick={onPin} className="btn-secondary ml-auto">⊹ set as baseline</button>
        </>
      )}
      {baseline && isBaseline && (
        <>
          <span className="text-bone-300">
            Baseline pinned — analyze another {kind} dump to compare against it.
          </span>
          <button onClick={onClear} className="btn-secondary ml-auto">clear</button>
        </>
      )}
      {baseline && !isBaseline && (
        <>
          <span className="text-bone-300">
            Comparing against baseline <span className="font-mono text-bone-200">{baseline.name}</span> — see the delta below.
          </span>
          <button onClick={onPin} className="btn-secondary ml-auto">pin current instead</button>
          <button onClick={onClear} className="btn-secondary">clear</button>
        </>
      )}
    </div>
  )
}

function Header({ onReset, hasAnalysis, section, onNavigate, loading }) {
  return (
    <header className="border-b border-ink-700/60 backdrop-blur-md sticky top-0 z-30 bg-ink-950/70">
      <div className="app-header">
        <button onClick={onReset} disabled={loading} className="flex items-center gap-3 group">
          <div className="w-7 h-7 border-2 border-flag-warning flex items-center justify-center crosshair text-flag-warning">
            <div className="w-1.5 h-1.5 bg-flag-warning rounded-full animate-pulse-slow" />
          </div>
          <div className="app-brand">
            <span className="font-display text-base font-medium tracking-tightest text-bone-100">
              Stack Analyser
            </span>
            <span className="label text-bone-500 group-hover:text-bone-300 transition-colors">
              Deep insights into JVM and database performance
            </span>
          </div>
        </button>
        <nav aria-label="Analyser navigation" className="analyser-nav">
          {[['jvm', 'JVM Analyser'], ['database', 'Database Analyser']].map(([key, label]) => (
            <button key={key} type="button" disabled={loading}
              aria-current={section === key ? 'page' : undefined}
              className={`analyser-nav-button${section === key ? ' active' : ''}`}
              onClick={() => onNavigate(key)}>{label}</button>
          ))}
        </nav>
        {hasAnalysis && (
          <button onClick={onReset} disabled={loading} className="btn-secondary">
            <span>← New analysis</span>
          </button>
        )}
      </div>
    </header>
  )
}
