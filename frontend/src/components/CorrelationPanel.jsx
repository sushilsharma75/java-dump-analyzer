import { useState, useEffect } from 'react'
import Findings from './Findings'
import LLMPanel from './LLMPanel'
import { correlateDumps } from '../api'

/**
 * Cross-dump correlation. Appears once the user has analyzed BOTH a thread dump
 * and a heap dump in this session. Intersects heap-dominant app classes with
 * live thread stack frames to produce double-confirmed, line-precise findings.
 */
export default function CorrelationPanel({ heap, thread, gc, sourceSession }) {
  const [state, setState] = useState('idle') // idle | loading | done | error
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)
  const [open, setOpen] = useState(true)

  // Re-run only when the underlying dumps actually change, not on every render.
  // Keying the effect on this derived string (rather than the heap/thread object
  // identities) means a parent re-render with the same data won't re-fire — while
  // still re-issuing the request on a real remount (e.g. StrictMode's mount/
  // unmount/mount in dev), so the in-flight result is never orphaned by a stale
  // cleanup flag.
  const key = heap && thread
    ? `${heap.file_size_bytes}|${heap.total_instances}|${thread.total_threads}|${gc?.gc_count ?? ''}|${gc?.heap_after_trend_mb_per_min ?? ''}|${sourceSession?.session_id || ''}`
    : null

  useEffect(() => {
    if (!heap || !thread) return
    let cancelled = false
    setState('loading'); setError(null)
    correlateDumps(heap, thread, sourceSession?.session_id || null, gc || null)
      .then((r) => { if (!cancelled) { setResult(r); setState('done') } })
      .catch((e) => { if (!cancelled) { setError(e.message); setState('error') } })
    return () => { cancelled = true }
  }, [key])

  if (!heap || !thread) return null

  const matched = result?.matched_classes ?? 0

  return (
    <section className="panel border-flag-ok/30 bg-flag-ok/[0.02] overflow-hidden animate-slide-up">
      <button
        onClick={() => setOpen(!open)}
        className="w-full p-5 md:p-6 flex items-start gap-4 text-left"
      >
        <span className="text-flag-ok font-mono text-lg mt-0.5 shrink-0">⌖</span>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1 flex-wrap">
            <span className="badge-ok">cross-dump</span>
            <span className="label text-bone-500">// thread × heap{gc ? ' × gc' : ''}{sourceSession ? ' × source' : ''}</span>
            {state === 'done' && (
              <span className="badge-neutral">{matched} matched</span>
            )}
          </div>
          <h3 className="font-display text-lg text-bone-100 leading-snug">
            Correlated diagnosis
          </h3>
          {state === 'done' && result?.summary && (
            <p className="text-sm text-bone-300 mt-1 leading-relaxed">{result.summary}</p>
          )}
          {state === 'loading' && (
            <p className="text-sm text-bone-500 mt-1 font-mono">correlating…</p>
          )}
          {state === 'error' && (
            <p className="text-sm text-flag-critical mt-1">{error}</p>
          )}
        </div>
        <span className={`text-bone-500 font-mono text-xs mt-1 shrink-0 transition-transform ${open ? 'rotate-90' : ''}`}>▸</span>
      </button>

      {open && state === 'done' && (
        <div className="px-5 md:px-6 pb-6 space-y-6 animate-fade-in">
          {result?.findings?.length > 0 && <Findings findings={result.findings} />}
          {/* Unified AI diagnosis: synthesize heap + thread + correlation into a
              single Problem→Evidence→Location→Fix write-up for an entry-level dev. */}
          <LLMPanel analysis={{ heap, thread, gc, correlation: result }} kind="unified" />
        </div>
      )}
    </section>
  )
}
