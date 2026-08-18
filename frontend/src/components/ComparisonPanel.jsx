import { useState, useEffect } from 'react'
import Findings from './Findings'
import { compareHeaps, compareThreads } from '../api'

const TONE = {
  critical: { border: 'border-flag-critical/40', bg: 'bg-flag-critical/5', badge: 'badge-critical', dot: 'bg-flag-critical' },
  degraded: { border: 'border-flag-warning/40', bg: 'bg-flag-warning/5', badge: 'badge-warning', dot: 'bg-flag-warning' },
  healthy: { border: 'border-flag-ok/30', bg: 'bg-flag-ok/[0.03]', badge: 'badge-ok', dot: 'bg-flag-ok' },
}

function fmtBytes(n) {
  if (n == null) return '—'
  const sign = n < 0 ? '-' : ''
  let v = Math.abs(n)
  const u = ['B', 'KB', 'MB', 'GB', 'TB']
  let i = 0
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++ }
  return `${sign}${v.toFixed(i === 0 ? 0 : 1)} ${u[i]}`
}

/**
 * Cross-capture delta. Diffs a pinned baseline against the current analysis:
 * for heaps, which classes grew (the leak suspects); for threads, which are stuck
 * at the same frame in both. Auto-runs whenever baseline/current change.
 */
export default function ComparisonPanel({ kind, before, after, beforeName, afterName, sourceSession }) {
  const [state, setState] = useState('idle')
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)
  const [open, setOpen] = useState(true)

  // Stable discriminator so the effect only re-runs on a real change (and re-fires
  // on a StrictMode remount instead of orphaning the request).
  const disc = kind === 'heap'
    ? `${before?.file_size_bytes}|${before?.total_instances}|${after?.file_size_bytes}|${after?.total_instances}`
    : `${before?.total_threads}|${after?.total_threads}`
  const key = before && after ? `${kind}|${disc}|${sourceSession?.session_id || ''}` : null

  useEffect(() => {
    if (!before || !after) return
    let cancelled = false
    setState('loading'); setError(null)
    const p = kind === 'heap'
      ? compareHeaps(before, after, sourceSession?.session_id || null)
      : compareThreads(before, after)
    p.then((r) => { if (!cancelled) { setResult(r); setState('done') } })
     .catch((e) => { if (!cancelled) { setError(e.message); setState('error') } })
    return () => { cancelled = true }
  }, [key])

  if (!before || !after) return null
  const tone = TONE[result?.verdict] || TONE.healthy

  return (
    <section className={`panel ${tone.border} ${tone.bg} overflow-hidden animate-slide-up`}>
      <button onClick={() => setOpen(!open)} className="w-full p-5 md:p-6 flex items-start gap-4 text-left">
        <span className={`${tone.dot} w-2.5 h-2.5 rounded-full mt-1.5 shrink-0`} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1 flex-wrap">
            <span className="badge-neutral">delta</span>
            <span className="label text-bone-500">
              // {kind === 'heap' ? 'heap growth' : 'stuck threads'} · baseline → current
            </span>
            {state === 'done' && <span className={tone.badge}>{result.verdict}</span>}
          </div>
          <h3 className="font-display text-lg text-bone-100 leading-snug">
            {kind === 'heap' ? 'What grew between the two heaps' : 'What stayed stuck between the two dumps'}
          </h3>
          <p className="font-mono text-[11px] text-bone-500 mt-1 truncate">
            {beforeName || 'baseline'} <span className="text-bone-400">→</span> {afterName || 'current'}
          </p>
          {state === 'done' && result?.summary && (
            <p className="text-sm text-bone-300 mt-1 leading-relaxed">{result.summary}</p>
          )}
          {state === 'loading' && <p className="text-sm text-bone-500 mt-1 font-mono">comparing…</p>}
          {state === 'error' && <p className="text-sm text-flag-critical mt-1">{error}</p>}
        </div>
        <span className={`text-bone-500 font-mono text-xs mt-1 shrink-0 transition-transform ${open ? 'rotate-90' : ''}`}>▸</span>
      </button>

      {open && state === 'done' && (
        <div className="px-5 md:px-6 pb-6 space-y-6 animate-fade-in">
          {kind === 'heap' ? <Growers result={result} /> : <Stuck result={result} />}
          {result?.findings?.length > 0 && <Findings findings={result.findings} />}
        </div>
      )}
    </section>
  )
}

function Growers({ result }) {
  const rows = result.growers || []
  if (!rows.length) {
    return <div className="panel-inset p-4 text-bone-500 font-mono text-sm">no class grew between the captures</div>
  }
  const max = Math.max(...rows.map(r => r.bytes_delta), 1)
  return (
    <div className="panel overflow-hidden">
      <div className="flex items-center justify-between px-5 py-3 border-b border-ink-600/60">
        <span className="label">class growth</span>
        <span className="font-mono text-[11px] text-bone-400">net {fmtBytes(result.bytes_growth)}</span>
      </div>
      <div>
        {rows.slice(0, 15).map((d, i) => {
          const pct = (d.bytes_delta / max) * 100
          return (
            <div key={i} className="relative border-b border-ink-700/30 last:border-0 px-5 py-2.5 flex items-center gap-3 text-sm">
              <div className="absolute inset-y-0 left-0 bg-flag-critical/[0.06]" style={{ width: `${pct}%` }} />
              <span className="flex-1 min-w-0 relative z-10">
                <span className="font-mono text-xs text-bone-200 truncate block">
                  {d.class_name}
                  {d.is_new && <span className="badge-warning ml-2">new</span>}
                </span>
                <span className="font-mono text-[11px] text-bone-500">
                  {fmtBytes(d.bytes_before)} → {fmtBytes(d.bytes_after)} · {d.count_before.toLocaleString()} → {d.count_after.toLocaleString()} inst
                </span>
              </span>
              <span className="font-mono text-xs text-flag-critical text-right tabular-nums shrink-0 relative z-10">
                +{fmtBytes(d.bytes_delta)}
                <span className="text-bone-500 block text-[11px]">+{d.count_delta.toLocaleString()}</span>
              </span>
            </div>
          )
        })}
      </div>
    </div>
  )
}

function Stuck({ result }) {
  const rows = result.stuck_threads || []
  if (!rows.length) {
    return <div className="panel-inset p-4 text-bone-500 font-mono text-sm">no threads stuck at the same frame in both dumps</div>
  }
  return (
    <div className="panel overflow-hidden">
      <div className="px-5 py-3 border-b border-ink-600/60 label">threads stuck in both captures</div>
      <div>
        {rows.map((t, i) => (
          <div key={i} className="border-b border-ink-700/30 last:border-0 px-5 py-2.5 flex items-center gap-3 text-sm">
            <span className={t.blocked ? 'badge-critical' : 'badge-warning'}>{t.state}</span>
            <span className="flex-1 min-w-0">
              <span className="font-mono text-xs text-bone-200 truncate block">{t.name}</span>
              <span className="font-mono text-[11px] text-bone-500 truncate block">{t.top_frame}</span>
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}
