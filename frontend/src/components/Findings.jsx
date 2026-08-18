import { useState } from 'react'
import SourceSnippet from './SourceSnippet'

// Findings are ranked most-severe-first, so the first handful is the diagnosis.
// Anything past this is context, revealed on request.
const TOP_N = 10

export default function Findings({ findings }) {
  const [limit, setLimit] = useState(TOP_N)
  if (!findings?.length) return null
  const visible = findings.slice(0, limit)
  return (
    <div className="space-y-3">
      {visible.map((f, i) => (
        <FindingCard key={i} f={f} defaultOpen={i < 2} />
      ))}
      {findings.length > visible.length && (
        <button
          onClick={() => setLimit(l => l + TOP_N)}
          className="font-mono text-xs text-bone-400 hover:text-bone-200 transition-colors px-1"
        >
          → show {findings.length - visible.length} more finding
          {findings.length - visible.length === 1 ? '' : 's'}
        </button>
      )}
    </div>
  )
}

function FindingCard({ f, defaultOpen }) {
  const [open, setOpen] = useState(defaultOpen)
  const sev = f.severity
  const sevClass = {
    critical: 'border-flag-critical/40 bg-flag-critical/[0.03]',
    warning: 'border-flag-warning/40 bg-flag-warning/[0.03]',
    info: 'border-flag-info/30 bg-flag-info/[0.03]',
  }[sev] || 'border-ink-600'

  const badgeClass = {
    critical: 'badge-critical',
    warning: 'badge-warning',
    info: 'badge-info',
  }[sev] || 'badge-neutral'

  const dot = {
    critical: 'bg-flag-critical',
    warning: 'bg-flag-warning',
    info: 'bg-flag-info',
  }[sev] || 'bg-bone-500'

  return (
    <div className={`panel ${sevClass} overflow-hidden`}>
      <button
        onClick={() => setOpen(!open)}
        className="w-full p-4 md:p-5 flex items-start gap-4 text-left"
      >
        <span className={`${dot} w-2 h-2 rounded-full mt-2 shrink-0 ${sev === 'critical' ? 'animate-pulse' : ''}`} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1 flex-wrap">
            <span className={badgeClass}>{sev}</span>
            <span className="label text-bone-500">// {f.category}</span>
          </div>
          <h3 className="font-display text-lg text-bone-100 leading-snug">
            {f.title}
          </h3>
        </div>
        <span className={`text-bone-500 font-mono text-xs mt-1 shrink-0 transition-transform ${open ? 'rotate-90' : ''}`}>▸</span>
      </button>
      {open && (
        <div className="px-5 pb-5 pl-11 space-y-4 animate-fade-in">
          <p className="text-sm text-bone-300 leading-relaxed">{f.description}</p>

          {(f.impact || f.likely_cause) && (
            <div className="grid md:grid-cols-2 gap-3">
              {f.impact && (
                <div className="panel-inset p-4">
                  <div className="label mb-2 text-flag-warning">what you're experiencing</div>
                  <p className="text-sm text-bone-200 leading-relaxed">{f.impact}</p>
                </div>
              )}
              {f.likely_cause && (
                <div className="panel-inset p-4">
                  <div className="label mb-2 text-flag-info">likely root cause</div>
                  <p className="text-sm text-bone-200 leading-relaxed">{f.likely_cause}</p>
                </div>
              )}
            </div>
          )}

          {f.evidence?.length > 0 && (
            <div className="panel-inset p-4">
              <div className="label mb-2">evidence</div>
              <ul className="space-y-1">
                {f.evidence.map((e, i) => (
                  <li key={i} className="font-mono text-[11px] text-bone-300 flex gap-2">
                    <span className="text-bone-500 shrink-0">·</span>
                    <span className="break-all">{e}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {f.remediation && (
            <div className="panel-inset p-4">
              <div className="label mb-2 flex items-center gap-2">
                <span>→</span> how to fix it
              </div>
              <p className="text-sm text-bone-200 leading-relaxed">{f.remediation}</p>
            </div>
          )}
          {f.affected_threads?.length > 0 && (
            <div>
              <div className="label mb-2">affected · {f.affected_threads.length}</div>
              <div className="flex flex-wrap gap-1.5">
                {f.affected_threads.slice(0, 12).map((t, i) => (
                  <span key={i} className="font-mono text-[11px] px-2 py-0.5 rounded bg-ink-800 text-bone-300 border border-ink-600/60">
                    {t}
                  </span>
                ))}
                {f.affected_threads.length > 12 && (
                  <span className="font-mono text-[11px] px-2 py-0.5 text-bone-500">
                    +{f.affected_threads.length - 12} more
                  </span>
                )}
              </div>
            </div>
          )}
          {f.source_locations?.length > 0 && (
            <SourceLocations locations={f.source_locations} />
          )}
        </div>
      )}
    </div>
  )
}

function SourceLocations({ locations }) {
  // Show first 2 expanded by default; rest collapsed
  const [showAll, setShowAll] = useState(false)
  const userCodeLocs = locations.filter(l => l.is_user_code)
  // Prefer user-code locations; if none, show all
  const primary = userCodeLocs.length > 0 ? userCodeLocs : locations
  const visible = showAll ? primary : primary.slice(0, 2)
  const remaining = primary.length - visible.length

  const hasResolved = primary.some(l => l.repo_path)

  return (
    <div>
      <div className="label mb-2 flex items-center gap-2 flex-wrap">
        <span>source location{primary.length > 1 ? 's' : ''} · {primary.length}</span>
        {!hasResolved && (
          <span className="text-bone-500 normal-case tracking-normal font-sans text-[10px]">
            (attach source to see code)
          </span>
        )}
      </div>
      <div className="space-y-2">
        {visible.map((loc, i) => (
          <SourceSnippet key={i} location={loc} compact />
        ))}
      </div>
      {remaining > 0 && (
        <button
          onClick={() => setShowAll(true)}
          className="mt-2 font-mono text-[11px] text-bone-400 hover:text-bone-200 transition-colors"
        >
          → show {remaining} more location{remaining > 1 ? 's' : ''}
        </button>
      )}
    </div>
  )
}
