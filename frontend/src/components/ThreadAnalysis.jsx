import { useState, useMemo } from 'react'
import Findings from './Findings'
import LLMPanel from './LLMPanel'
import VerdictBanner from './VerdictBanner'
import { PoolsView, HotThreads, StateLegend } from './ThreadInsights'
import ExportReport from './ExportReport'

const STATE_COLORS = {
  RUNNABLE: 'bg-flag-ok',
  BLOCKED: 'bg-flag-critical',
  WAITING: 'bg-flag-info',
  TIMED_WAITING: 'bg-bone-500',
  NEW: 'bg-ink-500',
  TERMINATED: 'bg-ink-500',
  UNKNOWN: 'bg-ink-500',
}

export default function ThreadAnalysis({ analysis, filename, sourceSession }) {
  return (
    <div className="max-w-7xl mx-auto pt-8 space-y-8">
      <VerdictBanner verdict={analysis.verdict} summary={analysis.summary} />
      <CaseFile analysis={analysis} filename={filename} />
      <StateBreakdown analysis={analysis} />
      <ExportReport analysis={analysis} filename={filename} kind="thread" />

      <Section label="// diagnostic findings" count={analysis.findings.length}>
        <Findings findings={analysis.findings} />
      </Section>

      {analysis.pools?.length > 0 && (
        <Section label="// thread pools" count={analysis.pools.length}>
          <PoolsView pools={analysis.pools} />
        </Section>
      )}

      {analysis.hot_threads?.length > 0 && (
        <Section label="// cpu hot threads" count={analysis.hot_threads.length}>
          <HotThreads hotThreads={analysis.hot_threads} />
        </Section>
      )}

      <LLMPanel analysis={analysis} kind="thread" />

      {analysis.deadlocks?.length > 0 && (
        <Section label="// deadlocks" count={analysis.deadlocks.length}>
          <DeadlockView deadlocks={analysis.deadlocks} />
        </Section>
      )}

      {analysis.blocked_chains?.length > 0 && (
        <Section label="// blocking relationships" count={analysis.blocked_chains.length}>
          <BlockedChains chains={analysis.blocked_chains} />
        </Section>
      )}

      {analysis.stack_groups?.length > 0 && (
        <Section label="// stack-trace clusters" count={analysis.stack_groups.length}>
          <StackGroups groups={analysis.stack_groups} />
        </Section>
      )}

      <Section label="// threads" count={analysis.total_threads}>
        <ThreadsTable threads={analysis.threads} />
      </Section>

      <StateLegend />
    </div>
  )
}

function CaseFile({ analysis, filename }) {
  return (
    <div className="panel p-6 animate-fade-in">
      <div className="flex flex-wrap items-baseline gap-x-6 gap-y-2 text-sm">
        <div>
          <span className="label">case file</span>
          <div className="font-mono text-bone-200 mt-1">{filename || '<paste>'}</div>
        </div>
        {analysis.timestamp && (
          <div>
            <span className="label">captured</span>
            <div className="font-mono text-bone-200 mt-1">{analysis.timestamp}</div>
          </div>
        )}
        {analysis.jvm && (
          <div className="flex-1 min-w-[200px]">
            <span className="label">jvm</span>
            <div className="font-mono text-xs text-bone-400 mt-1 truncate">{analysis.jvm}</div>
          </div>
        )}
      </div>
    </div>
  )
}

function Summary({ analysis }) {
  return (
    <div className="panel p-6 md:p-8 animate-slide-up">
      <div className="label mb-3">// triage summary</div>
      <p className="text-bone-100 text-lg md:text-xl font-light leading-relaxed font-display tracking-tight">
        {analysis.summary}
      </p>
    </div>
  )
}

function StateBreakdown({ analysis }) {
  const states = analysis.state_breakdown || {}
  const total = analysis.total_threads
  const entries = Object.entries(states).sort((a, b) => b[1] - a[1])

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-3 animate-slide-up">
      <Stat label="total threads" value={total} />
      <Stat label="daemon" value={analysis.daemon_count} />
      <Stat label="deadlocks"
            value={analysis.deadlocks?.length || 0}
            critical={analysis.deadlocks?.length > 0} />
      <Stat label="findings" value={analysis.findings.length} />

      <div className="col-span-2 md:col-span-4 panel p-5">
        <div className="label mb-4">// thread state distribution</div>
        <div className="flex h-3 rounded-full overflow-hidden bg-ink-800">
          {entries.map(([state, n]) => (
            <div
              key={state}
              className={`${STATE_COLORS[state] || 'bg-bone-500'} transition-all`}
              style={{ width: `${(n / total) * 100}%` }}
              title={`${state}: ${n}`}
            />
          ))}
        </div>
        <div className="flex flex-wrap gap-x-5 gap-y-2 mt-4">
          {entries.map(([state, n]) => (
            <div key={state} className="flex items-center gap-2">
              <span className={`w-2.5 h-2.5 rounded-sm ${STATE_COLORS[state] || 'bg-bone-500'}`} />
              <span className="font-mono text-xs">
                <span className="text-bone-200">{state}</span>
                <span className="text-bone-500 ml-1">{n}</span>
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

function Stat({ label, value, critical }) {
  return (
    <div className={`panel p-5 ${critical ? 'border-flag-critical/40 bg-flag-critical/[0.03]' : ''}`}>
      <div className="label mb-2">{label}</div>
      <div className={`stat-num ${critical ? 'text-flag-critical' : ''}`}>
        {typeof value === 'number' ? value.toLocaleString() : value}
      </div>
    </div>
  )
}

function Section({ label, count, children }) {
  return (
    <section className="animate-slide-up">
      <div className="flex items-center justify-between mb-4">
        <div className="label text-bone-300">{label}</div>
        {count != null && <span className="badge-neutral">{count}</span>}
      </div>
      {children}
    </section>
  )
}

function DeadlockView({ deadlocks }) {
  return (
    <div className="space-y-4">
      {deadlocks.map((d, i) => (
        <div key={i} className="panel border-flag-critical/40 p-5">
          <div className="flex items-start gap-3 mb-4">
            <span className="badge-critical">deadlock #{i + 1}</span>
            <span className="label text-bone-500">{d.threads.length} threads</span>
          </div>
          <div className="flex flex-wrap items-center gap-2 font-mono text-sm">
            {d.threads.map((t, j) => (
              <span key={j} className="contents">
                <span className="px-3 py-1.5 bg-flag-critical/10 border border-flag-critical/30 text-flag-critical rounded">
                  {t}
                </span>
                <span className="text-flag-critical/60">→</span>
              </span>
            ))}
            <span className="px-3 py-1.5 bg-flag-critical/10 border border-flag-critical/30 text-flag-critical rounded">
              {d.threads[0]}
            </span>
            <span className="label text-flag-critical/70 ml-2">cycle</span>
          </div>
        </div>
      ))}
    </div>
  )
}

function BlockedChains({ chains }) {
  // Deduplicate by (waiter, holder)
  const seen = new Set()
  const dedup = chains.filter(c => {
    const k = `${c.waiter}|${c.holder}`
    if (seen.has(k)) return false
    seen.add(k)
    return true
  })
  return (
    <div className="panel p-5 overflow-x-auto">
      <table className="w-full text-sm font-mono">
        <thead>
          <tr className="text-left border-b border-ink-600/60">
            <th className="label pb-3">waiter</th>
            <th className="label pb-3"></th>
            <th className="label pb-3">holder</th>
            <th className="label pb-3">lock</th>
          </tr>
        </thead>
        <tbody>
          {dedup.map((c, i) => (
            <tr key={i} className="border-b border-ink-700/30 last:border-0">
              <td className="py-2.5 pr-4 text-flag-warning">{c.waiter}</td>
              <td className="py-2.5 pr-4 text-bone-500">→ waits on lock held by →</td>
              <td className="py-2.5 pr-4 text-bone-200">{c.holder}</td>
              <td className="py-2.5 text-bone-500 text-[11px]">{c.waiting_for_lock}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function StackGroups({ groups }) {
  return (
    <div className="space-y-2">
      {groups.map((g, i) => (
        <StackGroupItem key={i} g={g} />
      ))}
    </div>
  )
}

function StackGroupItem({ g }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="panel-inset overflow-hidden">
      <button onClick={() => setOpen(!open)} className="w-full p-4 flex items-center gap-4 text-left">
        <span className="font-display text-2xl font-light text-bone-100 tabular-nums w-12">
          {g.count}
        </span>
        <div className="flex-1 min-w-0">
          <div className="font-mono text-sm text-bone-200 truncate">
            {g.top_frames[0]}
          </div>
          <div className="font-mono text-xs text-bone-500 truncate">
            {g.top_frames[1] || '<end>'}
          </div>
        </div>
        <div className="flex gap-1 shrink-0">
          {Object.entries(g.states).map(([s, n]) => (
            <span key={s} className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-ink-700 text-bone-300">
              {s.slice(0, 3)}·{n}
            </span>
          ))}
        </div>
        <span className={`text-bone-500 font-mono text-xs transition-transform ${open ? 'rotate-90' : ''}`}>▸</span>
      </button>
      {open && (
        <div className="p-4 pt-0 pl-16 animate-fade-in">
          <div className="label mb-2">// shared top frames</div>
          <ol className="space-y-1 font-mono text-xs text-bone-300 mb-4">
            {g.top_frames.map((f, i) => (
              <li key={i} className="truncate">
                <span className="text-bone-500">at</span> {f}
              </li>
            ))}
          </ol>
          <div className="label mb-2">// threads in cluster</div>
          <div className="flex flex-wrap gap-1.5">
            {g.thread_names.slice(0, 20).map((t, i) => (
              <span key={i} className="font-mono text-[11px] px-2 py-0.5 rounded bg-ink-800 text-bone-300 border border-ink-600/60">
                {t}
              </span>
            ))}
            {g.thread_names.length > 20 && (
              <span className="font-mono text-[11px] text-bone-500">+{g.thread_names.length - 20}</span>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

function ThreadsTable({ threads }) {
  const [filter, setFilter] = useState('')
  const [stateFilter, setStateFilter] = useState('ALL')
  const [selected, setSelected] = useState(null)

  const states = useMemo(() => {
    const s = new Set(threads.map(t => t.state))
    return ['ALL', ...Array.from(s)]
  }, [threads])

  const filtered = useMemo(() => {
    const term = filter.trim().toLowerCase()
    return threads.filter(t => {
      if (stateFilter !== 'ALL' && t.state !== stateFilter) return false
      if (!term) return true
      if (t.name.toLowerCase().includes(term)) return true
      return t.stack.some(f => f.class_name.toLowerCase().includes(term))
    })
  }, [threads, filter, stateFilter])

  return (
    <div className="panel">
      <div className="p-4 border-b border-ink-600/60 flex flex-wrap gap-3 items-center">
        <input
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="filter by thread name or class…"
          className="flex-1 min-w-[200px] bg-ink-950 border border-ink-600/60 rounded px-3 py-1.5 font-mono text-xs text-bone-200 placeholder-bone-500 focus:outline-none focus:border-flag-warning/50"
        />
        <select
          value={stateFilter}
          onChange={(e) => setStateFilter(e.target.value)}
          className="bg-ink-950 border border-ink-600/60 rounded px-3 py-1.5 font-mono text-xs text-bone-200"
        >
          {states.map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        <span className="label">{filtered.length} / {threads.length}</span>
      </div>
      <div className="grid md:grid-cols-[1fr_2fr] divide-x divide-ink-600/40 max-h-[600px]">
        <div className="overflow-y-auto max-h-[600px]">
          {filtered.map((t, i) => (
            <button
              key={i}
              onClick={() => setSelected(t)}
              className={`w-full px-4 py-2.5 text-left border-b border-ink-700/40 hover:bg-ink-800/50 transition-colors ${selected === t ? 'bg-ink-800' : ''}`}
            >
              <div className="flex items-center gap-2 mb-0.5">
                <span className={`w-1.5 h-1.5 rounded-full ${STATE_COLORS[t.state] || 'bg-bone-500'}`} />
                <span className="font-mono text-xs text-bone-200 truncate">{t.name}</span>
                {t.daemon && <span className="label text-bone-500">daemon</span>}
              </div>
              <div className="font-mono text-[10px] text-bone-500 ml-3.5">
                {t.state} · {t.stack.length} frames
              </div>
            </button>
          ))}
        </div>
        <div className="overflow-y-auto max-h-[600px] p-5">
          {selected ? (
            <ThreadDetail t={selected} />
          ) : (
            <div className="text-bone-500 text-sm font-mono py-12 text-center">
              ← select a thread to inspect
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function ThreadDetail({ t }) {
  return (
    <div>
      <div className="mb-4">
        <div className="flex items-center gap-2 mb-1 flex-wrap">
          <span className={`badge-neutral`}>
            <span className={`w-1.5 h-1.5 rounded-full mr-1.5 inline-block ${STATE_COLORS[t.state]}`} />
            {t.state}
          </span>
          {t.state_detail && <span className="label text-bone-500">{t.state_detail}</span>}
          {t.daemon && <span className="badge-neutral">daemon</span>}
        </div>
        <h3 className="font-mono text-bone-100 text-base break-all">{t.name}</h3>
        <div className="font-mono text-[11px] text-bone-500 mt-1">
          {t.id && <>#{t.id} · </>}
          {t.tid && <>tid={t.tid} · </>}
          {t.nid && <>nid={t.nid}</>}
        </div>
      </div>

      {(t.locks?.length > 0) && (
        <div className="mb-4">
          <div className="label mb-2">// locks</div>
          <div className="space-y-1">
            {t.locks.map((l, i) => (
              <div key={i} className={`font-mono text-xs px-2 py-1 rounded ${
                l.op === 'locked' ? 'bg-flag-ok/10 text-flag-ok' : 'bg-flag-warning/10 text-flag-warning'
              }`}>
                {l.op} {l.address} <span className="opacity-60">({l.class_name})</span>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="label mb-2">// stack ({t.stack.length})</div>
      <ol className="space-y-0.5 font-mono text-xs">
        {t.stack.map((f, i) => (
          <li key={i} className="text-bone-300">
            <span className="text-bone-500">at</span> {f.class_name}.<span className="text-bone-100">{f.method}</span>
            {f.file && <span className="text-bone-500"> ({f.file}{f.line ? `:${f.line}` : ''})</span>}
            {f.is_native && <span className="text-flag-info ml-1">[native]</span>}
          </li>
        ))}
      </ol>
    </div>
  )
}
