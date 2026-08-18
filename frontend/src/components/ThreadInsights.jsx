/**
 * Insight panels for thread dumps:
 *  - PoolsView: per-pool health with state distribution bars
 *  - HotThreads: CPU consumers ranked by share of lifetime
 *  - StateLegend: plain-English explanation of what each thread state means
 */

const POOL_HEALTH = {
  saturated: { badge: 'badge-critical', label: 'saturated' },
  busy: { badge: 'badge-warning', label: 'busy' },
  ok: { badge: 'badge-ok', label: 'ok' },
}

const STATE_BAR_COLORS = {
  RUNNABLE: 'bg-flag-ok',
  BLOCKED: 'bg-flag-critical',
  WAITING: 'bg-flag-info',
  TIMED_WAITING: 'bg-bone-500',
  NEW: 'bg-ink-500',
  TERMINATED: 'bg-ink-500',
}

export function PoolsView({ pools }) {
  if (!pools?.length) {
    return <div className="panel p-5 text-bone-500 font-mono text-sm">no pools with 3+ threads detected</div>
  }
  return (
    <div className="space-y-3">
      {pools.map((p, i) => {
        const h = POOL_HEALTH[p.health] || POOL_HEALTH.ok
        return (
          <div key={i} className="panel p-5">
            <div className="flex items-center gap-3 mb-3 flex-wrap">
              <span className={h.badge}>{h.label}</span>
              <span className="font-mono text-sm text-bone-100">{p.name}</span>
              <span className="font-mono text-xs text-bone-500 ml-auto tabular-nums">
                {p.total} threads · {p.busy_pct}% busy
              </span>
            </div>
            {/* Stacked state bar */}
            <div className="h-2 rounded-full overflow-hidden flex bg-ink-800 mb-2">
              {Object.entries(p.states).map(([state, n], j) => (
                <div
                  key={j}
                  className={STATE_BAR_COLORS[state] || 'bg-ink-500'}
                  style={{ width: `${(n / p.total) * 100}%` }}
                  title={`${state}: ${n}`}
                />
              ))}
            </div>
            <div className="flex flex-wrap gap-x-4 gap-y-1 mb-2">
              {Object.entries(p.states).sort((a, b) => b[1] - a[1]).map(([state, n], j) => (
                <span key={j} className="font-mono text-[11px] text-bone-400">
                  <span className={`inline-block w-2 h-2 rounded-sm mr-1.5 ${STATE_BAR_COLORS[state] || 'bg-ink-500'}`} />
                  {state} {n}
                </span>
              ))}
            </div>
            {p.note && <p className="text-sm text-bone-300 leading-relaxed">{p.note}</p>}
          </div>
        )
      })}
    </div>
  )
}

export function HotThreads({ hotThreads }) {
  if (!hotThreads?.length) {
    return (
      <div className="panel p-5 text-bone-500 font-mono text-sm">
        no CPU data — this dump format doesn't include cpu=/elapsed= fields (jstack from Java 11+ does)
      </div>
    )
  }
  const max = Math.max(...hotThreads.map(h => h.cpu_pct))
  return (
    <div className="panel overflow-hidden">
      <div className="grid grid-cols-[1fr_auto] gap-x-4 px-5 py-3 border-b border-ink-600/60 label">
        <span>thread · top frame</span>
        <span className="text-right">cpu share of lifetime</span>
      </div>
      {hotThreads.map((h, i) => (
        <div key={i} className="grid grid-cols-[1fr_auto] gap-x-4 px-5 py-2.5 border-b border-ink-700/30 last:border-0 items-center relative">
          <div
            className={`absolute inset-y-0 left-0 ${h.is_gc ? 'bg-flag-warning/[0.06]' : 'bg-flag-info/[0.06]'}`}
            style={{ width: `${(h.cpu_pct / Math.max(max, 1)) * 100}%` }}
          />
          <div className="min-w-0 relative z-10">
            <div className="font-mono text-xs text-bone-100 truncate">
              {h.name}
              {h.is_gc && <span className="badge-warning ml-2">gc</span>}
            </div>
            {h.top_frame && (
              <div className="font-mono text-[11px] text-bone-500 truncate">{h.top_frame}</div>
            )}
          </div>
          <div className="font-mono text-sm text-bone-100 text-right tabular-nums relative z-10">
            {h.cpu_pct}%
            <span className="text-[10px] text-bone-500 ml-1">({(h.cpu_ms / 1000).toFixed(0)}s/{h.elapsed_s.toFixed(0)}s)</span>
          </div>
        </div>
      ))}
    </div>
  )
}

const STATE_EXPLANATIONS = [
  ['RUNNABLE', 'bg-flag-ok', 'Executing or ready to execute. Note: threads blocked in native I/O (socket reads) also show as RUNNABLE.'],
  ['BLOCKED', 'bg-flag-critical', 'Waiting to enter a synchronized block someone else holds. Many of these = lock contention.'],
  ['WAITING', 'bg-flag-info', 'Parked indefinitely until notified — usually a pool thread waiting for work, or stuck waiting on a resource.'],
  ['TIMED_WAITING', 'bg-bone-500', 'Waiting with a timeout (sleep, poll, timed lock). Wakes by itself eventually.'],
]

export function StateLegend() {
  return (
    <div className="panel p-5">
      <div className="label mb-3">// what the states mean</div>
      <div className="grid md:grid-cols-2 gap-3">
        {STATE_EXPLANATIONS.map(([state, dot, text], i) => (
          <div key={i} className="flex gap-3 items-start">
            <span className={`${dot} w-2 h-2 rounded-sm mt-1.5 shrink-0`} />
            <div className="min-w-0">
              <div className="font-mono text-xs text-bone-100 mb-0.5">{state}</div>
              <p className="text-[13px] text-bone-400 leading-relaxed">{text}</p>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
