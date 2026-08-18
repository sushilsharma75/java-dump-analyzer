import Findings from './Findings'
import LLMPanel from './LLMPanel'
import VerdictBanner from './VerdictBanner'
import ExportReport from './ExportReport'

function fmtMb(mb) {
  if (mb == null) return '—'
  return mb >= 1024 ? `${(mb / 1024).toFixed(2)} GB` : `${mb.toFixed(0)} MB`
}

function fmtMs(ms) {
  if (ms == null) return '—'
  return ms >= 1000 ? `${(ms / 1000).toFixed(2)} s` : `${ms.toFixed(0)} ms`
}

export default function GCAnalysis({ analysis, filename }) {
  const a = analysis
  return (
    <div className="max-w-7xl mx-auto pt-8 space-y-8">
      <VerdictBanner verdict={a.verdict} summary={a.summary} />
      <CaseFile analysis={a} filename={filename} />
      <Stats analysis={a} />
      <ExportReport analysis={a} filename={filename} kind="gc" />

      <Section label="// garbage-collection timeline" count={a.gc_count}>
        <Charts events={a.events} trend={a.heap_after_trend_mb_per_min} />
      </Section>

      <Section label="// diagnostic findings" count={a.findings.length}>
        <Findings findings={a.findings} />
      </Section>

      <LLMPanel analysis={a} kind="gc" />
    </div>
  )
}

function CaseFile({ analysis, filename }) {
  return (
    <div className="panel p-6 animate-fade-in">
      <div className="flex flex-wrap items-baseline gap-x-6 gap-y-2 text-sm">
        <div>
          <span className="label">case file</span>
          <div className="font-mono text-bone-200 mt-1">{filename || '<upload>'}</div>
        </div>
        <div>
          <span className="label">collector</span>
          <div className="font-mono text-bone-200 mt-1">{analysis.collector}</div>
        </div>
        <div>
          <span className="label">logging</span>
          <div className="font-mono text-bone-200 mt-1">{analysis.jdk_logging}</div>
        </div>
        <div>
          <span className="label">window</span>
          <div className="font-mono text-bone-200 mt-1">{analysis.duration_s?.toFixed(0)}s</div>
        </div>
      </div>
    </div>
  )
}

function Stats({ analysis: a }) {
  const lowTput = a.throughput_pct < 90
  const leaky = a.heap_after_trend_mb_per_min > 1
  const trendStr = `${a.heap_after_trend_mb_per_min >= 0 ? '+' : ''}${a.heap_after_trend_mb_per_min.toFixed(1)} MB/min`
  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-3 animate-slide-up">
      <Stat label="throughput" value={`${a.throughput_pct.toFixed(1)}%`} critical={lowTput} />
      <Stat label="live-set trend" value={trendStr} critical={leaky} />
      <Stat label="full GCs" value={a.full_gc_count} critical={a.full_gc_count >= 3} />
      <Stat label="P99 pause" value={fmtMs(a.pause_p99_ms)} critical={a.pause_p99_ms > 1000} />
      <Stat label="gc events" value={a.gc_count?.toLocaleString() ?? '—'} />
      <Stat label="alloc rate" value={`${a.alloc_rate_mb_s?.toFixed(0)} MB/s`} critical={a.alloc_rate_mb_s > 512} />
      <Stat label="total pause" value={fmtMs(a.total_pause_ms)} />
      <Stat label="max pause" value={fmtMs(a.pause_max_ms)} critical={a.pause_max_ms > 1000} />
    </div>
  )
}

function Stat({ label, value, critical }) {
  return (
    <div className={`panel p-5 ${critical ? 'border-flag-critical/40 bg-flag-critical/[0.03]' : ''}`}>
      <div className="label mb-2">{label}</div>
      <div className={`stat-num ${critical ? 'text-flag-critical' : ''}`}>{value}</div>
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

// --- charts ----------------------------------------------------------------

function linreg(pts) {
  const n = pts.length
  if (n < 2) return null
  const mx = pts.reduce((s, p) => s + p.x, 0) / n
  const my = pts.reduce((s, p) => s + p.y, 0) / n
  let num = 0, den = 0
  for (const p of pts) { num += (p.x - mx) * (p.y - my); den += (p.x - mx) ** 2 }
  if (den === 0) return null
  const m = num / den
  return { m, b: my - m * mx }
}

function Charts({ events, trend }) {
  if (!events || events.length < 2) {
    return <div className="panel p-5 text-bone-500 font-mono text-sm">not enough GC events to chart</div>
  }
  return (
    <div className="grid md:grid-cols-2 gap-4">
      <HeapTrendChart events={events} trend={trend} />
      <PauseChart events={events} />
    </div>
  )
}

const W = 520, H = 150, PAD_L = 44, PAD_R = 12, PAD_T = 14, PAD_B = 22

function HeapTrendChart({ events, trend }) {
  const xs = events.map(e => e.timestamp_s)
  const x0 = Math.min(...xs), x1 = Math.max(...xs)
  const ymax = Math.max(...events.map(e => Math.max(e.after_mb, e.before_mb))) * 1.08 || 1
  const sx = (x) => PAD_L + ((x - x0) / (x1 - x0 || 1)) * (W - PAD_L - PAD_R)
  const sy = (y) => H - PAD_B - (y / ymax) * (H - PAD_T - PAD_B)

  const afterPts = events.map(e => ({ x: e.timestamp_s, y: e.after_mb }))
  const afterPath = afterPts.map((p, i) => `${i ? 'L' : 'M'}${sx(p.x).toFixed(1)},${sy(p.y).toFixed(1)}`).join(' ')
  const fit = linreg(afterPts)
  const leaky = trend > 1

  return (
    <ChartFrame
      title="Heap after GC — live-set trend"
      hint={leaky ? `climbing +${trend.toFixed(1)} MB/min` : 'stable post-GC floor'}
      hintCritical={leaky}
    >
      {[0, 0.5, 1].map((f) => (
        <g key={f}>
          <line x1={PAD_L} x2={W - PAD_R} y1={sy(ymax * f)} y2={sy(ymax * f)}
                stroke="currentColor" className="text-ink-600" strokeWidth="1" opacity="0.4" />
          <text x={PAD_L - 6} y={sy(ymax * f) + 3} textAnchor="end"
                className="fill-bone-500 font-mono" fontSize="9">{fmtMb(ymax * f)}</text>
        </g>
      ))}
      {/* post-GC occupancy line */}
      <path d={afterPath} fill="none" stroke="currentColor"
            className={leaky ? 'text-flag-critical' : 'text-flag-ok'} strokeWidth="1.6" />
      {/* regression / trend line */}
      {fit && (
        <line
          x1={sx(x0)} y1={sy(Math.max(0, fit.b + fit.m * x0))}
          x2={sx(x1)} y2={sy(Math.max(0, fit.b + fit.m * x1))}
          stroke="currentColor" className="text-bone-400" strokeWidth="1.2"
          strokeDasharray="4 3" opacity="0.8"
        />
      )}
    </ChartFrame>
  )
}

function PauseChart({ events }) {
  const xs = events.map(e => e.timestamp_s)
  const x0 = Math.min(...xs), x1 = Math.max(...xs)
  const pmax = Math.max(...events.map(e => e.pause_ms)) || 1
  const sx = (x) => PAD_L + ((x - x0) / (x1 - x0 || 1)) * (W - PAD_L - PAD_R)
  const sy = (y) => H - PAD_B - (y / pmax) * (H - PAD_T - PAD_B)
  const bw = Math.max(1, (W - PAD_L - PAD_R) / events.length - 1)

  return (
    <ChartFrame title="GC pause time" hint={`max ${fmtMs(pmax)}`} hintCritical={pmax > 1000}>
      {[0, 0.5, 1].map((f) => (
        <g key={f}>
          <line x1={PAD_L} x2={W - PAD_R} y1={sy(pmax * f)} y2={sy(pmax * f)}
                stroke="currentColor" className="text-ink-600" strokeWidth="1" opacity="0.4" />
          <text x={PAD_L - 6} y={sy(pmax * f) + 3} textAnchor="end"
                className="fill-bone-500 font-mono" fontSize="9">{fmtMs(pmax * f)}</text>
        </g>
      ))}
      {events.map((e, i) => {
        const full = e.phase === 'full' || e.phase === 'stall'
        const h = (H - PAD_B) - sy(e.pause_ms)
        return (
          <rect key={i} x={sx(e.timestamp_s)} y={sy(e.pause_ms)} width={bw} height={Math.max(0, h)}
                className={full ? 'fill-flag-critical' : 'fill-flag-info'} opacity={full ? 0.9 : 0.65} />
        )
      })}
    </ChartFrame>
  )
}

function ChartFrame({ title, hint, hintCritical, children }) {
  return (
    <div className="panel p-4">
      <div className="flex items-center justify-between mb-2">
        <div className="label text-bone-300">{title}</div>
        {hint && (
          <span className={`font-mono text-[10px] ${hintCritical ? 'text-flag-critical' : 'text-bone-500'}`}>
            {hint}
          </span>
        )}
      </div>
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-auto" preserveAspectRatio="xMidYMid meet">
        {children}
      </svg>
    </div>
  )
}
