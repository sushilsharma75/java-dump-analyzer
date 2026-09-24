import { useState } from 'react'

// Lifecycle markers carry a text glyph and label, never colour alone.
const MARKERS = [
  ['oom', 'OOM', 'OutOfMemoryError', 'text-flag-critical'],
  ['heap_dump', 'DUMP', 'automatic heap dump', 'text-bone-200'],
  ['server_start', 'START', 'server start', 'text-bone-200'],
  ['deploy', 'DEPLOY', 'deploy', 'text-bone-200'],
  ['undeploy', 'UNDEPLOY', 'undeploy', 'text-bone-200'],
]

const time = start => start.slice(11, 16)
// styles.css is a hand-written subset of utility classes; chart geometry is inline.
const ROW = { display: 'flex', gap: 2 }
const TINY = { fontSize: 9, lineHeight: 1.2 }

function describe(bucket, captures) {
  const parts = [`${time(bucket.start)} · ${bucket.errors.toLocaleString()} errors · ${bucket.warnings.toLocaleString()} warnings · ${bucket.total.toLocaleString()} events`]
  for (const [key, , label] of MARKERS) if (bucket[key]) parts.push(`${bucket[key]} ${label}`)
  for (const c of captures) if (c.bucket === bucket.start) parts.push(`${c.kind} dump captured`)
  return parts.join(' · ')
}

/** Errors per bucket before the capture, with memory and lifecycle events marked. */
export default function LogTimeline({ timeline }) {
  const [hover, setHover] = useState(null)
  if (!timeline?.buckets?.length) return null
  const { buckets, captures = [], bucket_minutes: minutes, basis } = timeline
  const max = Math.max(1, ...buckets.map(b => b.errors))
  const active = hover ?? buckets.findIndex(b => captures.some(c => c.bucket === b.start))
  return <section className="panel-inset p-4 space-y-3" aria-label="Log timeline">
    <div className="flex flex-wrap items-baseline justify-between gap-2">
      <h4 className="font-display text-base">{`Errors per ${minutes} minutes before the capture`}</h4>
      <span className="text-xs text-bone-500">{basis} · peak {max.toLocaleString()}</span>
    </div>
    {timeline.note && <p className="text-sm text-flag-warning" role="note">{timeline.note}</p>}
    <p className="text-sm text-bone-300" style={{ minHeight: '1.25rem' }} aria-live="polite">{active >= 0 ? describe(buckets[active], captures) : 'Hover a bar for details.'}</p>
    <div className="border-b border-ink-600/60" style={{ ...ROW, alignItems: 'flex-end', height: 128 }} onMouseLeave={() => setHover(null)}>
      {buckets.map((b, i) => {
        const captured = captures.some(c => c.bucket === b.start)
        return <div key={b.start} className="flex-1 h-full relative" style={{ display: 'flex', alignItems: 'flex-end' }}
                    onMouseEnter={() => setHover(i)} title={describe(b, captures)}>
          {captured && <div className="absolute inset-y-0" aria-hidden="true"
                            style={{ left: '50%', borderLeft: '1px dashed var(--bone-300)' }} />}
          <div className="w-full" style={{ height: b.errors ? `${Math.max(2, (b.errors / max) * 100)}%` : 0, borderRadius: '4px 4px 0 0',
               background: i === hover ? 'var(--flag-info)' : 'rgba(var(--flag-info-rgb), 0.7)' }} />
        </div>
      })}
    </div>
    <div className="font-mono" style={{ ...ROW, ...TINY }} aria-hidden="true">
      {buckets.map(b => <div key={b.start} className="flex-1 text-center overflow-hidden">
        {MARKERS.filter(([key]) => b[key]).map(([key, glyph, , tone]) => <div key={key} className={tone}>{glyph}</div>)}
        {captures.some(c => c.bucket === b.start) && <div className="text-bone-100">CAPTURE</div>}
      </div>)}
    </div>
    <div className="flex justify-between font-mono text-bone-500" style={{ fontSize: 10 }}>
      <span>{time(buckets[0].start)}</span><span>{time(buckets[buckets.length - 1].start)}</span>
    </div>
    <details><summary className="text-xs">Timeline table</summary>
      <table className="text-xs w-full mt-2">
        <thead><tr className="text-left text-bone-500"><th>Bucket</th><th>Errors</th><th>Warnings</th><th>Events</th><th>Markers</th></tr></thead>
        <tbody>{buckets.filter(b => b.total || MARKERS.some(([key]) => b[key])).map(b => <tr key={b.start}>
          <td>{b.start}</td><td>{b.errors}</td><td>{b.warnings}</td><td>{b.total}</td>
          <td>{MARKERS.filter(([key]) => b[key]).map(([key, , label]) => `${b[key]} ${label}`).join(', ')}</td>
        </tr>)}</tbody>
      </table>
    </details>
  </section>
}
