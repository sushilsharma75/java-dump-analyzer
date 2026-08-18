/**
 * The first thing the user sees: a clear verdict on the dump.
 * Answers "is this JVM healthy?" before any detail.
 */
const VERDICTS = {
  critical: {
    badge: 'badge-critical',
    border: 'border-flag-critical/40',
    bg: 'bg-flag-critical/5',
    dot: 'bg-flag-critical',
    title: 'Critical problems found',
    text: 'This JVM has issues that are actively breaking things — start with the first finding below.',
  },
  degraded: {
    badge: 'badge-warning',
    border: 'border-flag-warning/40',
    bg: 'bg-flag-warning/5',
    dot: 'bg-flag-warning',
    title: 'Degraded — warning signs present',
    text: 'Nothing is fully broken, but the warnings below explain slowness or instability you may be seeing.',
  },
  healthy: {
    badge: 'badge-ok',
    border: 'border-flag-ok/30',
    bg: 'bg-flag-ok/[0.03]',
    dot: 'bg-flag-ok',
    title: 'Looks healthy',
    text: 'No deadlocks, contention, or leak signatures detected in this snapshot.',
  },
}

export default function VerdictBanner({ verdict, summary }) {
  const v = VERDICTS[verdict] || VERDICTS.healthy
  return (
    <div className={`panel ${v.border} ${v.bg} p-5 md:p-6 animate-fade-in`}>
      <div className="flex items-start gap-4">
        <span className={`${v.dot} w-2.5 h-2.5 rounded-full mt-1.5 shrink-0 ${verdict === 'critical' ? 'animate-pulse' : ''}`} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1 flex-wrap">
            <span className={v.badge}>{verdict}</span>
            <span className="label text-bone-500">// verdict</span>
          </div>
          <h2 className="font-display text-xl md:text-2xl text-bone-100 tracking-tight mb-2">
            {v.title}
          </h2>
          <p className="text-sm text-bone-300 leading-relaxed">{summary || v.text}</p>
        </div>
      </div>
    </div>
  )
}
