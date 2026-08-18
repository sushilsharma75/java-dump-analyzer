function fmtBytes(n) {
  if (n == null || n < 0) return '—'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let i = 0, v = n
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++ }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${units[i]}`
}

function fmtDuration(sec) {
  if (sec == null) return '—'
  if (sec < 60) return `${sec.toFixed(1)}s`
  const m = Math.floor(sec / 60)
  const s = Math.floor(sec % 60)
  return `${m}m ${s}s`
}

export default function HeapProgress({ phase, uploadProgress, jobStatus, filename }) {
  // phase: 'uploading' | 'parsing' | 'done'
  const upload = uploadProgress || { loaded: 0, total: 0 }
  const job = jobStatus || {}

  const uploadPct = upload.total > 0 ? (upload.loaded / upload.total) * 100 : 0
  const parsePct = job.bytes_total > 0 ? (job.bytes_processed / job.bytes_total) * 100 : 0

  return (
    <div className="max-w-3xl mx-auto pt-12 animate-fade-in">
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-3">
          <span className="label">// in progress</span>
          <div className="h-px flex-1 bg-ink-600/50" />
          <div className="w-1.5 h-1.5 bg-flag-info rounded-full animate-pulse" />
        </div>
        <h2 className="font-display text-3xl md:text-4xl font-light text-bone-100 mb-2 tracking-tightest">
          Analyzing heap dump
        </h2>
        {filename && (
          <p className="font-mono text-sm text-bone-500 truncate">{filename}</p>
        )}
      </div>

      <div className="space-y-4">
        {/* Upload phase */}
        <PhaseRow
          label="01 · Upload"
          status={phase === 'uploading' ? 'active' : 'done'}
          pct={phase === 'uploading' ? uploadPct : 100}
          detail={
            phase === 'uploading'
              ? `${fmtBytes(upload.loaded)} of ${fmtBytes(upload.total)}`
              : `${fmtBytes(upload.total)} received`
          }
        />

        {/* Parse phase */}
        <PhaseRow
          label="02 · Parse"
          status={
            phase === 'parsing'
              ? (job.status === 'error' ? 'error' : 'active')
              : phase === 'done' ? 'done' : 'pending'
          }
          pct={phase === 'parsing' || phase === 'done' ? parsePct : 0}
          detail={
            phase === 'parsing'
              ? `${fmtBytes(job.bytes_processed || 0)} of ${fmtBytes(job.bytes_total || 0)} · ${(job.instances_seen || 0).toLocaleString()} instances`
              : phase === 'done' ? 'complete' : 'queued'
          }
        />

        {/* Stats grid */}
        {phase === 'parsing' && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 pt-4">
            <Stat label="elapsed" value={fmtDuration(job.elapsed_seconds)} />
            <Stat label="eta" value={fmtDuration(job.eta_seconds)} />
            <Stat label="records" value={(job.records_seen || 0).toLocaleString()} />
            <Stat label="instances" value={(job.instances_seen || 0).toLocaleString()} />
          </div>
        )}

        {job.error && (
          <div className="panel border-flag-critical/40 bg-flag-critical/5 p-4">
            <span className="badge-critical mb-2 inline-block">error</span>
            <p className="font-mono text-sm text-flag-critical/90">{job.error}</p>
          </div>
        )}
      </div>
    </div>
  )
}

function PhaseRow({ label, status, pct, detail }) {
  const colorClass = {
    pending: 'bg-ink-700',
    active: 'bg-flag-info',
    done: 'bg-flag-ok',
    error: 'bg-flag-critical',
  }[status]
  const textClass = {
    pending: 'text-bone-500',
    active: 'text-flag-info',
    done: 'text-flag-ok',
    error: 'text-flag-critical',
  }[status]

  return (
    <div className="panel p-5">
      <div className="flex items-baseline justify-between mb-3 gap-4">
        <div className="font-mono text-sm">
          <span className={textClass}>{label}</span>
          {status === 'active' && (
            <span className="ml-2 inline-block w-1 h-1 bg-flag-info rounded-full animate-pulse" />
          )}
        </div>
        <span className="font-mono text-xs text-bone-400 tabular-nums">
          {pct.toFixed(1)}%
        </span>
      </div>
      <div className="h-1.5 bg-ink-800 rounded-full overflow-hidden">
        <div
          className={`h-full ${colorClass} transition-all duration-300`}
          style={{ width: `${Math.min(100, pct)}%` }}
        />
      </div>
      <div className="font-mono text-[11px] text-bone-500 mt-2 truncate">
        {detail}
      </div>
    </div>
  )
}

function Stat({ label, value }) {
  return (
    <div className="panel-inset p-3">
      <div className="label mb-1">{label}</div>
      <div className="font-mono text-lg text-bone-100 tabular-nums">{value}</div>
    </div>
  )
}
