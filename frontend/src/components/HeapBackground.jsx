export default function HeapBackground({ job, error, onCancel }) {
  if (!job) return null
  const running = ['running', 'queued'].includes(job.status)
  const scanning = job.scan_total > 0
  const seconds = Math.floor(job.elapsed_seconds || 0)
  const stageSeconds = Math.floor(job.stage_elapsed_seconds || 0)
  const bytes = n => `${((n || 0) / (1024 ** 3)).toFixed(2)} GiB`
  return <section className="panel p-5 space-y-3" aria-label="Background heap analysis">
    <div className="flex flex-wrap items-center gap-3">
      <h2 className="font-display text-lg">{running ? 'Report available · background analysis continues' : job.stage}</h2>
      {running && <button className="btn-secondary ml-auto" disabled={job.cancel_requested} onClick={onCancel}>
        {job.cancel_requested ? 'Stopping background analysis…' : 'Stop background analysis'}
      </button>}
    </div>
    {running && <p>{job.stage} · {Math.floor(seconds / 60)}m {seconds % 60}s total · {Math.floor(stageSeconds / 60)}m {stageSeconds % 60}s in this stage</p>}
    {running && <div>
      <p className="text-sm">{scanning
        ? `Scan pass ${job.scan_pass} · ${bytes(job.scan_bytes)} / ${bytes(job.scan_total)}`
        : 'Waiting for scan progress · analysis continues'}</p>
      <progress className="w-full" aria-label="Current scan progress"
        value={scanning ? job.scan_bytes : undefined} max={scanning ? job.scan_total : undefined} />
      <p className="text-sm text-bone-400">Progress is for this scan. More passes may follow; completion time is unknown.</p>
    </div>}
    <p className="text-sm text-bone-400">Saved findings remain available when you refresh or stop background analysis. Unfinished stages are shown in coverage.</p>
    {(error || job.error) && <p role="alert">{error || job.error}</p>}
  </section>
}
