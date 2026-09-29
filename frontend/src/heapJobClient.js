// Live metadata is small; fetch the saved report only when its revision changes.
// Polling keeps this usable behind proxies that buffer or disable SSE.
export function watchHeapJob(jobId, { onStatus, onReport, onError }, {
  request = fetch, Events = globalThis.EventSource, delay = 1000,
} = {}) {
  let active = true, stream = null, timer = null, watchdog = null, revision = -1
  let pending = null, processing = false, polling = false
  const base = `/api/jobs/${encodeURIComponent(jobId)}`
  const stop = () => { active = false; stream?.close(); clearTimeout(timer); clearTimeout(watchdog) }
  const json = async url => {
    const response = await request(url)
    if (!response.ok) throw new Error(`Could not refresh heap analysis (${response.status})`)
    return response.json()
  }
  const receive = async status => {
    if (!active) return
    pending = status
    if (processing) return
    processing = true
    try {
      while (active && pending) {
        const next = pending; pending = null
        onStatus(next)
        if (next.analysis_id && next.revision > revision) {
          const saved = await json(`/api/analyses/${next.analysis_id}`)
          if (!active) return
          onReport(saved.analysis)
          revision = next.revision
        }
        if (!['running', 'queued'].includes(next.status)) { stop(); return }
      }
    } catch (error) {
      if (active) { onError(error.message); fallback() }
    } finally { processing = false }
  }
  const poll = async () => {
    if (!active) return
    try { await receive(await json(`${base}?include_result=false`)) }
    catch (error) { if (active) onError(error.message) }
    if (active) timer = setTimeout(poll, delay)
  }
  const fallback = () => {
    stream?.close()
    clearTimeout(watchdog)
    if (!polling && active) { polling = true; timer = setTimeout(poll, delay) }
  }
  if (Events) {
    try { stream = new Events(`${base}/events`) } catch { fallback(); return stop }
    watchdog = setTimeout(fallback, 3000)
    stream.addEventListener('progress', event => {
      clearTimeout(watchdog)
      watchdog = setTimeout(fallback, 10000)
      try { receive(JSON.parse(event.data)) } catch { fallback() }
    })
    stream.addEventListener('removed', () => { onError('Background job is no longer available. Saved reports remain in history.'); stop() })
    stream.onerror = fallback
  } else fallback()
  return stop
}
