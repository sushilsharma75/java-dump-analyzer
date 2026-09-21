import { useState, useEffect } from 'react'
import SourceSnippet from './SourceSnippet'

async function request(path, options) {
  const r = await fetch(path, options)
  const data = await r.json()
  if (!r.ok) throw new Error(data.detail || `Request failed (${r.status})`)
  return data
}
const post = body => ({ method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })

export default function Investigation({ analysis, sourceSession, onUpdate }) {
  const [capture, setCapture] = useState(analysis.capture || {})
  const [query, setQuery] = useState('')
  const [objects, setObjects] = useState([])
  const [offset, setOffset] = useState(0)
  const [object, setObject] = useState(null)
  const [paths, setPaths] = useState(null)
  const [threads, setThreads] = useState(null)
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  const [weak, setWeak] = useState(false)
  useEffect(() => { setCapture(analysis.capture || {}); setObjects([]); setObject(null); setPaths(null); setThreads(null) }, [analysis.analysis_id])
  const id = analysis.object_index_id
  const act = async fn => { setError(null); setBusy(true); try { await fn() } catch (e) { setError(e.message) } finally { setBusy(false) } }
  const inspect = oid => act(async () => {
    const data = await request(`/api/heap/${id}/objects/${encodeURIComponent(oid)}`)
    setObject(data); setPaths(null)
  })
  const search = page => act(async () => {
    setObjects(await request(`/api/heap/${id}/objects?class_name=${encodeURIComponent(query)}&offset=${page}`)); setOffset(page)
  })
  return <section className="panel p-5 space-y-4">
    <h3 className="font-display text-lg">Evidence and investigation</h3>
    <p className="text-sm text-bone-400">Source locations identify executing code or retaining fields. A matching source revision and compatible captures are needed before attributing a defect.</p>
    {error && <p role="alert" className="text-flag-critical">{error}</p>}
    <details><summary>Capture identity and source provenance</summary>
      <div className="space-y-3 p-3">
        {['process_id', 'process_start', 'captured_at', 'build_id'].map(k => <label key={k} className="block text-sm">{k.replaceAll('_', ' ')}
          <input className="w-full bg-ink-950 border rounded p-2" value={capture[k] || ''} placeholder={k.includes('at') || k === 'process_start' ? 'ISO timestamp, including timezone' : ''} onChange={e => setCapture({ ...capture, [k]: e.target.value || null })} />
        </label>)}
        <button disabled={busy || !analysis.analysis_id} className="btn-secondary" onClick={() => act(async () => onUpdate?.(await request(`/api/analyses/${analysis.analysis_id}/capture`, post(capture))))}>Save capture identity</button>
        {sourceSession && <button disabled={busy} className="btn-secondary" onClick={() => act(async () => onUpdate?.(await request(`/api/analyses/${analysis.analysis_id}/source/${sourceSession.session_id}`, post({}))))}>Refresh source locations</button>}
        <pre className="overflow-x-auto text-xs">{JSON.stringify(analysis.source_provenance, null, 2)}</pre>
      </div>
    </details>
    <details><summary>Analysis coverage and assumptions</summary>
      <pre className="overflow-x-auto text-xs p-3">{JSON.stringify({ parsing: analysis.parse_coverage, stages: analysis.stages, sizing: analysis.sizing_assumptions }, null, 2)}</pre>
    </details>
    <a className="btn-secondary" href={`/api/analyses/${analysis.analysis_id}`} download>Download complete analysis JSON</a>
    {id && <details><summary>Explore heap objects and GC roots</summary>
      <div className="space-y-3 p-3">
        <form onSubmit={e => { e.preventDefault(); search(0) }} className="flex gap-2">
          <input aria-label="Class name filter" className="bg-ink-950 border rounded p-2" placeholder="Class name" value={query} onChange={e => setQuery(e.target.value)} />
          <button className="btn-secondary" disabled={busy}>Search objects</button>
        </form>
        <div className="flex gap-2 flex-wrap">{(analysis.dominators || []).slice(0, 10).map(d => <button key={d.object_id} className="btn-secondary" disabled={busy} onClick={() => inspect(d.object_id)}>{d.class_name} · {d.object_id}</button>)}</div>
        {objects.map(o => <button className="block text-sm" key={o.oid} disabled={busy} onClick={() => inspect(o.oid)}>{o.oid} · {o.name || o.kind} · {o.shallow} shallow bytes</button>)}
        {!!objects.length && <div className="flex gap-2"><button className="btn-secondary" disabled={busy || !offset} onClick={() => search(Math.max(0, offset - 50))}>Previous objects</button><button className="btn-secondary" disabled={busy || objects.length < 50} onClick={() => search(offset + 50)}>Next objects</button></div>}
        {object && <div className="panel-inset p-3 space-y-3">
          <h4>{object.oid} · {object.name || object.kind}</h4>
          <pre className="overflow-x-auto text-xs">{JSON.stringify({ shallow_bytes: object.shallow, length: object.length, fields: object.values, collection: object.collection, roots: object.roots }, null, 2)}</pre>
          {['outgoing', 'incoming'].map(direction => <details key={direction} open><summary>{direction} references ({object[`${direction}_count`]})</summary>
            {(object[direction] || []).map((e, i) => <div key={i} className="text-sm"><button disabled={busy} onClick={() => inspect(direction === 'outgoing' ? e.dst : e.src)}>{e.src} → {e.field} → {e.dst} ({e.strength})</button></div>)}
          </details>)}
          <button className="btn-secondary" disabled={busy || (object.outgoing.length >= object.outgoing_count && object.incoming.length >= object.incoming_count)} onClick={() => act(async () => {
            const start = Math.max(object.outgoing.length, object.incoming.length)
            const next = await request(`/api/heap/${id}/objects/${object.oid}?offset=${start}`)
            setObject({ ...object, outgoing: [...object.outgoing, ...next.outgoing], incoming: [...object.incoming, ...next.incoming] })
          })}>More references</button>
          <label className="block text-sm"><input type="checkbox" checked={weak} onChange={e => { setWeak(e.target.checked); setPaths(null) }} /> Include Reference.referent edges</label>
          <button className="btn-secondary" disabled={busy} onClick={() => act(async () => setPaths(await request(`/api/heap/${id}/objects/${object.oid}/roots?include_weak=${weak}&source_session=${sourceSession?.session_id || ''}`)))}>Find paths to GC roots</button>
          {paths && <div><p className="text-sm">{paths.note} {paths.partial ? 'Search was limited.' : ''}</p>{paths.paths.map((p, i) => <div key={i} className="panel-inset p-3"><pre className="text-xs">{JSON.stringify(p.root)}</pre>{p.edges.map((e, j) => <div key={j}><button onClick={() => inspect(e.src)}>{e.src} → {e.field} → {e.dst}</button>{e.source && <SourceSnippet location={{ ...e.source, is_user_code: true }} />}</div>)}</div>)}</div>}
        </div>}
        <button className="btn-secondary" disabled={busy} onClick={() => act(async () => setThreads(await request(`/api/heap/${id}/threads`)))}>Inspect heap thread stacks and locals</button>
        {threads && <pre className="overflow-x-auto text-xs">{JSON.stringify(threads, null, 2)}</pre>}
      </div>
    </details>}
    <details><summary>Source method context</summary><SourceContext analysis={analysis} sourceSession={sourceSession} /></details>
  </section>
}

function SourceContext({ analysis, sourceSession }) {
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)
  const locations = (analysis.findings || []).flatMap(f => (f.source_locations || []).map(l => ({ ...l, evidence_id: f.evidence_id })))
  return <div className="p-3 space-y-2">
    {!sourceSession && <p>Attach source to retrieve method context.</p>}
    {locations.map((l, i) => <button key={i} className="block text-sm" disabled={!sourceSession} onClick={async () => {
      setError(null)
      try { setResult(await request(`/api/source/${sourceSession.session_id}/context?${new URLSearchParams({ class_name: l.class_name, method: l.method || '', ...(l.line ? { line: l.line } : {}) })}`)) }
      catch (e) { setError(e.message) }
    }}>{l.evidence_id} · {l.repo_path || l.class_name}:{l.line} · {l.role || 'candidate'}</button>)}
    {error && <p role="alert">{error}</p>}
    {result && <pre className="overflow-x-auto text-xs">{JSON.stringify(result, null, 2)}</pre>}
  </div>
}
