import { useEffect, useRef, useState } from 'react'
import RetentionTrace from './RetentionTrace'
import SourceSnippet from './SourceSnippet'
import { fmtBytes } from '../report'

export async function heapRequest(url, options) {
  const response = await fetch(url, options)
  const result = await response.json()
  if (!response.ok) throw new Error(typeof result.detail === 'string' ? result.detail : `Request failed (${response.status})`)
  return result
}
const post = body => ({ method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
const columns = {
  index: 'Index', logical_size: 'Logical size', backing_bytes: 'Backing bytes', class_name: 'Class / group', name: 'Class', oid: 'Object', instance_count: 'Instances',
  shallow_size_bytes: 'Shallow bytes', shallow_bytes: 'Shallow bytes', retained_bytes: 'Retained bytes',
  children: 'Children', loader: 'Classloader', kind: 'Kind', thread: 'Thread', frame: 'Frame',
  classes: 'Classes', copies: 'Copies', potential_bytes: 'Potential duplicate bytes',
  capacity: 'Capacity', occupied: 'Occupied', element_type: 'Element type', length: 'Length',
  pct_of_reachable: '% reachable', object_id: 'Object', constant_value: 'Constant value',
  string_object_bytes: 'String object bytes', distinct_backing_arrays: 'Backing arrays', backing_length: 'Backing length',
  thread_object: 'Thread object', value_object: 'Value object', key_object: 'Key object', key_status: 'Key status', recorded_referents: 'Recorded referents',
}
const bytes = new Set(['shallow_size_bytes', 'shallow_bytes', 'retained_bytes', 'potential_bytes', 'string_object_bytes', 'backing_bytes'])
const value = (key, v) => v == null ? 'Unavailable' : bytes.has(key) ? fmtBytes(v) : typeof v === 'number' ? v.toLocaleString() : String(v)

export function ResultTable({ rows = [], onInspect, onClass, onExpand, onSelect, selected = [], actions }) {
  const keys = Object.keys(columns).filter(k => rows.some(r => r[k] != null))
  if (!rows.length) return <p className="heap-empty">No matching results in this query’s scope.</p>
  return <div className="heap-table-scroll"><table className="heap-table">
    <thead><tr>{onSelect && <th>Select</th>}{keys.map(k => <th key={k}>{columns[k]}</th>)}{(onExpand || actions) && <th>Investigate</th>}</tr></thead>
    <tbody>{rows.map((r, i) => <tr key={`${r.oid || r.class_name || i}:${i}`}>
      {onSelect && <td>{r.oid && r.oid !== '0x0' && <input type="checkbox" aria-label={`Select ${r.oid}`} checked={selected.includes(r.oid)} onChange={() => onSelect(r.oid)} />}</td>}
      {keys.map(k => <td key={k} className={bytes.has(k) ? 'heap-number' : ''}>
        {['oid', 'thread_object', 'value_object', 'key_object'].includes(k) && r[k] && r[k] !== '0x0' && onInspect ? <button className="heap-link" onClick={() => onInspect(r[k])}>{r[k]}</button>
          : k === 'class_name' && onClass ? <button className="heap-link" onClick={() => onClass(r.class_name)}>{r.class_name}</button>
          : value(k, r[k])}
      </td>)}
      {(onExpand || actions) && <td>{onExpand && r.children > 0 && <button className="btn-secondary" onClick={() => onExpand(r.oid)}>Expand children</button>}{actions?.(r)}</td>}
    </tr>)}</tbody>
  </table></div>
}

function useQuery(url) {
  const [state, setState] = useState({ data: null, error: '', busy: false })
  useEffect(() => {
    if (!url) { setState({ data: null, error: '', busy: false }); return }
    const controller = new AbortController()
    setState({ data: null, error: '', busy: true })
    heapRequest(url, { signal: controller.signal }).then(data => {
      if (!controller.signal.aborted) setState({ data, error: '', busy: false })
    }).catch(e => { if (!controller.signal.aborted) setState({ data: null, error: e.message, busy: false }) })
    return () => controller.abort()
  }, [url])
  return state
}

function Pager({ offset, limit, total, onPage }) {
  return <div className="heap-toolbar"><span>{total ? `${offset + 1}–${Math.min(offset + limit, total)} of ${total.toLocaleString()}` : '0 results'}</span>
    <button className="btn-secondary" disabled={offset === 0} onClick={() => onPage(Math.max(0, offset - limit))}>Previous</button>
    <button className="btn-secondary" disabled={offset + limit >= total} onClick={() => onPage(offset + limit)}>Next</button>
  </div>
}

function QueryStatus({ state }) {
  return <>{state.busy && <p role="status">Loading investigation…</p>}{state.error && <p role="alert" className="heap-unavailable">{state.error}</p>}</>
}

export function HeapThreads({ threads, onInspect }) {
  if (!threads?.length) return <p className="heap-empty">No thread roots were recorded.</p>
  return threads.map((t, i) => <details className="heap-thread" key={i}><summary>Thread {t.thread_serial ?? t.thread ?? i} · {t.stack_status || 'not recorded'}</summary>
    {(t.frames || []).map((f, j) => <p className="font-mono text-xs" key={j}>#{j} {f.class_name}.{f.method_name} ({f.file_name}:{f.line})</p>)}
    {(t.locals || []).map((r, j) => <p key={j}>Frame {r.frame} · {r.kind} · <button className="heap-link" onClick={() => onInspect(r.oid)}>{r.oid}</button></p>)}
  </details>)
}

function ObjectInspector({ id, oid, sourceSession, onInspect, onRetained, onBookmark, onClose }) {
  const state = useQuery(oid ? `/api/heap/${id}/objects/${encodeURIComponent(oid)}` : null)
  const [paths, setPaths] = useState(null)
  const [collection, setCollection] = useState(null)
  const [error, setError] = useState('')
  const [allReferences, setAllReferences] = useState(false)
  const [busy, setBusy] = useState(false)
  const [extra, setExtra] = useState({ incoming: [], outgoing: [] })
  const generation = useRef(0)
  useEffect(() => { generation.current++; setPaths(null); setCollection(null); setError(''); setBusy(false); setExtra({ incoming: [], outgoing: [] }) }, [oid, sourceSession?.session_id, allReferences])
  const act = async fn => {
    const current = generation.current
    setBusy(true); setError('')
    try { const apply = await fn(); if (generation.current === current) apply?.() }
    catch (e) { if (generation.current === current) setError(e.message) }
    finally { if (generation.current === current) setBusy(false) }
  }
  const o = state.data
  return <aside className="heap-inspector panel" aria-label="Object inspector">
    <div className="heap-toolbar"><h3>Object inspector</h3><button className="btn-secondary" onClick={onClose}>Close</button></div>
    <QueryStatus state={state} />
    {o && <>
      <h4>{o.name || o.kind}</h4><p className="font-mono">{o.oid}</p>
      <dl className="heap-facts"><dt>Shallow</dt><dd>{fmtBytes(o.shallow)}</dd><dt>Retained</dt><dd>{o.retained_bytes == null ? 'Unavailable' : fmtBytes(o.retained_bytes)}</dd><dt>Length</dt><dd>{o.length ?? 'Unavailable'}</dd></dl>
      {o.display_value && <p className="heap-value">{o.display_value.text}{o.display_value.partial && '… (preview)'}</p>}
      <div className="heap-toolbar"><button className="btn-secondary" onClick={() => onRetained([oid])}>Retained set</button><button className="btn-secondary" onClick={() => onBookmark(oid)}>Bookmark</button>{o.dominator && o.dominator !== '0x0' && <button className="btn-secondary" onClick={() => onInspect(o.dominator)}>Immediate dominator</button>}</div>
      <details open><summary>Fields and recorded values</summary><table className="heap-table"><thead><tr><th>Field</th><th>Value</th></tr></thead><tbody>{Object.entries(o.values || {}).map(([k, v]) => <tr key={k}><td>{k}</td><td>{Array.isArray(v) ? v.join(', ') : String(v)}</td></tr>)}</tbody></table></details>
      {o.collection && <details open><summary>Observed collection metrics</summary><dl className="heap-facts">{Object.entries(o.collection).map(([k, v]) => <div key={k}><dt>{k.replaceAll('_', ' ')}</dt><dd>{String(v ?? 'Unavailable')}</dd></div>)}</dl><p className="heap-muted">Field-layout observations; capacity and collision semantics depend on the collection implementation.</p></details>}
      {o.collection && <button className="btn-secondary" disabled={busy} onClick={() => act(async () => { const next = await heapRequest(`/api/heap/${id}/objects/${oid}/collection`); return () => setCollection(next) })}>Inspect logical collection entries</button>}
      {collection && <><p>{collection.note} · {collection.complete ? 'Complete supported layout' : 'Partial traversal'}</p><ResultTable rows={collection.rows} onInspect={onInspect} /><Pager offset={collection.offset} limit={50} total={collection.total} onPage={page => act(async () => { const next = await heapRequest(`/api/heap/${id}/objects/${oid}/collection?offset=${page}`); return () => setCollection(next) })} /></>}
      {['incoming', 'outgoing'].map(direction => {
        const refs = [...o[direction], ...extra[direction]]
        return <details open key={direction}><summary>{direction} references · {refs.length} / {o[`${direction}_count`]}</summary>
          <ul className="heap-references">{refs.map((e, i) => <li key={i}><span>{e.field} · {e.strength}</span><button className="heap-link" onClick={() => onInspect(direction === 'incoming' ? e.src : e.dst)}>{direction === 'incoming' ? e.src : e.dst}</button></li>)}</ul>
          <button className="btn-secondary" disabled={busy || refs.length >= o[`${direction}_count`]} onClick={() => act(async () => {
            const next = await heapRequest(`/api/heap/${id}/objects/${oid}?offset=${refs.length}`)
            return () => setExtra(prev => ({ ...prev, [direction]: [...prev[direction], ...next[direction]] }))
          })}>More {direction}</button>
        </details>
      })}
      <label className="heap-toolbar"><input type="checkbox" checked={allReferences} onChange={e => setAllReferences(e.target.checked)} /> Include Reference.referent edges</label>
      <button disabled={busy} className="btn-primary" onClick={() => act(async () => {
        const result = await heapRequest(`/api/heap/${id}/objects/${oid}/roots?${new URLSearchParams({ include_weak: allReferences, ...(sourceSession ? { source_session: sourceSession.session_id } : {}) })}`)
        return () => setPaths(result)
      })}>Explain retention and source</button>
      {busy && <p role="status">Loading evidence…</p>}{error && <p role="alert">{error}</p>}
      <RetentionTrace data={paths} onInspect={onInspect} />
    </>}
  </aside>
}

const tabs = ['Histogram', 'Dominators', 'Leak suspects', 'Objects', 'GC roots', 'Threads', 'Classloaders', 'Memory waste', 'Queries', 'Notes']
const queryCatalog = [
  ['Histogram', 'Find classes by count or shallow memory'], ['Dominators', 'Find owners and expand retained children'],
  ['Leak suspects', 'Individual owners and groups above a threshold'], ['GC roots', 'Browse recorded root objects'],
  ['Classloaders', 'Classes and instances grouped by defining loader'], ['Memory waste', 'Duplicate, empty and sparse arrays'],
]

export default function HeapWorkbench({ analysis, sourceSession }) {
  const id = analysis.analysis_id
  const [tab, setTab] = useState('Histogram')
  const [query, setQuery] = useState('')
  const [sort, setSort] = useState('shallow_size_bytes')
  const [descending, setDescending] = useState(true)
  const [group, setGroup] = useState('class')
  const [domGroup, setDomGroup] = useState('object')
  const [parent, setParent] = useState('0x0')
  const [offset, setOffset] = useState(0)
  const [limit, setLimit] = useState(50)
  const [threshold, setThreshold] = useState(10)
  const [waste, setWaste] = useState('duplicate_arrays')
  const [selected, setSelected] = useState([])
  const [inspecting, setInspecting] = useState(null)
  const [navigation, setNavigation] = useState([])
  const [pinned, setPinned] = useState(false)
  const [result, setResult] = useState(null)
  const [operationError, setOperationError] = useState('')
  const [operationBusy, setOperationBusy] = useState(false)
  const [notes, setNotes] = useState(analysis.investigation_notes?.text || '')
  const [bookmarks, setBookmarks] = useState(analysis.investigation_notes?.bookmarks || [])
  const [history, setHistory] = useState([])
  const [saved, setSaved] = useState(false)
  const requestGeneration = useRef(0)
  const indexed = Boolean(analysis.object_index_id)
  const changeTab = name => { requestGeneration.current++; setOperationBusy(false); setOperationError(''); setResult(null); setOffset(0); setTab(name); setHistory(h => [name, ...h.filter(x => x !== name)].slice(0, 10)) }
  const inspect = oid => { setNavigation(h => inspecting ? [...h, inspecting].slice(-50) : h); setInspecting(oid) }
  const params = new URLSearchParams({ offset, limit })
  let endpoint = null
  if (tab === 'Histogram') endpoint = `histogram?${params}&${new URLSearchParams({ query, sort, descending, group })}`
  if (tab === 'Dominators') endpoint = `dominators?${params}&${new URLSearchParams({ parent, group: domGroup })}`
  if (tab === 'Leak suspects') endpoint = `suspects?${params}&threshold=${threshold}`
  if (tab === 'Objects') endpoint = `objects?${params}&class_name=${encodeURIComponent(query)}`
  if (tab === 'GC roots') endpoint = `roots?${params}`
  if (tab === 'Threads') endpoint = 'threads'
  if (tab === 'Classloaders') endpoint = `loaders?${params}`
  if (tab === 'Memory waste') endpoint = waste === 'unreachable' ? `unreachable?${params}` : `waste?${params}&query=${waste}`
  const state = useQuery(id && endpoint && (tab === 'Histogram' || indexed) ? `/api/heap/${id}/${endpoint}` : null)
  const data = Array.isArray(state.data) ? { rows: state.data.map(r => ({ ...r, class_name: r.name || r.kind, shallow_bytes: r.shallow })), total: offset + state.data.length + (state.data.length === limit ? 1 : 0) } : state.data
  const act = async fn => {
    const generation = ++requestGeneration.current
    setOperationBusy(true); setOperationError('')
    try { const next = await fn(); if (generation === requestGeneration.current) setResult(next) }
    catch (e) { if (generation === requestGeneration.current) setOperationError(e.message) }
    finally { if (generation === requestGeneration.current) setOperationBusy(false) }
  }
  const retained = objects => act(() => heapRequest(`/api/heap/${id}/retained-set`, post({ objects })))
  const merged = objects => act(() => heapRequest(`/api/heap/${id}/merged-paths`, post({ objects: objects.slice(0, 20), source_session: sourceSession?.session_id })))
  const sourceRefs = class_name => act(async () => ({ sourceReferences: await heapRequest(`/api/source/${sourceSession.session_id}/references?class_name=${encodeURIComponent(class_name)}`) }))
  const bookmark = oid => { setBookmarks(xs => [...new Set([...xs, oid])].slice(0, 100)); setSaved(false) }
  const select = oid => setSelected(xs => xs.includes(oid) ? xs.filter(x => x !== oid) : [...xs, oid].slice(0, 200))
  return <section className="heap-workbench panel" aria-label="Heap investigation workspace">
    <header className="heap-workbench-header"><div><h2>Heap investigation</h2><p className="heap-muted">Follow memory consumers to owners, GC roots and application code.</p></div>
      <div className="heap-toolbar"><span className="badge-info">{analysis.engine || 'native'} · {analysis.input_format?.format || 'HPROF'}</span><span>{analysis.histogram_complete ? 'Complete histogram' : 'Partial / legacy histogram'}</span><span>{indexed ? 'Object index available' : 'Object index unavailable'}</span></div>
    </header>
    <nav className="heap-tabs" aria-label="Investigation views">{tabs.map(name => <button key={name} aria-current={tab === name ? 'page' : undefined} onClick={() => changeTab(name)}>{name}</button>)}</nav>
    <div className={`heap-layout${inspecting ? ' with-inspector' : ''}`}><div className="heap-main">
      <div className="heap-toolbar"><h3>{tab}</h3>{!['Threads', 'Queries', 'Notes'].includes(tab) && <label>Rows <select value={limit} onChange={e => { setLimit(Number(e.target.value)); setOffset(0) }}>{[25, 50, 100, 200].map(n => <option key={n}>{n}</option>)}</select></label>}</div>
      {['Histogram', 'Objects'].includes(tab) && <div className="heap-toolbar"><label>Class search <input value={query} placeholder="Package or class name" onChange={e => { setQuery(e.target.value); setOffset(0) }} /></label></div>}
      {tab === 'Histogram' && <div className="heap-toolbar">
        <label>Group <select value={group} onChange={e => { setGroup(e.target.value); setOffset(0) }}><option value="class">Class</option><option value="package">Package</option></select></label>
        <label>Sort <select value={sort} onChange={e => { setSort(e.target.value); setOffset(0) }}><option value="shallow_size_bytes">Shallow bytes</option><option value="instance_count">Instances</option><option value="class_name">Class name</option></select></label>
        <button className="btn-secondary" onClick={() => setDescending(v => !v)}>{descending ? 'Descending' : 'Ascending'}</button>
        <a className="btn-secondary" href={`/api/heap/${id}/histogram.csv?${new URLSearchParams({ query, group })}`}>Export filtered CSV</a>
        {data && !data.complete && <p className="heap-unavailable">This histogram is incomplete. Missing classes must not be interpreted as zero.</p>}
      </div>}
      {tab === 'Dominators' && <div className="heap-toolbar"><span>Children of {parent}</span><button className="btn-secondary" onClick={() => { setParent('0x0'); setOffset(0) }}>Top owners</button><button className="btn-secondary" disabled={parent === '0x0' || !data?.parent_of_parent} onClick={() => { setParent(data.parent_of_parent); setOffset(0) }}>Parent</button><label>Group <select value={domGroup} onChange={e => { setDomGroup(e.target.value); setOffset(0) }}><option value="object">Object</option><option value="class">Class</option><option value="loader">Loader</option></select></label></div>}
      {tab === 'Leak suspects' && <label className="heap-toolbar">Minimum % of reachable heap <input type="number" min="0" max="100" value={threshold} onChange={e => { setThreshold(Math.max(0, Math.min(100, Number(e.target.value)))); setOffset(0) }} /><span>Minimum size: 1 MiB</span></label>}
      {tab === 'Memory waste' && <label className="heap-toolbar">Query <select value={waste} onChange={e => { setWaste(e.target.value); setOffset(0) }}><option value="duplicate_arrays">Duplicate arrays</option><option value="empty_arrays">Empty arrays</option><option value="sparse_arrays">Sparse object arrays (&lt;50% occupied)</option><option value="collections">Collection utilization (supported layouts)</option><option value="constant_arrays">Constant primitive arrays</option><option value="duplicate_strings">Duplicate strings (supported layouts)</option><option value="threadlocals">ThreadLocal entries</option><option value="references">Reference statistics</option><option value="unreachable">Unreachable object histogram</option></select></label>}
      {endpoint && tab !== 'Histogram' && !indexed && <p className="heap-unavailable">Unavailable: object indexing did not complete. {analysis.skipped_analyses?.find(s => s.stage === 'object index')?.reason || 'Check analysis coverage for the configured limits or failure.'} Deep retention mode does not lift object-index or dominator limits.</p>}
      <QueryStatus state={state} />
      {data?.note && <p className="heap-muted">{data.note}</p>}
      {tab === 'Threads' && state.data && <HeapThreads threads={state.data} onInspect={inspect} />}
      {tab !== 'Threads' && data && <><ResultTable rows={data.rows} onInspect={inspect}
        onClass={tab === 'Histogram' ? name => { setQuery(name); changeTab('Objects') } : undefined}
        onExpand={tab === 'Dominators' ? oid => { setParent(oid); setOffset(0) } : undefined}
        onSelect={indexed && ['Dominators', 'Objects', 'GC roots'].includes(tab) ? select : undefined} selected={selected}
        actions={tab === 'Histogram' && sourceSession ? r => <button className="btn-secondary" onClick={() => sourceRefs(r.class_name)}>Source references</button> : tab === 'Leak suspects' ? r => <><button className="btn-secondary" disabled={operationBusy} onClick={() => merged(r.sample_ids)}>Explain paths and source{r.instance_count > 20 ? ' (20 samples)' : ''}</button>{r.oid && <button className="btn-secondary" onClick={() => retained([r.oid])}>Retained classes</button>}</> : undefined} />
        <Pager offset={offset} limit={limit} total={data.total || 0} onPage={setOffset} /></>}
      {selected.length > 0 && <div className="heap-toolbar"><span>{selected.length} selected</span><button className="btn-secondary" disabled={operationBusy} onClick={() => retained(selected)}>Calculate retained set</button><button className="btn-secondary" disabled={operationBusy || selected.length > 20} onClick={() => merged(selected)}>Merge root paths (up to 20)</button><button className="btn-secondary" onClick={() => setSelected([])}>Clear selection</button></div>}
      {operationBusy && <p role="status">Calculating evidence…</p>}{operationError && <p role="alert" className="heap-unavailable">{operationError}</p>}
      {result && <div className="heap-query-result"><button className="btn-secondary" onClick={() => setResult(null)}>Close result</button>
        {result.paths && <RetentionTrace data={result} onInspect={inspect} />}
        {result.rows && <><h4>Retained set · {fmtBytes(result.retained_bytes)} · {result.object_count} objects</h4><p>{result.semantics}</p><ResultTable rows={result.rows} onInspect={inspect} /><Pager offset={result.offset} limit={50} total={result.total} onPage={page => act(() => heapRequest(`/api/heap/${id}/retained-set`, post({ objects: result.selection, offset: page })))} /></>}
        {result.sourceReferences && <><h4>Source references · candidates</h4><p>These references do not establish which call allocated or retained the selected objects.</p>{result.sourceReferences.map((r, i) => <SourceSnippet key={i} location={{ ...r, is_user_code: true }} />)}{!result.sourceReferences.length && <p>No unambiguous references resolved.</p>}</>}
      </div>}
      {tab === 'Queries' && <><p>Choose an investigation. These queries run inside this analyzer. General OQL syntax is not supported.</p><div className="heap-query-catalog">{queryCatalog.map(([name, description]) => <button className="panel-inset" key={name} onClick={() => changeTab(name)}><strong>{name}</strong><span>{description}</span></button>)}</div><h4>Recent views (this session)</h4>{history.map(name => <button className="btn-secondary" key={name} onClick={() => changeTab(name)}>{name}</button>)}</>}
      {tab === 'Notes' && <><label>Snapshot notes<textarea className="heap-notes" maxLength={20000} value={notes} onChange={e => { setNotes(e.target.value); setSaved(false) }} /></label><h4>Bookmarked objects</h4>{bookmarks.map(oid => <div className="heap-toolbar" key={oid}><button className="heap-link" onClick={() => inspect(oid)}>{oid}</button><button className="btn-secondary" onClick={() => { setBookmarks(xs => xs.filter(x => x !== oid)); setSaved(false) }}>Remove</button></div>)}<button className="btn-primary" disabled={operationBusy} onClick={() => act(async () => { await heapRequest(`/api/heap/${id}/notes`, { ...post({ text: notes, bookmarks }), method: 'PUT' }); setSaved(true); return null })}>Save notes and bookmarks</button>{saved && <p role="status">Saved with this snapshot.</p>}<p><a className="heap-link" href={`/api/heap/${id}/diagnostics`} target="_blank" rel="noreferrer">Analysis diagnostics</a></p></>}
    </div>
    {inspecting && <div><div className="heap-toolbar"><button className="btn-secondary" disabled={!navigation.length} onClick={() => { setInspecting(navigation.at(-1)); setNavigation(h => h.slice(0, -1)) }}>Back</button><label><input type="checkbox" checked={pinned} onChange={e => setPinned(e.target.checked)} /> Keep inspector open</label></div><ObjectInspector key={inspecting} id={id} oid={inspecting} sourceSession={sourceSession} onInspect={inspect} onRetained={retained} onBookmark={bookmark} onClose={() => { if (!pinned) setInspecting(null) }} /></div>}
    </div>
  </section>
}
