import SourceSnippet from './SourceSnippet'

function TraceSource({ location }) {
  if (!location) return null
  const context = location.context
  const methods = context?.related_field_methods || []
  return <div>
    <SourceSnippet location={location} />
    {context?.method && <details><summary>Recorded method context</summary>
      <SourceSnippet location={{ ...location, snippet: context.method }} />
      {context.method.truncated && <p>Method context truncated.</p>}
    </details>}
    {methods.length > 0 && <details><summary>Methods referencing this field ({methods.length})</summary>
      <p>Source candidates; field-name matches do not prove which call retained this object.</p>
      {methods.map((m, i) => <SourceSnippet key={i} location={{ ...location, method: m.method,
        line: m.start_line, role: m.role, snippet: m }} />)}
      {context.related_methods_omitted > 0 && <p>{context.related_methods_omitted} additional methods omitted.</p>}
    </details>}
  </div>
}

export default function RetentionTrace({ data, onInspect }) {
  if (!data) return null
  const object = (oid, info) => onInspect
    ? <button className="underline" onClick={() => onInspect(oid)}>{info?.name || info?.kind || 'object'} @ {oid}</button>
    : <span>{info?.name || info?.kind || 'object'} @ {oid}</span>
  return <div className="space-y-3 text-sm">
    <p>{data.note} {data.partial && 'Search was limited.'}</p>
    {data.source_attached === false && <p>Attach matching source and refresh source locations to resolve retaining fields.</p>}
    {!data.paths?.length && <p>No root path found within this search.</p>}
    {(data.paths || []).map((p, i) => <div key={i} className="panel-inset p-3 space-y-3">
      <h5>Root → retained object · path {i + 1}</h5>
      {p.root.map((r, j) => <div key={j}>
        <p>GC root: {r.kind_name || r.kind} · {object(r.oid, r.object)}</p>
        {r.thread != null && <p>Thread {r.thread} · stack {r.stack_status || 'not recorded'}</p>}
        {r.frames?.length > 0 && <details open><summary>Recorded root thread stack</summary>
          {r.frames.map((f, k) => <div key={k}>
            <p>#{f.index} {f.class_name}.{f.method_name} ({f.file_name}:{f.line}) {f.holds_root && '— holds this local root'}</p>
            <TraceSource location={f.source} />
          </div>)}
        </details>}
      </div>)}
      <ol className="space-y-3">{p.edges.map((e, j) => <li key={j}>
        <div>{object(e.src, e.owner)} → <strong>{e.field}</strong> → {object(e.dst, e.target)} ({e.strength})</div>
        <TraceSource location={e.source} />
        {!e.source && e.source_status === 'field_unresolved' && <p>Field declaration unavailable in the attached source.</p>}
      </li>)}</ol>
    </div>)}
  </div>
}
