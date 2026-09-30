import FileUpload from './FileUpload'
import { useState } from 'react'

export function downloadDatabaseReport(analysis, format) {
  const content = format === 'json' ? JSON.stringify(analysis, null, 2) : databaseReportHTML(analysis)
  const url = URL.createObjectURL(new Blob([content], { type: format === 'json' ? 'application/json' : 'text/html' }))
  const a = document.createElement('a'); a.href = url
  a.download = `stack-analyser-database-${analysis.analysis_id}.${format}`; a.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

export function databaseReportHTML(analysis) {
  const escape = value => String(value ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]))
  const score = analysis.score.score == null ? 'Unavailable — workload evidence needed' : `${analysis.score.score}/100`
  return `<!doctype html><html><head><meta charset="utf-8"><title>Stack Analyser — Database report</title></head><body><h1>Stack Analyser</h1><h2>${escape(analysis.summary)}</h2><p>${escape(analysis.score_label)}: ${escape(score)}</p><h2>Coverage</h2><pre>${escape(JSON.stringify(analysis.coverage, null, 2))}</pre><h2>Limitations</h2><ul>${analysis.limitations.map(x => `<li>${escape(x)}</li>`).join('')}</ul>${analysis.findings.map(f => `<article><h2>${escape(f.severity)} · ${escape(f.title)}</h2><p>${escape(f.evidence_id)} · ${escape(f.affected_object)} · confidence: ${escape(f.confidence)}</p><pre>${escape(JSON.stringify(f.evidence, null, 2))}</pre><p>${escape(f.suggested_action)}</p></article>`).join('')}${analysis.schema_catalog ? `<h2>Schema and stored routines</h2><pre>${escape(JSON.stringify(analysis.schema_catalog, null, 2))}</pre>` : ''}</body></html>`
}

export async function downloadDatabaseArtifact(identifier, format, printWindow = null) {
  const response = await fetch(`/api/database/${encodeURIComponent(identifier)}/report?fmt=${format}`)
  if (!response.ok) throw new Error(await response.text())
  const url = URL.createObjectURL(await response.blob())
  if (printWindow) {
    printWindow.onload = () => { printWindow.focus(); printWindow.print() }
    printWindow.location.href = url
  } else {
    const link = document.createElement('a')
    link.href = url
    link.download = `stack-analyser-database-${identifier}.${format === 'tasks' ? 'tasks.md' : format === 'schema' ? 'schema.json' : format}`
    link.click()
  }
  setTimeout(() => URL.revokeObjectURL(url), printWindow ? 60_000 : 1000)
}

export function DatabaseUpload({ onUpload, loading }) {
  const [current, setCurrent] = useState(null)
  const [baseline, setBaseline] = useState(null)
  const [ddl, setDdl] = useState([])
  const [engine, setEngine] = useState('postgres')
  const [clientAlias, setClientAlias] = useState('')
  const uploadError = ddl.length > 20 ? 'Select at most 20 SQL files.'
    : ddl.reduce((total, file) => total + file.size, 0) > 5 * 1024 * 1024 ? 'SQL files must total no more than 5 MiB.'
    : baseline && !current ? 'A baseline needs a current snapshot.' : null
  return <section className="panel p-6 mb-8">
    <h2 className="text-2xl text-bone-100 mb-2">Database Snapshot</h2>
    <p className="text-sm text-bone-400 mb-4">PostgreSQL, MySQL and MariaDB diagnostics powered by DBDoctor. Upload collector JSON (up to 10 MiB), SQL definitions, or both. Add an older snapshot from the same database to estimate rates.</p>
    <label className="block text-sm mb-4">Database name (optional)
      <input className="field mt-2" value={clientAlias} maxLength={120} disabled={loading} onChange={event => setClientAlias(event.target.value)} placeholder="e.g. Orders production" />
    </label>
    <div className="database-upload-grid">
      <FileUpload label="Current snapshot" accept=".json,application/json" formats="JSON · up to 10 MiB" loading={loading} file={current} onFile={setCurrent} onClear={() => setCurrent(null)} />
      <FileUpload label="Baseline snapshot (optional)" accept=".json,application/json" formats="JSON · an older capture from the same database" loading={loading} file={baseline} onFile={setBaseline} onClear={() => setBaseline(null)} />
    </div>
    <div className="mt-4">
      <label htmlFor="database-ddl-files" className="block text-sm mb-2">Combined DDL file — table schema and stored procedures (optional)</label>
      <input id="database-ddl-files" type="file" multiple accept=".sql,.ddl,text/plain,application/sql" disabled={loading} onChange={event => setDdl(Array.from(event.target.files || []))} />
      <p className="text-sm text-bone-400 mt-2">Upload one file containing your table schemas, indexes and stored procedures together. The analyser detects each definition in that file; separate schema and procedure files are not required. PostgreSQL function bodies and MySQL / MariaDB DELIMITER blocks are supported.</p>
      <p className="text-sm text-bone-400 mt-2">Up to 20 UTF-8 SQL files, 5 MiB combined. SQL is inspected without execution; source files are not saved.</p>
      {ddl.length > 0 && <ul className="text-sm mt-2">{ddl.map((file, index) => <li key={`${index}-${file.name}`}>{file.name} <button type="button" className="btn-secondary" disabled={loading} onClick={() => setDdl(files => files.filter((_, i) => i !== index))} aria-label={`Remove ${file.name}`}>Remove</button></li>)}</ul>}
      {!current && <label className="block text-sm mt-3">Engine for SQL-only inspection <select className="bg-ink-900 ml-2" value={engine} disabled={loading} onChange={event => setEngine(event.target.value)}><option value="postgres">PostgreSQL</option><option value="mysql">MySQL</option><option value="mariadb">MariaDB</option></select></label>}
      {uploadError && <p className="text-sm mt-3" role="alert">{uploadError}</p>}
    </div>
    <div className="database-upload-footer">
      <p className="text-sm text-bone-400">{current ? 'Snapshot ready. Start your analysis when you’re ready.' : ddl.length ? 'SQL definitions ready for static inspection.' : 'Upload a snapshot or SQL definitions to get started.'}</p>
      <button type="button" className="btn-primary" disabled={loading || (!current && !ddl.length) || !!uploadError} onClick={() => onUpload(current, baseline, ddl, { engine, clientAlias })}>{loading ? 'Analysing…' : 'Analyse database'}</button>
    </div>
    <details className="mt-4 text-sm text-bone-400"><summary>Collect a database snapshot</summary>
      <p className="mt-3">Run a collector inside your database environment with a read-only account. Use its --help for connection and output options. This workbench does not connect to your database.</p>
      <div className="flex gap-4 my-3"><a className="underline" href="/api/database/collectors/pg_collect.py">PostgreSQL collector</a><a className="underline" href="/api/database/collectors/mysql_collect.py">MySQL / MariaDB collector</a><a className="underline" href="/api/database/collectors/delta.py">Delta helper</a></div>
      <p>Python collectors require psycopg[binary] or PyMySQL respectively. Place delta.py alongside the collector for --delta-of. Review SQL sanitization before sharing snapshot files. Add --include-procedures to capture stored procedure/function bodies and column datatypes. This opt-in source capture retains literals and comments; review it for secrets before sharing.</p>
      <p className="mt-3">Stored procedure analysis checks parameter/local-variable and temporary-column datatype mismatches in simple comparisons, unindexed temporary-table access, cursors/loops, SELECT *, dynamic SQL, and functions on predicate columns. Findings include review suggestions; execution plans are needed to confirm performance impact.</p>
    </details>
  </section>
}

export default function DatabaseAnalysis({ analysis, threadAnalysis }) {
  const [confirmed, setConfirmed] = useState(false)
  const [correlation, setCorrelation] = useState(null)
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  const [category, setCategory] = useState('all')
  const findings = analysis.findings.filter(f => category === 'all' || f.category === category)
  const catalog = analysis.schema_catalog
  async function exportArtifact(format, print = false) {
    const preview = print ? window.open('', '_blank') : null
    if (print && !preview) { setError('Allow the report window to print or save a PDF.'); return }
    setBusy(true); setError(null)
    try { await downloadDatabaseArtifact(analysis.analysis_id, format, preview) }
    catch (failure) { preview?.close(); setError(failure.message) }
    finally { setBusy(false) }
  }
  return <div className="max-w-7xl mx-auto pt-8 space-y-6">
    <section className="panel p-6">
      <h1 className="text-3xl text-bone-100">Database Analyser</h1>
      {analysis.client_alias && <p className="my-2">{analysis.client_alias}</p>}
      <p className="my-3">{analysis.summary}</p>
      <p>{analysis.score_label}: <strong>{analysis.score.score == null ? 'Unavailable — workload evidence needed' : `${analysis.score.score}/100`}</strong> · {analysis.status}</p>
      <p className="text-sm text-bone-400 mt-2">{analysis.status === 'static' ? 'Inspected' : 'Captured'} {analysis.collected_at} · {analysis.status === 'static' ? 'SQL definitions only' : analysis.is_delta ? 'Baseline rates included' : 'Single snapshot'}</p>
      <div className="flex gap-3 mt-4 flex-wrap">
        <button className="btn-secondary" disabled={busy} onClick={() => exportArtifact('html')}>Export HTML</button>
        <button className="btn-secondary" disabled={busy} onClick={() => exportArtifact('html', true)}>Print / save PDF</button>
        <button className="btn-secondary" disabled={busy} onClick={() => exportArtifact('tasks')}>Export tasks</button>
        {catalog && <button className="btn-secondary" disabled={busy} onClick={() => exportArtifact('schema')}>Export schema JSON</button>}
        <button className="btn-secondary" onClick={() => downloadDatabaseReport(analysis, 'json')}>Export complete JSON</button>
      </div>
      {error && <p role="alert" className="mt-3">{error}</p>}
    </section>
    <section className="panel p-6"><h2 className="text-xl mb-3">Evidence coverage</h2>
      <div className="overflow-auto"><table className="w-full text-left text-sm"><thead><tr><th>Section</th><th>Status</th><th>Records</th></tr></thead><tbody>{analysis.coverage.map(c => <tr key={c.section}><td>{c.section}</td><td>{c.status}</td><td>{c.count}</td></tr>)}</tbody></table></div>
      <ul className="list-disc pl-5 mt-4 text-sm text-bone-400">{analysis.limitations.map((l, i) => <li key={i}>{l}</li>)}</ul>
    </section>
    {(catalog || (analysis.snapshot?.routine_stats?.length || 0) > 0) && <SchemaAnalysis catalog={catalog} routineStats={analysis.snapshot?.routine_stats || []} />}
    {analysis.status !== 'static' && <section className="panel p-6"><h2 className="text-xl mb-3">JVM and database evidence</h2>
      {!threadAnalysis ? <p>Analyze or reopen a thread dump, set its capture time under Evidence and investigation, then reopen this database analysis.</p> : <>
        <label className="block text-sm mb-3"><input type="checkbox" checked={confirmed} onChange={e => { setConfirmed(e.target.checked); setCorrelation(null) }} /> I confirm this JVM connects to this database and both captures concern the same incident.</label>
        <button className="btn-secondary" disabled={!confirmed || busy} onClick={async () => {
          setBusy(true); setError(null)
          try {
            const response = await fetch('/api/correlate/database', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ database_id: analysis.analysis_id, thread_id: threadAnalysis.analysis_id, same_incident_confirmed: confirmed }) })
            if (!response.ok) throw new Error(await response.text())
            setCorrelation(await response.json())
          } catch (e) { setError(e.message) } finally { setBusy(false) }
        }}>{busy ? 'Checking…' : 'Inspect correlation leads'}</button>
      </>}
      {error && <p role="alert">{error}</p>}
      {correlation && <div className="mt-3"><p>Status: {correlation.status}</p>{correlation.limitations.map((l, i) => <p key={i} className="text-sm text-bone-400">{l}</p>)}{correlation.leads.map((lead, i) => <details key={i} className="mt-3"><summary>{lead.thread} · {lead.state}</summary><p>{lead.interpretation}</p><pre className="overflow-auto text-xs">{lead.frames.map(f => `${f.class_name}.${f.method} (${f.file || 'unknown'}:${f.line || '?'})`).join('\n')}</pre></details>)}</div>}
    </section>}
    <section className="panel p-6"><div className="database-findings-toolbar"><h2 className="text-xl">Findings ({findings.length})</h2><label className="database-category-filter">Category <select value={category} onChange={e => setCategory(e.target.value)}><option value="all">All categories</option>{[...new Set(analysis.findings.map(f => f.category))].map(c => <option key={c} value={c}>{c.charAt(0).toUpperCase() + c.slice(1)}</option>)}</select></label></div>
      {!findings.length && <p>No findings in this selection. Check evidence coverage before drawing conclusions.</p>}
      {findings.map(f => <article key={f.evidence_id} className="border-t border-ink-600 py-5">
        <h3 className="text-lg text-bone-100">{f.severity} · {f.title}</h3><p className="text-xs text-bone-400 my-2">{f.evidence_id} · {f.rule_id} · confidence: {f.confidence}</p>
        <pre className="whitespace-pre-wrap break-all text-sm">{f.affected_object}</pre>
        <details className="my-3"><summary>Evidence</summary><pre className="overflow-auto text-xs mt-2">{JSON.stringify(f.evidence, null, 2)}</pre></details><p className="text-sm">{f.suggested_action}</p>
      </article>)}
    </section>
    <details className="panel p-6"><summary>Complete snapshot and analysis</summary><pre className="overflow-auto text-xs mt-3">{JSON.stringify(analysis, null, 2)}</pre></details>
  </div>
}

function SchemaAnalysis({ catalog: capturedCatalog, routineStats }) {
  const catalog = capturedCatalog || { source_count: 0, tables: [], indexes: [], views: [], routines: [], warnings: [] }
  return <section className="panel p-6">
    <h2 className="text-xl mb-3">Schema and stored routines</h2>
    <p className="text-sm text-bone-400">{catalog.source_count} SQL files · {catalog.tables.length} tables · {catalog.indexes.length} indexes · {catalog.views.length} views · {catalog.routines.length} routines</p>
    <p className="text-sm text-bone-400 mt-2">Static structure and source locations identify review candidates. Plans and workload measurements are needed to confirm performance.</p>
    {catalog.warnings.map((warning, i) => <p key={i} className="text-sm mt-2">{warning}</p>)}
    {catalog.tables.map(table => <details key={table.name} className="border-t border-ink-600 py-3 mt-3"><summary>{table.name} · {table.columns.length} columns</summary>
      <div className="overflow-auto"><table className="w-full text-left text-sm mt-3"><thead><tr><th>Column</th><th>Type</th><th>Constraints</th></tr></thead><tbody>{table.columns.map(column => <tr key={column.name}><td>{column.name}</td><td>{column.data_type}</td><td>{[column.primary_key && 'Primary key', column.unique && 'Unique', !column.nullable && 'Not null'].filter(Boolean).join(' · ')}</td></tr>)}</tbody></table></div>
      <p className="text-sm mt-3">References: {table.referenced_tables.join(', ') || 'None recorded'}</p>
      {catalog.indexes.filter(index => index.table === table.name).map(index => <p key={index.name} className="text-sm mt-2">{index.name} · {index.columns.join(', ')} · {index.primary ? 'Primary' : index.unique ? 'Unique' : 'Index'}</p>)}
    </details>)}
    {catalog.views.length > 0 && <p className="text-sm mt-3">Views: {catalog.views.join(', ')}</p>}
    {catalog.routines.map((routine, i) => <details key={`${routine.source_file}-${routine.name}-${i}`} className="border-t border-ink-600 py-3"><summary>{routine.name} · {routine.kind} · SQL file {routine.source_file}, line {routine.line}</summary>
      <p className="text-sm mt-3">Dependencies: {routine.dependencies.join(', ') || 'None resolved'}</p>
      {[['Parameters', routine.parameters], ['Local variables', routine.variables]].map(([label, variables]) => <div key={label} className="mt-3"><h3>{label}</h3>{!variables.length && <p className="text-sm text-bone-400">None recorded</p>}{variables.map((variable, j) => <p key={j} className="text-sm">{variable.name}: {variable.data_type} · declared line {variable.declaration_line} · {variable.occurrences} lexical references · assignment lines {variable.assignment_lines.join(', ') || 'None recorded'}</p>)}</div>)}
      <div className="mt-3"><h3>Temporary tables</h3>{!routine.temporary_tables.length && <p className="text-sm text-bone-400">None recorded</p>}{routine.temporary_tables.map((table, j) => <div key={j} className="text-sm mt-2"><p>{table.name} · created line {table.creation_line} · indexes: {table.indexes.join(', ') || 'None recorded'}</p><p>Read lines: {table.read_lines.join(', ') || 'None'} · Write lines: {table.write_lines.join(', ') || 'None'} · Drop lines: {table.drop_lines.join(', ') || 'None'}</p></div>)}</div>
      <p className="text-sm mt-3">Loop lines: {routine.loop_lines.join(', ') || 'None'} · Branch lines: {routine.branch_lines.join(', ') || 'None'} · Dynamic SQL lines: {routine.dynamic_sql_lines.join(', ') || 'None'}</p>
      <div className="mt-3"><h3>Static statements</h3>{routine.statements.map((statement, j) => <details key={j} className="mt-2"><summary>Line {statement.line} · {statement.kind} · {statement.parsed ? 'Parsed' : 'Needs manual review'}</summary><pre className="whitespace-pre-wrap break-all text-xs mt-2">{statement.normalized_sql}</pre></details>)}</div>
      {routine.limitations.map((note, j) => <p key={j} className="text-sm text-bone-400 mt-2">{note}</p>)}
    </details>)}
    {routineStats.length > 0 && <div className="mt-4"><h3>Captured routine execution statistics</h3>{routineStats.map((routine, i) => <p key={i} className="text-sm mt-2">{routine.name} · {routine.calls} calls · {routine.total_time_ms} ms total · {routine.nested_statements} nested statements · {routine.nested_time_ms} ms nested time</p>)}</div>}
  </section>
}
