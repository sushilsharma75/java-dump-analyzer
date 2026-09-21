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
  return `<!doctype html><html><head><meta charset="utf-8"><title>Stack Analyser — Database report</title></head><body><h1>Stack Analyser</h1><h2>${escape(analysis.summary)}</h2><p>${escape(analysis.score_label)}: ${escape(analysis.score.score)}/100</p><h2>Coverage</h2><pre>${escape(JSON.stringify(analysis.coverage, null, 2))}</pre><h2>Limitations</h2><ul>${analysis.limitations.map(x => `<li>${escape(x)}</li>`).join('')}</ul>${analysis.findings.map(f => `<article><h2>${escape(f.severity)} · ${escape(f.title)}</h2><p>${escape(f.evidence_id)} · ${escape(f.affected_object)} · confidence: ${escape(f.confidence)}</p><pre>${escape(JSON.stringify(f.evidence, null, 2))}</pre><p>${escape(f.suggested_action)}</p></article>`).join('')}</body></html>`
}

export function DatabaseUpload({ onUpload, loading }) {
  const [current, setCurrent] = useState(null)
  const [baseline, setBaseline] = useState(null)
  return <section className="panel p-6 mb-8">
    <h2 className="text-2xl text-bone-100 mb-2">Database Snapshot</h2>
    <p className="text-sm text-bone-400 mb-4">PostgreSQL, MySQL and MariaDB diagnostics powered by DBDoctor. Upload collector JSON (up to 10 MiB). Add an older snapshot from the same database to estimate rates.</p>
    <div className="database-upload-grid">
      <FileUpload label="Current snapshot" accept=".json,application/json" formats="JSON · up to 10 MiB" loading={loading} file={current} onFile={setCurrent} onClear={() => setCurrent(null)} />
      <FileUpload label="Baseline snapshot (optional)" accept=".json,application/json" formats="JSON · an older capture from the same database" loading={loading} file={baseline} onFile={setBaseline} onClear={() => setBaseline(null)} />
    </div>
    <div className="database-upload-footer">
      <p className="text-sm text-bone-400">{current ? 'Snapshot ready. Start your analysis when you’re ready.' : 'Upload a current snapshot to get started.'}</p>
      <button type="button" className="btn-primary" disabled={loading || !current} onClick={() => onUpload(current, baseline)}>{loading ? 'Analysing…' : 'Analyse database'}</button>
    </div>
    <details className="mt-4 text-sm text-bone-400"><summary>Collect a database snapshot</summary>
      <p className="mt-3">Run a collector inside your database environment with a read-only account. Use its --help for connection and output options. This workbench does not connect to your database.</p>
      <div className="flex gap-4 my-3"><a className="underline" href="/api/database/collectors/pg_collect.py">PostgreSQL collector</a><a className="underline" href="/api/database/collectors/mysql_collect.py">MySQL / MariaDB collector</a><a className="underline" href="/api/database/collectors/delta.py">Delta helper</a></div>
      <p>Python collectors require psycopg[binary] or PyMySQL respectively. Place delta.py alongside the collector for --delta-of. Review SQL sanitization before sharing snapshot files.</p>
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
  return <div className="max-w-7xl mx-auto pt-8 space-y-6">
    <section className="panel p-6">
      <h1 className="text-3xl text-bone-100">Database Analyser</h1>
      <p className="my-3">{analysis.summary}</p>
      <p>{analysis.score_label}: <strong>{analysis.score.score}/100</strong> · {analysis.status}</p>
      <p className="text-sm text-bone-400 mt-2">Captured {analysis.collected_at} · {analysis.is_delta ? 'Baseline rates included' : 'Single snapshot'}</p>
      <div className="flex gap-3 mt-4"><button className="btn-secondary" onClick={() => downloadDatabaseReport(analysis, 'html')}>Export HTML</button><button className="btn-secondary" onClick={() => downloadDatabaseReport(analysis, 'json')}>Export complete JSON</button></div>
    </section>
    <section className="panel p-6"><h2 className="text-xl mb-3">Evidence coverage</h2>
      <div className="overflow-auto"><table className="w-full text-left text-sm"><thead><tr><th>Section</th><th>Status</th><th>Records</th></tr></thead><tbody>{analysis.coverage.map(c => <tr key={c.section}><td>{c.section}</td><td>{c.status}</td><td>{c.count}</td></tr>)}</tbody></table></div>
      <ul className="list-disc pl-5 mt-4 text-sm text-bone-400">{analysis.limitations.map((l, i) => <li key={i}>{l}</li>)}</ul>
    </section>
    <section className="panel p-6"><h2 className="text-xl mb-3">JVM and database evidence</h2>
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
    </section>
    <section className="panel p-6"><div className="flex gap-4 items-center mb-4"><h2 className="text-xl">Findings ({findings.length})</h2><label>Category <select className="bg-ink-900" value={category} onChange={e => setCategory(e.target.value)}><option value="all">All</option>{[...new Set(analysis.findings.map(f => f.category))].map(c => <option key={c}>{c}</option>)}</select></label></div>
      {!findings.length && <p>No findings in this selection. Check evidence coverage before drawing conclusions.</p>}
      {findings.map(f => <article key={f.evidence_id} className="border-t border-ink-600 py-5">
        <h3 className="text-lg text-bone-100">{f.severity} · {f.title}</h3><p className="text-xs text-bone-400 my-2">{f.evidence_id} · {f.rule_id} · confidence: {f.confidence}</p>
        <pre className="whitespace-pre-wrap break-all text-sm">{f.affected_object}</pre>
        <details className="my-3"><summary>Measured evidence</summary><pre className="overflow-auto text-xs mt-2">{JSON.stringify(f.evidence, null, 2)}</pre></details><p className="text-sm">{f.suggested_action}</p>
      </article>)}
    </section>
    <details className="panel p-6"><summary>Complete snapshot and analysis</summary><pre className="overflow-auto text-xs mt-3">{JSON.stringify(analysis, null, 2)}</pre></details>
  </div>
}
