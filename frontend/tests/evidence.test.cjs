const test = require('node:test')
const assert = require('node:assert/strict')
const path = require('node:path')
const babel = require('@babel/core')
const React = require('react')
const { renderToString } = require('react-dom/server')
const root = path.resolve(__dirname, '../src')
const loadJS = require.extensions['.js']
function load(module, filename) {
  if (!filename.startsWith(root)) return loadJS(module, filename)
  const { code } = babel.transformFileSync(filename, {
    babelrc: false, configFile: false,
    plugins: [() => ({ visitor: { MetaProperty(p) { if (p.node.meta.name === 'import') p.replaceWithSourceString('({env:{}})') } } })],
    presets: [['@babel/preset-env', { targets: { node: 'current' } }], ['@babel/preset-react', { runtime: 'automatic' }]],
  })
  module._compile(code, filename)
}
require.extensions['.jsx'] = load
require.extensions['.js'] = load
const { buildReportHTML } = require('../src/report.js')
const Investigation = require('../src/components/Investigation.jsx').default
const VerdictBanner = require('../src/components/VerdictBanner.jsx').default
const Findings = require('../src/components/Findings.jsx').default

const analysis = {
  analysis_id: 'a'.repeat(32), object_index_id: 'a'.repeat(32), verdict: 'insufficient_evidence',
  header: 'JAVA PROFILE 1.0.2', file_size_bytes: 1000,
  findings: [{ severity: 'warning', title: 'Candidate', description: 'Observation', evidence_id: 'E-test', confidence: 'low', conclusion: 'hypothesis', limitations: ['Layout assumed'], verification: ['Check root ownership'], source_locations: [] }],
  stages: [{ stage: 'object index', status: 'failed', reason: '<bad input>' }],
  source_provenance: { build_verified: false }, sizing_assumptions: ['Object headers assumed'],
  dominators: [{ object_id: '0x1', class_name: 'Cache', retained_bytes: 100 }],
  top_classes_by_size: [], top_classes_by_count: [],
}

test('HTML export preserves evidence and coverage without injecting markup', () => {
  const html = buildReportHTML({ kind: 'heap', filename: 'dump.hprof', analysis })
  for (const text of ['E-test', 'Layout assumed', 'Check root ownership', 'Object headers assumed', 'failed', '&lt;bad input&gt;']) assert.ok(html.includes(text), text)
  assert.ok(!html.includes('<bad input>'))
})

test('Investigation exposes the saved index and capture controls', () => {
  const html = renderToString(React.createElement(Investigation, { analysis }))
  for (const text of ['Explore heap objects', 'Source method context', 'Search objects', 'Save capture identity', '0x1']) assert.ok(html.includes(text), text)
})

test('Unknown verdict cannot render a healthy banner', () => {
  const html = renderToString(React.createElement(VerdictBanner, { verdict: 'unexpected' }))
  assert.ok(html.includes('Insufficient evidence'))
  assert.ok(!html.includes('Looks healthy'))
})

test('Finding cards expose confidence and verification', () => {
  const html = renderToString(React.createElement(Findings, { findings: analysis.findings }))
  for (const text of ['E-test', 'Layout assumed', 'Check root ownership']) assert.ok(html.includes(text), text)
})

const DatabaseAnalysis = require('../src/components/DatabaseAnalysis.jsx').default
const { databaseReportHTML } = require('../src/components/DatabaseAnalysis.jsx')
const database = {
  analysis_id: 'b'.repeat(32), summary: 'postgres · test-db', status: 'partial', collected_at: '2026-07-01T00:00:00Z',
  score: { score: 100 }, score_label: 'Observed findings score (not a health certification)',
  coverage: [{ section: 'queries', status: 'missing', count: 0 }],
  limitations: ['Missing statistics cannot rule out problems.'],
  findings: [{ evidence_id: 'db-0001', rule_id: 'R-Q1', title: '<script>bad</script>', severity: 'HIGH', confidence: 'medium', category: 'queries', affected_object: 'SELECT <secret>', evidence: { mean_ms: 1200 }, suggested_action: 'Verify the plan.' }],
}
test('Database UI exposes missing coverage and diagnostic uncertainty', () => {
  const html = renderToString(React.createElement(DatabaseAnalysis, { analysis: database }))
  for (const text of ['missing', 'not a health certification', 'db-0001', 'medium', 'Export complete JSON']) assert.ok(html.includes(text), text)
  assert.ok(!html.includes('<script>bad</script>'))
})
test('Database export escapes SQL and preserves measured evidence', () => {
  const html = databaseReportHTML(database)
  for (const text of ['&lt;script&gt;', '1200', 'db-0001', 'Missing statistics']) assert.ok(html.includes(text), text)
  assert.ok(!html.includes('<script>bad</script>'))
})

test('Stored procedure source evidence and suggestions appear in UI and export', () => {
  const analysis = { ...database, findings: [{ evidence_id: 'db-0001', rule_id: 'R-SP1',
    title: 'Compared operands have different declared datatypes', severity: 'MEDIUM',
    category: 'procedures', confidence: 'medium', affected_object: 'shop.review_orders',
    evidence: { line: 7, left_type: 'bigint', right_type: 'varchar(20)' },
    suggested_action: 'Align parameter types and validate the execution plan.' }] }
  for (const html of [renderToString(React.createElement(DatabaseAnalysis, { analysis })), databaseReportHTML(analysis)]) {
    for (const text of ['shop.review_orders', 'bigint', 'varchar(20)', 'Align parameter types']) assert.ok(html.includes(text), text)
  }
})


test('heap progress distinguishes parsing from remaining analysis', () => {
  const HeapProgress = require('../src/components/HeapProgress.jsx').default
  const html = renderToString(React.createElement(HeapProgress, {
    phase: 'parsing', filename: 'dump.hprof',
    jobStatus: { status: 'running', bytes_total: 100, bytes_processed: 100,
      stage: 'Computing retained sizes', eta_seconds: 0 },
  }))
  assert.ok(html.includes('Computing retained sizes'))
  assert.ok(html.includes('Analysis still running'))
  assert.ok(html.includes('parse eta'))
  assert.ok(!html.includes('0.0s'))
})

const RetentionTrace = require('../src/components/RetentionTrace.jsx').default
test('retention trace displays chain, field methods, recorded roots and missing evidence', () => {
  const data = { source_attached: true, partial: true, note: 'Representative paths', paths: [{
    root: [{ oid: '0x1', kind_name: 'Java local', thread: 7, stack_status: 'available', frames: [
      { index: 0, class_name: 'Cache', method_name: 'store', file_name: 'Cache.java', line: 5, holds_root: true },
    ] }], edges: [{ src: '0x1', dst: '0x2', field: 'Cache.retained', strength: 'strong',
      owner: { name: 'Cache' }, target: { name: 'Order' }, source: { repo_path: 'Cache.java', line: 3,
        role: 'retaining_field', snippet: { start_line: 3, lines: ['Object retained;'] },
        context: { related_field_methods: [{ method: 'store', start_line: 4, lines: ['retained = value;'], role: 'candidate field usage' }] } } }],
  }] }
  const html = renderToString(React.createElement(RetentionTrace, { data }))
  for (const text of ['Cache.retained', 'Order', 'holds this local root', 'retained = value;', 'Search was limited.', 'do not prove']) assert.ok(html.includes(text), text)
})

const { LogEvent, IncidentReport, incidentReportHTML } = require('../src/components/ServerLogWorkspace.jsx')
const ServerLogWorkspace = require('../src/components/ServerLogWorkspace.jsx').default
const logEvent = { id: 1, evidence_id: 'E-log1', level: 'ERROR', start_line: 4, end_line: 8,
  thread: 'worker-1', request_id: 'request-1', excerpt: '<script>alert(1)</script>', truncated: 1,
  frames: [{ class_name: 'example.Cache', method: 'put', file: 'Cache.java', line: 4,
    source: { repo_path: 'Cache.java', line: 4, role: 'logged_frame', snippet: { start_line: 4, lines: ['cache.put(value);'] } } }] }

test('server log attachment uses the normal dump analysis workflow', () => {
  const html = renderToString(React.createElement(ServerLogWorkspace, { onLog() {} }))
  assert.ok(!html.includes('Analyze all attached evidence'))
  for (const text of ['5 GiB', 'Upload server.log', 'included automatically', 'Timezone']) assert.ok(html.includes(text), text)
})
test('log events and incident exports preserve evidence and escape log text', () => {
  const result = { summary: 'One event', status: 'completed', matches: [{ event: logEvent, links: [{ kind: 'same_class_and_method' }], aligned_with: ['thread'], confidence: 'medium' }], limitations: ['Context is not causation.'] }
  for (const html of [renderToString(React.createElement(LogEvent, { event: logEvent })), incidentReportHTML(result)]) {
    for (const text of ['E-log1', '&lt;script&gt;', 'Cache.java', 'cache.put(value);']) assert.ok(html.includes(text), text)
    assert.ok(!html.includes('<script>'))
  }
  const html = renderToString(React.createElement(IncidentReport, { result }))
  for (const text of ['Combined JVM investigation', 'Export combined HTML', 'same_class_and_method', 'thread']) assert.ok(html.includes(text), text)
})
test('log client uploads the raw file and supports cancellation', async () => {
  const { uploadServerLog } = require('../src/api.js')
  const previous = global.XMLHttpRequest
  let xhr
  global.XMLHttpRequest = class {
    constructor() { xhr = this; this.upload = {} }
    open(method, url) { this.method = method; this.url = url }
    setRequestHeader(key, value) { this.header = [key, value] }
    send(body) { this.body = body }
    abort() { this.onabort() }
  }
  try {
    const file = { name: 'server log.log', size: 5 * 1024 ** 3 }
    const controller = new AbortController()
    const promise = uploadServerLog(file, '+05:30', null, controller.signal)
    assert.equal(xhr.body, file)
    assert.equal(xhr.header[1], 'application/octet-stream')
    assert.ok(xhr.url.includes('timezone_offset=%2B05%3A30'))
    controller.abort()
    await assert.rejects(promise, /cancelled/)
  } finally { global.XMLHttpRequest = previous }
})

const Hero = require('../src/components/Hero.jsx').default
const SourceUpload = require('../src/components/SourceUpload.jsx').default
const { startIncident } = require('../src/components/AutomaticIncident.jsx')

test('log attachment sits between source attachment and dump upload cards', () => {
  const html = renderToString(React.createElement(Hero, {
    serverLogAttachment: React.createElement(ServerLogWorkspace, { onLog() {} }),
  }))
  assert.ok(html.indexOf('Attach source code') < html.indexOf('Attach server log'))
  assert.ok(html.indexOf('Attach server log') < html.indexOf('Thread Dump'))
  assert.ok(!html.includes('Analyze all attached evidence'))
})

test('attachment controls respect shared workflow busy state', () => {
  const source = renderToString(React.createElement(SourceUpload, { disabled: true }))
  const log = renderToString(React.createElement(ServerLogWorkspace, { disabled: true, onLog() {} }))
  assert.match(source, /<fieldset disabled=""/)
  assert.match(log, /<button[^>]*disabled=""[^>]*>Upload server.log/)
})

test('automatic correlation includes attachments and ignores superseded responses', async () => {
  const previous = global.fetch
  const pending = [], bodies = [], results = [], busy = [], errors = []
  global.fetch = (url, options) => new Promise(resolve => {
    assert.equal(url, '/api/analyze/incident')
    bodies.push(JSON.parse(options.body)); pending.push(resolve)
  })
  const callbacks = { onResult: v => results.push(v), onError: e => errors.push(e), onBusy: b => busy.push(b) }
  const flush = () => new Promise(resolve => setImmediate(resolve))
  try {
    const cancel = startIncident({ log: { analysis_id: 'log' }, thread: { analysis_id: 'old-thread' }, sourceSession: { session_id: 'src' } }, callbacks)
    cancel()
    startIncident({ log: { analysis_id: 'log' }, heap: { analysis_id: 'new-heap' }, sourceSession: { session_id: 'src' } }, callbacks)
    assert.deepEqual(bodies[1], { server_log_id: 'log', heap_id: 'new-heap', thread_id: null, gc_id: null, source_session: 'src', window_seconds: 300 })
    pending[1]({ ok: true, json: async () => ({ summary: 'current' }) }); await flush()
    pending[0]({ ok: true, json: async () => ({ summary: 'stale' }) }); await flush()
    assert.deepEqual(results, [{ summary: 'current' }])
    assert.deepEqual(errors, [])
    assert.equal(busy.at(-1), false)
    startIncident({ log: { analysis_id: 'log' }, thread: { analysis_id: 'new-thread' } }, callbacks)
    pending[2]({ ok: false, json: async () => ({ detail: 'Source expired' }) }); await flush()
    assert.deepEqual(errors, ['Source expired'])
    assert.equal(busy.at(-1), false)
  } finally { global.fetch = previous }
})

test('timezone is pre-filled from the browser and alignment warnings are visible', () => {
  const { browserOffset, IncidentReport } = require('../src/components/ServerLogWorkspace.jsx')
  assert.equal(browserOffset({ getTimezoneOffset: () => -330 }), '+05:30')
  assert.equal(browserOffset({ getTimezoneOffset: () => 240 }), '-04:00')
  assert.equal(browserOffset({ getTimezoneOffset: () => 0 }), '+00:00')
  const note = 'Only 0 of 3 log events have timezone-aligned timestamps; the capture-time window was not applied.'
  const html = renderToString(React.createElement(IncidentReport, { result: { summary: 's', status: 'completed', matches: [], limitations: [note, 'Context is not causation.'] } }))
  assert.ok(html.includes('role="note"') && html.includes('timezone-aligned'))
})

test('incident report leads with log findings, timeline and readable match explanations', () => {
  const { IncidentReport } = require('../src/components/ServerLogWorkspace.jsx')
  const bucket = (start, extra = {}) => ({ start, total: 3, errors: 2, warnings: 1, oom: 0, deploy: 0, undeploy: 0, server_start: 0, heap_dump: 0, ...extra })
  const result = {
    summary: '1 OutOfMemoryError (Java heap space) in the log', status: 'completed', limitations: [],
    log_findings: [{ evidence_id: 'E-oom', severity: 'critical', category: 'server_log_memory', title: 'OutOfMemoryError: Java heap space logged 1×', description: 'The Java heap was full.', evidence: [], source_locations: [] }],
    correlation: { findings: [] },
    timeline: { basis: 'UTC', bucket_minutes: 10, buckets: [bucket('2026-09-23T09:50+00:00', { oom: 1 }), bucket('2026-09-23T10:00+00:00')],
                captures: [{ kind: 'heap', at: '2026-09-23T10:00:00.000+00:00', bucket: '2026-09-23T10:00+00:00' }] },
    matches: [{ event: { ...logEvent, evidence_id: 'E-1' }, links: [{ kind: 'memory_event' }], explanation: ['This event is an OutOfMemoryError: Java heap space.'], aligned_with: ['heap'], confidence: 'medium', score: 7 }],
  }
  const html = renderToString(React.createElement(IncidentReport, { result }))
  for (const text of ['What the server log adds', 'OutOfMemoryError: Java heap space logged', 'Errors per 10 minutes', 'OOM', 'CAPTURE', 'heap dump captured', 'This event is an OutOfMemoryError', 'Raw evidence links'])
    assert.ok(html.includes(text), text)
  assert.ok(html.indexOf('What the server log adds') < html.indexOf('Related log events'))
})
