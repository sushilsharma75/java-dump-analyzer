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
