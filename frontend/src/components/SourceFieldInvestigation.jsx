import SourceSnippet from './SourceSnippet'

export default function SourceFieldInvestigation({ data, buildVerified = false }) {
  if (!data) return null
  const render = category => {
    const ops = (data.operations || []).filter(o => o.category === category)
    return ops.length ? ops.map((op, i) => <SourceSnippet key={i} location={{ ...op, is_user_code: true, build_verified: buildVerified, role: `${op.category.replaceAll('_', ' ')} · ${op.operation}` }} />)
      : <p>No operations resolved in the inspected scope.</p>
  }
  return <section className="heap-source">
    <h4>Code lifecycle investigation · {data.status}</h4>
    <details open><summary>Candidate writes</summary>{render('candidate_write')}</details>
    <details open><summary>Cleanup paths to review</summary>{render('candidate_cleanup')}</details>
    <details><summary>Other field uses</summary>{render('other_usage')}</details>
    {data.omitted > 0 && <p>{data.omitted} additional operations omitted.</p>}
    {(data.limitations || []).map((s, i) => <p className="heap-muted" key={i}>{s}</p>)}
    <p><strong>How to verify:</strong> check the intended lifecycle and whether these cleanup paths execute. Compare a compatible capture after eviction or cleanup.</p>
  </section>
}
