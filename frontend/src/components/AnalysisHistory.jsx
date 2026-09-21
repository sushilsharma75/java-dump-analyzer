import { useState, useEffect } from 'react'

export default function AnalysisHistory({ onOpen, section }) {
  const [items, setItems] = useState([])
  const [error, setError] = useState(null)
  useEffect(() => {
    let active = true
    fetch('/api/analyses').then(r => { if (!r.ok) throw new Error('Could not load saved analyses'); return r.json() })
      .then(data => { if (active) setItems(data) }).catch(e => { if (active) setError(e.message) })
    return () => { active = false }
  }, [])
  const visibleItems = items.filter(item => !section || (section === 'database' ? item.kind === 'database' : item.kind !== 'database'))
  if (!visibleItems.length && !error) return null
  return <details className="panel p-5 max-w-3xl mx-auto mt-5">
    <summary>Saved analyses ({visibleItems.length})</summary>
    {error && <p role="alert">{error}</p>}
    {visibleItems.map(item => <div className="flex gap-3 items-start py-2" key={item.analysis_id}>
      <button className="text-sm text-left flex-1" onClick={async () => {
        try {
          const r = await fetch(`/api/analyses/${item.analysis_id}`)
          if (!r.ok) throw new Error('Analysis unavailable')
          onOpen(await r.json())
        } catch (e) { setError(e.message) }
      }}>{item.kind} · {item.summary || item.analysis_id}</button>
      <button className="btn-secondary" onClick={async () => {
        try {
          const r = await fetch(`/api/analyses/${item.analysis_id}`, { method: 'DELETE' })
          if (!r.ok) throw new Error('Could not delete analysis')
          setItems(items.filter(i => i.analysis_id !== item.analysis_id))
        } catch (e) { setError(e.message) }
      }}>Delete saved analysis</button>
    </div>)}
  </details>
}
