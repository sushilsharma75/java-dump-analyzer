import { useState, useEffect } from 'react'
import { getLLMSummary } from '../api'
import { useReport } from '../reportContext'
import { parseMarkdown, parseInline } from '../markdown'

const STORAGE_KEY = 'postmortem.anthropic_key'
const MODEL_KEY = 'postmortem.anthropic_model'

// Left blank the backend picks its default. Offered here because the usual cause
// of a rejected request is an organisation that can't use the default model yet.
const MODELS = [
  { id: '', label: 'backend default' },
  { id: 'claude-opus-5', label: 'Opus 5' },
  { id: 'claude-opus-4-8', label: 'Opus 4.8' },
  { id: 'claude-sonnet-5', label: 'Sonnet 5' },
  { id: 'claude-haiku-4-5', label: 'Haiku 4.5' },
]

export default function LLMPanel({ analysis, kind }) {
  // Publish the diagnosis so the exported report can include it — this panel is
  // not the only consumer of what Claude wrote.
  const { setLLM } = useReport()
  const [apiKey, setApiKey] = useState('')
  const [model, setModel] = useState('')
  const [remember, setRemember] = useState(false)
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)
  const [expanded, setExpanded] = useState(false)

  // Load remembered key from localStorage on mount
  useEffect(() => {
    try {
      const stored = localStorage.getItem(STORAGE_KEY)
      if (stored) {
        setApiKey(stored)
        setRemember(true)
      }
      const storedModel = localStorage.getItem(MODEL_KEY)
      if (storedModel) setModel(storedModel)
    } catch {
      // localStorage might be unavailable
    }
  }, [])

  const handleSubmit = async () => {
    if (!apiKey.trim()) {
      setError('API key is required.')
      return
    }
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      if (remember) {
        try { localStorage.setItem(STORAGE_KEY, apiKey) } catch {}
      } else {
        try { localStorage.removeItem(STORAGE_KEY) } catch {}
      }
      // The model choice is a preference, not a secret — keep it either way.
      try {
        if (model) localStorage.setItem(MODEL_KEY, model)
        else localStorage.removeItem(MODEL_KEY)
      } catch {}
      const res = await getLLMSummary(analysis, kind, apiKey, model)
      if (res.error) {
        setError(res.error)
      } else {
        setResult(res.summary)
        setLLM(kind, res.summary)
      }
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <section className="animate-slide-up">
      <div className="flex items-center justify-between mb-4">
        <div className="label text-bone-300">// ai diagnosis</div>
        <span className="badge-neutral">optional</span>
      </div>

      <div className="panel p-5 md:p-6">
        {!result && !expanded && (
          <button
            onClick={() => setExpanded(true)}
            className="w-full text-left group"
          >
            <div className="flex items-start gap-4">
              <div className="w-10 h-10 rounded-md border border-flag-info/30 bg-flag-info/5 flex items-center justify-center shrink-0 group-hover:bg-flag-info/10 transition-colors">
                <span className="font-mono text-flag-info text-lg">∴</span>
              </div>
              <div className="flex-1 min-w-0">
                <h3 className="font-display text-lg text-bone-100 mb-1">
                  Generate AI-powered diagnosis
                </h3>
                <p className="text-sm text-bone-400 leading-relaxed">
                  Send the structured findings to Claude for a tailored, prescriptive write-up.
                  Bring your own Anthropic API key — it's used for this single request and never stored on the server.
                </p>
              </div>
              <span className="text-bone-500 font-mono text-sm group-hover:text-bone-300 transition-colors">→</span>
            </div>
          </button>
        )}

        {!result && expanded && (
          <div className="space-y-4 animate-fade-in">
            <div className="flex items-start gap-3 mb-2">
              <span className="badge-info">setup</span>
              <p className="text-xs text-bone-400 leading-relaxed flex-1">
                Your API key is sent directly to your local backend, which forwards it to api.anthropic.com
                for one request and discards it. Server never logs or stores keys. If you check "remember,"
                the key is saved in your browser's localStorage only.
              </p>
            </div>

            <div>
              <label className="label block mb-1.5">anthropic api key</label>
              <input
                type="password"
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                placeholder="sk-ant-..."
                className="w-full bg-ink-950 border border-ink-600/60 rounded px-3 py-2 font-mono text-sm text-bone-100 placeholder-bone-500 focus:outline-none focus:border-flag-info/50"
                autoComplete="off"
                spellCheck={false}
              />
            </div>

            <div>
              <label className="label block mb-1.5">model</label>
              <select
                value={model}
                onChange={(e) => setModel(e.target.value)}
                className="w-full bg-ink-950 border border-ink-600/60 rounded px-3 py-2 font-mono text-sm text-bone-100 focus:outline-none focus:border-flag-info/50"
              >
                {MODELS.map((m) => (
                  <option key={m.id} value={m.id}>{m.label}{m.id ? ` · ${m.id}` : ''}</option>
                ))}
              </select>
              <p className="text-[11px] text-bone-500 mt-1.5 leading-snug">
                Leave on the default unless the request is rejected because your organisation
                can't use that model yet.
              </p>
            </div>

            <div className="flex items-center justify-between gap-4 flex-wrap">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={remember}
                  onChange={(e) => setRemember(e.target.checked)}
                  className="w-3.5 h-3.5 rounded accent-flag-info"
                />
                <span className="font-mono text-xs text-bone-400">
                  remember in browser
                </span>
              </label>

              <div className="flex gap-2">
                <button
                  onClick={() => { setExpanded(false); setError(null) }}
                  className="btn-secondary"
                  disabled={loading}
                >
                  cancel
                </button>
                <button
                  onClick={handleSubmit}
                  className="btn bg-flag-info/10 text-flag-info border-flag-info/30 hover:bg-flag-info/20 hover:border-flag-info/50 disabled:opacity-50"
                  disabled={loading || !apiKey.trim()}
                >
                  {loading ? 'analyzing…' : 'generate diagnosis'}
                </button>
              </div>
            </div>

            {error && (
              <div className="border border-flag-critical/40 bg-flag-critical/5 rounded p-3">
                <p className="label text-flag-critical mb-1">request rejected</p>
                <p className="font-mono text-xs text-flag-critical whitespace-pre-wrap leading-relaxed">
                  {error}
                </p>
              </div>
            )}
          </div>
        )}

        {result && (
          <div className="animate-fade-in">
            <div className="flex items-center gap-2 mb-4">
              <span className="badge-info">claude diagnosis</span>
              <span className="label text-bone-500">// generated for this dump · included in exported report</span>
              <button
                onClick={() => { setResult(null); setExpanded(false); setLLM(kind, null) }}
                className="ml-auto font-mono text-xs text-bone-500 hover:text-bone-300"
              >
                clear
              </button>
            </div>
            <Markdown text={result} />
          </div>
        )}
      </div>
    </section>
  )
}

/** Very lightweight markdown renderer — handles headings, lists, **bold**, `code`, paragraphs. */
function Markdown({ text }) {
  const blocks = parseMarkdown(text)
  return (
    <div className="prose-custom space-y-3">
      {blocks.map((b, i) => {
        if (b.type === 'heading') {
          const Tag = `h${b.level}`
          return (
            <Tag
              key={i}
              className={
                b.level === 1
                  ? 'font-display text-xl text-bone-100 mt-4'
                  : b.level === 2
                  ? 'font-display text-lg text-bone-100 mt-3'
                  : 'font-display text-base text-bone-200 mt-2'
              }
            >
              <Inline text={b.text} />
            </Tag>
          )
        }
        if (b.type === 'code') {
          return (
            <pre key={i} className="panel-inset p-3 overflow-x-auto font-mono text-[11px] leading-relaxed text-bone-200 whitespace-pre">
              {b.text}
            </pre>
          )
        }
        if (b.type === 'ul') {
          return (
            <ul key={i} className="space-y-1.5 ml-1">
              {b.items.map((item, j) => (
                <li key={j} className="text-sm text-bone-200 leading-relaxed flex gap-2">
                  <span className="text-flag-info shrink-0 font-mono">→</span>
                  <span><Inline text={item} /></span>
                </li>
              ))}
            </ul>
          )
        }
        if (b.type === 'ol') {
          return (
            <ol key={i} className="space-y-1.5 ml-1 list-decimal list-inside">
              {b.items.map((item, j) => (
                <li key={j} className="text-sm text-bone-200 leading-relaxed">
                  <Inline text={item} />
                </li>
              ))}
            </ol>
          )
        }
        return (
          <p key={i} className="text-sm text-bone-200 leading-relaxed">
            <Inline text={b.text} />
          </p>
        )
      })}
    </div>
  )
}

function Inline({ text }) {
  const parts = parseInline(text)
  return (
    <>
      {parts.map((p, i) => {
        if (p.kind === 'bold') return <strong key={i} className="text-bone-100 font-medium">{p.text}</strong>
        if (p.kind === 'code') return (
          <code key={i} className="font-mono text-xs px-1 py-0.5 bg-ink-800 rounded text-flag-info">
            {p.text}
          </code>
        )
        return <span key={i}>{p.text}</span>
      })}
    </>
  )
}
