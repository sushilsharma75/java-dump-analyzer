import { useState, useRef } from 'react'
import SourceUpload from './SourceUpload'
import CaptureGuide from './CaptureGuide'

// Per-card accent styling, keyed by `tone`.
const TONES = {
  warning: {
    hover: 'hover:border-flag-warning/60 focus-within:border-flag-warning/60',
    drag: 'border-flag-warning bg-flag-warning/5',
    btn: 'btn-primary',
  },
  info: {
    hover: 'hover:border-flag-info/60 focus-within:border-flag-info/60',
    drag: 'border-flag-info bg-flag-info/5',
    btn: 'btn bg-flag-info/10 text-flag-info border-flag-info/30 hover:bg-flag-info/20 hover:border-flag-info/50',
  },
  ok: {
    hover: 'hover:border-flag-ok/60 focus-within:border-flag-ok/60',
    drag: 'border-flag-ok bg-flag-ok/5',
    btn: 'btn bg-flag-ok/10 text-flag-ok border-flag-ok/30 hover:bg-flag-ok/20 hover:border-flag-ok/50',
  },
}

export default function Hero({
  onThreadUpload, onHeapUpload, onHeapPath, onGCUpload,
  sourceSession, onSourceSession,
  loading, error,
}) {
  return (
    <div className="max-w-6xl mx-auto pt-12 md:pt-20">
      {/* Title block */}
      <div className="mb-12 md:mb-16 animate-fade-in">
        <div className="flex items-center gap-3 mb-6">
          <span className="label">// case file</span>
          <div className="h-px flex-1 bg-ink-600/50 max-w-[200px]" />
          <span className="font-mono text-[10px] text-bone-500">v0.2.0</span>
        </div>
        <h1 className="font-display text-5xl md:text-7xl font-light tracking-tightest text-bone-100 leading-[1.02] mb-6">
          The JVM is misbehaving.<br />
          <span className="text-bone-400">
            Find out <em className="not-italic text-flag-warning font-normal">why</em>.
          </span>
        </h1>
        <p className="text-bone-400 max-w-2xl text-base md:text-lg leading-relaxed">
          Drop a thread dump, heap dump, or GC log. Get a structured diagnosis — deadlocks,
          lock contention, pool exhaustion, memory leaks, GC pressure — with concrete
          remediation steps. Attach your source repo and findings point straight to the line.
        </p>
      </div>

      {/* Source attachment (optional, shown above the dump upload) */}
      <div className="mb-8 animate-slide-up">
        <SourceUpload session={sourceSession} onSession={onSourceSession} />
      </div>

      {/* Upload grid */}
      <div className="grid md:grid-cols-3 gap-6 mb-12 animate-slide-up">
        <UploadCard
          tag="01"
          title="Thread Dump"
          subtitle="jstack · kill -3 · jcmd Thread.print"
          formats=".txt · .log · .tdump"
          accept=".txt,.log,.tdump,text/plain"
          onFile={onThreadUpload}
          loading={loading}
          tone="warning"
          description="Parses HotSpot output. Detects deadlocks, lock contention, blocked chains, thread-pool saturation, JDBC/HTTP exhaustion patterns."
        />
        <UploadCard
          tag="02"
          title="Heap Dump"
          subtitle="jmap -dump · jcmd GC.heap_dump"
          formats=".hprof"
          accept=".hprof,application/octet-stream"
          onFile={(f) => onHeapUpload(f, false)}
          quickOption
          onQuickFile={(f) => onHeapUpload(f, true)}
          loading={loading}
          tone="info"
          description="Streams .hprof binaries up to 50GB. Builds class histograms by instance count + shallow size. Flags leak signatures."
          serverPath
          onServerPath={onHeapPath}
        />
        <UploadCard
          tag="03"
          title="GC Log"
          subtitle="-Xlog:gc* · PrintGCDetails"
          formats=".log · .txt"
          accept=".log,.txt,text/plain"
          onFile={onGCUpload}
          loading={loading}
          tone="ok"
          description="Reads unified or legacy GC logs. Reports throughput, pause percentiles, and the post-GC live-set trend — the over-time proof of a leak a single heap snapshot can't give."
        />
      </div>

      {error && (
        <div className="panel border-flag-critical/40 bg-flag-critical/5 p-4 mb-12 animate-fade-in">
          <div className="flex items-start gap-3">
            <span className="badge-critical">error</span>
            <p className="font-mono text-sm text-flag-critical/90">{error}</p>
          </div>
        </div>
      )}

      <div className="border-t border-ink-700/40 pt-12 mt-12">
        <div className="grid md:grid-cols-3 gap-8">
          <Feature
            label="Source pinpointing"
            text="Attach a source repo and each finding gets a file path, line number, and surrounding code."
          />
          <Feature
            label="25GB+ heap dumps"
            text="Streaming parser handles production-scale dumps. Upload progress, parse progress, and ETA all live."
          />
          <Feature
            label="Pattern recognition"
            text="HikariCP exhaustion, Tomcat saturation, ThreadLocal leaks, hot-stack clusters — plus optional AI write-up."
          />
        </div>
      </div>

      <CaptureGuide />
    </div>
  )
}

function UploadCard({
  tag, title, subtitle, formats, accept, onFile,
  quickOption, onQuickFile, loading, tone, description,
  serverPath, onServerPath,
}) {
  const [drag, setDrag] = useState(false)
  const [showPath, setShowPath] = useState(false)
  const [pathInput, setPathInput] = useState('')
  const inputRef = useRef(null)

  const handleDrop = (e) => {
    e.preventDefault()
    setDrag(false)
    const file = e.dataTransfer.files?.[0]
    if (file) onFile(file)
  }

  const tc = TONES[tone] || TONES.info
  const toneClasses = tc.hover
  const dragClasses = drag ? tc.drag : 'border-ink-600/60'

  return (
    <div
      className={`panel p-6 md:p-8 transition-all duration-200 group relative overflow-hidden ${toneClasses} ${dragClasses}`}
      onDragOver={(e) => { e.preventDefault(); setDrag(true) }}
      onDragLeave={() => setDrag(false)}
      onDrop={handleDrop}
    >
      <div className="absolute top-4 right-4 label">{tag}</div>

      <div className="mb-6">
        <h2 className="font-display text-2xl md:text-3xl font-normal text-bone-100 tracking-tightest mb-2">
          {title}
        </h2>
        <p className="font-mono text-[11px] text-bone-500 uppercase tracking-wider">
          {subtitle}
        </p>
      </div>

      <p className="text-sm text-bone-400 leading-relaxed mb-6 min-h-[3rem]">
        {description}
      </p>

      {!showPath ? (
        <div className="border border-dashed border-ink-600/60 rounded-lg p-6 text-center bg-ink-950/30">
          <input
            ref={inputRef}
            type="file"
            accept={accept}
            className="hidden"
            onChange={(e) => {
              const f = e.target.files?.[0]
              if (f) onFile(f)
              e.target.value = ''
            }}
          />
          <div className="text-bone-400 text-sm mb-3">
            <span className="font-mono text-bone-500">→</span> Drop file or
          </div>
          <button
            onClick={() => inputRef.current?.click()}
            disabled={loading}
            className={tc.btn}
          >
            {loading ? 'Analyzing…' : 'Choose file'}
          </button>

          {quickOption && (
            <div className="mt-3 text-[10px] font-mono text-bone-500 uppercase tracking-wider">
              for sampling,
              <button
                onClick={(e) => {
                  e.preventDefault()
                  const inp = document.createElement('input')
                  inp.type = 'file'
                  inp.accept = accept
                  inp.onchange = (ev) => {
                    const f = ev.target.files?.[0]
                    if (f) onQuickFile(f)
                  }
                  inp.click()
                }}
                className="text-flag-info hover:underline ml-1"
              >
                try quick mode (256MB sample)
              </button>
            </div>
          )}

          {serverPath && (
            <div className="mt-3 text-[10px] font-mono text-bone-500 uppercase tracking-wider">
              dump on this server?
              <button
                onClick={(e) => { e.preventDefault(); setShowPath(true) }}
                className="text-flag-info hover:underline ml-1"
              >
                use server-side path
              </button>
            </div>
          )}

          <div className="mt-4 text-[10px] font-mono text-bone-500 tracking-wider">
            {formats}
          </div>
        </div>
      ) : (
        <div className="border border-dashed border-flag-info/40 rounded-lg p-5 bg-flag-info/[0.03]">
          <div className="label text-flag-info mb-2">// server-side path</div>
          <input
            type="text"
            value={pathInput}
            onChange={(e) => setPathInput(e.target.value)}
            placeholder="/var/log/heap-2026-05-26.hprof"
            className="w-full bg-ink-950 border border-ink-600/60 rounded px-3 py-2 font-mono text-xs text-bone-100 placeholder-bone-500 focus:outline-none focus:border-flag-info/50 mb-3"
            disabled={loading}
          />
          <p className="font-mono text-[10px] text-bone-500 mb-3">
            skips upload — best for multi-GB dumps already on the server
          </p>
          <div className="flex gap-2">
            <button
              onClick={() => onServerPath(pathInput.trim(), false)}
              disabled={loading || !pathInput.trim()}
              className="btn bg-flag-info/10 text-flag-info border-flag-info/30 hover:bg-flag-info/20 hover:border-flag-info/50 disabled:opacity-50"
            >
              Analyze
            </button>
            <button
              onClick={() => { setShowPath(false); setPathInput('') }}
              className="btn-secondary"
              disabled={loading}
            >
              cancel
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

function Feature({ label, text }) {
  return (
    <div>
      <div className="label mb-3 flex items-center gap-2">
        <span className="w-1 h-1 bg-flag-warning rounded-full" />
        {label}
      </div>
      <p className="text-sm text-bone-300 leading-relaxed">{text}</p>
    </div>
  )
}
