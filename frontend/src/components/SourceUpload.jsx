import { useState, useRef } from 'react'
import { uploadSource, indexSourcePath, indexSourceGit, releaseSource } from '../api'

const SESSION_STORAGE_KEY = 'postmortem.source_session'

export default function SourceUpload({ session, onSession }) {
  const [drag, setDrag] = useState(false)
  const [uploading, setUploading] = useState(false)
  const [uploadProgress, setUploadProgress] = useState(0)
  const [error, setError] = useState(null)
  const [mode, setMode] = useState('git') // git | zip | path
  const [pathInput, setPathInput] = useState('')
  const [gitUrl, setGitUrl] = useState('')
  const [gitToken, setGitToken] = useState('')
  const [showToken, setShowToken] = useState(false)
  const inputRef = useRef(null)

  const handleGit = async () => {
    if (!gitUrl.trim()) return
    setUploading(true)
    setError(null)
    try {
      const result = await indexSourceGit(gitUrl.trim(), gitToken.trim() || null)
      onSession(result)
      try { localStorage.setItem(SESSION_STORAGE_KEY, result.session_id) } catch {}
    } catch (e) {
      setError(e.message)
    } finally {
      setUploading(false)
    }
  }

  const handleFile = async (file) => {
    setUploading(true)
    setError(null)
    setUploadProgress(0)
    try {
      const result = await uploadSource(file, ({ loaded, total }) => {
        setUploadProgress(total ? (loaded / total) * 100 : 0)
      })
      onSession(result)
      try { localStorage.setItem(SESSION_STORAGE_KEY, result.session_id) } catch {}
    } catch (e) {
      setError(e.message)
    } finally {
      setUploading(false)
    }
  }

  const handlePath = async () => {
    if (!pathInput.trim()) return
    setUploading(true)
    setError(null)
    try {
      const result = await indexSourcePath(pathInput.trim())
      onSession(result)
      try { localStorage.setItem(SESSION_STORAGE_KEY, result.session_id) } catch {}
    } catch (e) {
      setError(e.message)
    } finally {
      setUploading(false)
    }
  }

  const handleDrop = (e) => {
    e.preventDefault()
    setDrag(false)
    const file = e.dataTransfer.files?.[0]
    if (file) handleFile(file)
  }

  const handleDisconnect = async () => {
    if (session) {
      try { await releaseSource(session.session_id) } catch {}
      try { localStorage.removeItem(SESSION_STORAGE_KEY) } catch {}
    }
    onSession(null)
  }

  // Connected state
  if (session) {
    return (
      <div className="panel border-flag-ok/30 bg-flag-ok/[0.03] p-5 animate-fade-in">
        <div className="flex items-start gap-4">
          <div className="w-9 h-9 rounded-md bg-flag-ok/15 border border-flag-ok/30 flex items-center justify-center shrink-0">
            <span className="text-flag-ok font-mono text-lg">✓</span>
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1 flex-wrap">
              <span className="badge-ok">source attached</span>
              <span className="label text-bone-500">// will resolve stack frames to code</span>
            </div>
            <div className="font-mono text-xs text-bone-300 truncate">
              {session.root_dir}
            </div>
            <div className="font-mono text-[11px] text-bone-500 mt-1">
              {session.classes_indexed.toLocaleString()} classes · {session.files_indexed.toLocaleString()} files
              {Object.entries(session.languages).map(([ext, n]) => (
                <span key={ext} className="ml-2">{ext} ×{n.toLocaleString()}</span>
              ))}
            </div>
          </div>
          <button
            onClick={handleDisconnect}
            className="font-mono text-xs text-bone-500 hover:text-flag-critical transition-colors shrink-0"
            title="Disconnect source"
          >
            ✕
          </button>
        </div>
      </div>
    )
  }

  // Disconnected state
  return (
    <div className="panel p-5 md:p-6 animate-fade-in">
      <div className="flex items-start gap-4 mb-4">
        <div className="w-9 h-9 rounded-md border border-ink-600/60 bg-ink-800 flex items-center justify-center shrink-0">
          <span className="font-mono text-base text-bone-300">{}</span>
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-baseline gap-2 mb-1 flex-wrap">
            <h3 className="font-display text-lg text-bone-100">
              Attach source code <span className="text-bone-500 text-sm font-normal">— optional</span>
            </h3>
          </div>
          <p className="text-sm text-bone-400 leading-relaxed">
            Paste a GitHub/Bitbucket URL (or upload a zip) and each finding gets pinpointed
            to the exact file and line of code responsible — with the surrounding lines shown inline.
          </p>
        </div>
      </div>

      <div className="flex gap-2 mb-3">
        <ModeTab active={mode === 'git'} onClick={() => setMode('git')}>git url</ModeTab>
        <ModeTab active={mode === 'zip'} onClick={() => setMode('zip')}>upload zip</ModeTab>
        <ModeTab active={mode === 'path'} onClick={() => setMode('path')}>server path</ModeTab>
      </div>

      {mode === 'git' && (
        <div>
          <input
            type="text"
            value={gitUrl}
            onChange={(e) => setGitUrl(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter') handleGit() }}
            placeholder="https://github.com/owner/repo  ·  bitbucket.org/owner/repo  ·  owner/repo"
            className="w-full bg-ink-950 border border-ink-600/60 rounded px-3 py-2 font-mono text-sm text-bone-100 placeholder-bone-500 focus:outline-none focus:border-flag-ok/50"
            disabled={uploading}
          />
          <p className="font-mono text-[10px] text-bone-500 mt-2">
            GitHub, Bitbucket, or GitLab. Add /tree/&lt;branch&gt; for a specific branch or tag.
          </p>

          {!showToken ? (
            <button
              onClick={() => setShowToken(true)}
              className="font-mono text-[10px] text-bone-400 hover:text-bone-200 mt-2 transition-colors"
            >
              + private repo? add an access token
            </button>
          ) : (
            <div className="mt-2">
              <input
                type="password"
                value={gitToken}
                onChange={(e) => setGitToken(e.target.value)}
                placeholder="personal access token (used once, never stored)"
                className="w-full bg-ink-950 border border-ink-600/60 rounded px-3 py-2 font-mono text-xs text-bone-100 placeholder-bone-500 focus:outline-none focus:border-flag-ok/50"
                disabled={uploading}
                autoComplete="off"
              />
            </div>
          )}

          <button
            onClick={handleGit}
            disabled={uploading || !gitUrl.trim()}
            className="btn bg-flag-ok/10 text-flag-ok border-flag-ok/30 hover:bg-flag-ok/20 hover:border-flag-ok/50 mt-3 disabled:opacity-50"
          >
            {uploading ? 'fetching & indexing…' : 'Fetch from Git'}
          </button>
        </div>
      )}
      {mode === 'zip' && (
        <div
          className={`border border-dashed rounded-lg p-5 text-center transition-all ${
            drag ? 'border-flag-ok bg-flag-ok/5' : 'border-ink-600/60 bg-ink-950/30'
          }`}
          onDragOver={(e) => { e.preventDefault(); setDrag(true) }}
          onDragLeave={() => setDrag(false)}
          onDrop={handleDrop}
        >
          <input
            ref={inputRef}
            type="file"
            accept=".zip,application/zip"
            className="hidden"
            onChange={(e) => {
              const f = e.target.files?.[0]
              if (f) handleFile(f)
              e.target.value = ''
            }}
          />
          {!uploading ? (
            <>
              <div className="text-bone-400 text-sm mb-3">
                <span className="font-mono text-bone-500">→</span> Drop a .zip of your repo, or
              </div>
              <button
                onClick={() => inputRef.current?.click()}
                className="btn bg-flag-ok/10 text-flag-ok border-flag-ok/30 hover:bg-flag-ok/20 hover:border-flag-ok/50"
              >
                Choose zip file
              </button>
              <div className="mt-3 text-[10px] font-mono text-bone-500 tracking-wider">
                indexes .java · .kt · .scala · up to 500MB
              </div>
            </>
          ) : (
            <div className="font-mono text-xs text-flag-ok">
              <div className="mb-2">uploading {uploadProgress.toFixed(0)}%</div>
              <div className="h-1 bg-ink-700 rounded-full overflow-hidden">
                <div
                  className="h-full bg-flag-ok transition-all"
                  style={{ width: `${uploadProgress}%` }}
                />
              </div>
              {uploadProgress >= 100 && <div className="mt-3 text-bone-400">indexing…</div>}
            </div>
          )}
        </div>
      )}

      {mode === 'path' && (
        <div>
          <input
            type="text"
            value={pathInput}
            onChange={(e) => setPathInput(e.target.value)}
            placeholder="/absolute/path/to/your/repo"
            className="w-full bg-ink-950 border border-ink-600/60 rounded px-3 py-2 font-mono text-sm text-bone-100 placeholder-bone-500 focus:outline-none focus:border-flag-ok/50"
            disabled={uploading}
          />
          <p className="font-mono text-[10px] text-bone-500 mt-2">
            best for self-hosted: skips the zip step entirely
          </p>
          <button
            onClick={handlePath}
            disabled={uploading || !pathInput.trim()}
            className="btn bg-flag-ok/10 text-flag-ok border-flag-ok/30 hover:bg-flag-ok/20 hover:border-flag-ok/50 mt-3 disabled:opacity-50"
          >
            {uploading ? 'indexing…' : 'Index directory'}
          </button>
        </div>
      )}

      {error && (
        <div className="mt-3 border border-flag-critical/40 bg-flag-critical/5 rounded p-3">
          <p className="font-mono text-xs text-flag-critical">{error}</p>
        </div>
      )}
    </div>
  )
}

function ModeTab({ active, onClick, children }) {
  return (
    <button
      onClick={onClick}
      className={`px-3 py-1.5 rounded-md font-mono text-[11px] uppercase tracking-wider border transition-all ${
        active
          ? 'bg-flag-ok/10 text-flag-ok border-flag-ok/30'
          : 'bg-ink-800 text-bone-400 border-ink-600/60 hover:text-bone-200'
      }`}
    >
      {children}
    </button>
  )
}
