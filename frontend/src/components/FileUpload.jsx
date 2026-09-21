import { useId, useRef, useState } from 'react'

/** Shared keyboard-accessible file picker and drop target. */
export default function FileUpload({ label, accept, formats, onFile, loading, file, onClear }) {
  const input = useRef(null)
  const id = useId()
  const [dragging, setDragging] = useState(false)
  return <div className={`file-upload${dragging ? ' is-dragging' : ''}${loading ? ' is-disabled' : ''}`}
    onDragOver={e => { e.preventDefault(); if (!loading) setDragging(true) }}
    onDragLeave={() => setDragging(false)}
    onDrop={e => { e.preventDefault(); e.stopPropagation(); setDragging(false); if (!loading && e.dataTransfer.files?.[0]) onFile(e.dataTransfer.files[0]) }}>
    <span className="file-upload-icon" aria-hidden="true">
      <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M12 16V4m-4 4 4-4 4 4M4 16v4h16v-4" /></svg>
    </span>
    <span id={`${id}-label`} className="file-upload-label">{label}</span>
    <span id={`${id}-hint`} className="file-upload-hint">{file ? file.name : 'Drag and drop your file here'}</span>
    <input ref={input} id={id} type="file" accept={accept} disabled={loading} className="hidden"
      aria-labelledby={`${id}-label`} aria-describedby={`${id}-hint`}
      onChange={e => { const selected = e.target.files?.[0]; if (selected) onFile(selected); e.target.value = '' }} />
    <div className="file-upload-actions">
      <button type="button" className="btn-primary" disabled={loading} aria-label={`${file ? 'Replace' : 'Upload'} ${label.toLowerCase()}`} onClick={() => input.current?.click()}>
        {loading ? 'Processing…' : file ? 'Replace file' : 'Upload file'}
      </button>
      {file && onClear && <button type="button" className="btn-secondary" disabled={loading} onClick={onClear}>Remove</button>}
    </div>
    <span className="file-upload-formats">{formats}</span>
  </div>
}
