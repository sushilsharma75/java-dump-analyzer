const BASE = import.meta.env.VITE_API_BASE || '';

export async function analyzeThreadDump(file, sourceSession = null) {
  const fd = new FormData();
  fd.append('file', file);
  if (sourceSession) fd.append('source_session', sourceSession);
  const res = await fetch(`${BASE}/api/analyze/thread`, { method: 'POST', body: fd });
  if (!res.ok) throw new Error(`Thread analysis failed: ${res.status} ${await res.text()}`);
  return res.json();
}

/** GC log upload (unified -Xlog:gc* or legacy PrintGCDetails). Always synchronous — GC logs are text. */
export async function analyzeGCLog(file) {
  const fd = new FormData();
  fd.append('file', file);
  const res = await fetch(`${BASE}/api/analyze/gc`, { method: 'POST', body: fd });
  if (!res.ok) throw new Error(`GC log analysis failed: ${res.status} ${await res.text()}`);
  return res.json();
}

/** Synchronous heap upload — fine for files under 200MB. */
export async function analyzeHeapDumpSync(file, quick = false, sourceSession = null) {
  const fd = new FormData();
  fd.append('file', file);
  fd.append('quick', String(quick));
  if (sourceSession) fd.append('source_session', sourceSession);
  const res = await fetch(`${BASE}/api/analyze/heap`, { method: 'POST', body: fd });
  if (!res.ok) throw new Error(`Heap analysis failed: ${res.status} ${await res.text()}`);
  return res.json();
}

/** Submit a large heap dump for async parsing. Returns the initial JobStatus. */
export async function analyzeHeapDumpAsync(file, quick = false, onUploadProgress = null, sourceSession = null) {
  return new Promise((resolve, reject) => {
    const fd = new FormData();
    fd.append('file', file);
    fd.append('quick', String(quick));
    if (sourceSession) fd.append('source_session', sourceSession);
    const xhr = new XMLHttpRequest();
    xhr.open('POST', `${BASE}/api/analyze/heap/async`);
    if (onUploadProgress) {
      xhr.upload.onprogress = (e) => {
        if (e.lengthComputable) onUploadProgress({ loaded: e.loaded, total: e.total });
      };
    }
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        try { resolve(JSON.parse(xhr.responseText)); }
        catch (e) { reject(e); }
      } else {
        reject(new Error(`Upload failed: ${xhr.status} ${xhr.responseText}`));
      }
    };
    xhr.onerror = () => reject(new Error('Network error during upload'));
    xhr.send(fd);
  });
}

/** Trigger parsing of a heap dump that already exists on the server. */
export async function analyzeHeapDumpPath(path, quick = false, sourceSession = null) {
  const res = await fetch(`${BASE}/api/analyze/heap/path`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ path, quick, source_session: sourceSession || null }),
  });
  if (!res.ok) throw new Error(`Path analysis failed: ${res.status} ${await res.text()}`);
  return res.json();
}

export async function getJob(jobId) {
  const res = await fetch(`${BASE}/api/jobs/${jobId}`);
  if (!res.ok) throw new Error(`Job poll failed: ${res.status}`);
  return res.json();
}

export async function deleteJob(jobId) {
  await fetch(`${BASE}/api/jobs/${jobId}`, { method: 'DELETE' });
}

/** Upload a zip of source code → returns { session_id, files_indexed, ... } */
export async function uploadSource(file, onProgress = null) {
  return new Promise((resolve, reject) => {
    const fd = new FormData();
    fd.append('file', file);
    const xhr = new XMLHttpRequest();
    xhr.open('POST', `${BASE}/api/source/upload`);
    if (onProgress) {
      xhr.upload.onprogress = (e) => {
        if (e.lengthComputable) onProgress({ loaded: e.loaded, total: e.total });
      };
    }
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        try { resolve(JSON.parse(xhr.responseText)); }
        catch (e) { reject(e); }
      } else {
        reject(new Error(`Source upload failed: ${xhr.status} ${xhr.responseText}`));
      }
    };
    xhr.onerror = () => reject(new Error('Network error during source upload'));
    xhr.send(fd);
  });
}

export async function indexSourcePath(path) {
  const res = await fetch(`${BASE}/api/source/path`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ path }),
  });
  if (!res.ok) throw new Error(`Source path index failed: ${res.status} ${await res.text()}`);
  return res.json();
}

export async function indexSourceGit(url, token = null) {
  const res = await fetch(`${BASE}/api/source/git`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url, token: token || null }),
  });
  if (!res.ok) throw new Error(`${await res.text()}`);
  return res.json();
}

export async function lookupSource(sessionId, className, line = null) {
  const params = new URLSearchParams({ class_name: className });
  if (line) params.set('line', String(line));
  const res = await fetch(`${BASE}/api/source/${sessionId}/lookup?${params}`);
  if (!res.ok) throw new Error(`Source lookup failed: ${res.status}`);
  return res.json();
}

export async function releaseSource(sessionId) {
  await fetch(`${BASE}/api/source/${sessionId}`, { method: 'DELETE' });
}

/** Cross-reference a heap analysis with a thread analysis (optionally + GC log + source). */
export async function correlateDumps(heap, thread, sourceSession = null, gc = null) {
  const res = await fetch(`${BASE}/api/correlate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ heap, thread, gc: gc || null, source_session: sourceSession || null }),
  });
  if (!res.ok) throw new Error(`Correlation failed: ${res.status} ${await res.text()}`);
  return res.json();
}

/** Diff two heap analyses → growers + leak-suspect findings (optionally + source). */
export async function compareHeaps(before, after, sourceSession = null) {
  const res = await fetch(`${BASE}/api/compare/heap`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ before, after, source_session: sourceSession || null }),
  });
  if (!res.ok) throw new Error(`Heap comparison failed: ${res.status} ${await res.text()}`);
  return res.json();
}

/** Diff two thread analyses → threads stuck in the same place across both. */
export async function compareThreads(before, after) {
  const res = await fetch(`${BASE}/api/compare/threads`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ before, after }),
  });
  if (!res.ok) throw new Error(`Thread comparison failed: ${res.status} ${await res.text()}`);
  return res.json();
}

export async function getLLMSummary(analysis, kind, apiKey, model, detail = "summary", sourceSession = null) {
  const res = await fetch(`${BASE}/api/llm/summarize`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ analysis, kind, api_key: apiKey, model: model || null, detail, source_session: sourceSession }),
  });
  if (!res.ok) {
    // The backend reports API rejections in the response body, not the status —
    // read it before falling back to a bare status line.
    let detail = ''
    try {
      const body = await res.json()
      detail = body.error || body.detail || ''
    } catch { /* non-JSON error page */ }
    throw new Error(detail || `LLM call failed: ${res.status}`);
  }
  return res.json();
}

/** Raw streamed body: no multipart pre-spooling or browser file.readAsText. */
export function uploadServerLog(file, timezoneOffset, onProgress, signal) {
  return new Promise((resolve, reject) => {
    const params = new URLSearchParams({ filename: file.name })
    if (timezoneOffset) params.set('timezone_offset', timezoneOffset)
    const xhr = new XMLHttpRequest()
    const abort = () => xhr.abort()
    const cleanup = () => signal?.removeEventListener('abort', abort)
    xhr.open('POST', `${BASE}/api/analyze/server-log?${params}`)
    xhr.setRequestHeader('Content-Type', 'application/octet-stream')
    xhr.upload.onprogress = e => { if (e.lengthComputable) onProgress?.({ loaded: e.loaded, total: e.total }) }
    xhr.onload = () => {
      cleanup()
      try {
        const data = JSON.parse(xhr.responseText)
        if (xhr.status < 200 || xhr.status >= 300) throw new Error(data.detail || `Log upload failed (${xhr.status})`)
        resolve(data)
      } catch (e) { reject(e) }
    }
    xhr.onerror = () => { cleanup(); reject(new Error('Network error uploading server log')) }
    xhr.onabort = () => { cleanup(); reject(new Error('Server log upload cancelled')) }
    if (signal?.aborted) { reject(new Error('Server log upload cancelled')); return }
    signal?.addEventListener('abort', abort, { once: true })
    xhr.send(file)
  })
}

export async function analyzeIncident(serverLogId, heapId, threadId, gcId, sourceSession) {
  const response = await fetch(`${BASE}/api/analyze/incident`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ server_log_id: serverLogId, heap_id: heapId || null,
      thread_id: threadId || null, gc_id: gcId || null, source_session: sourceSession || null }),
  })
  const data = await response.json()
  if (!response.ok) throw new Error(data.detail || `Combined analysis failed (${response.status})`)
  return data
}
