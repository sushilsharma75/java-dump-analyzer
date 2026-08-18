"""
FastAPI entry point for the Java Dump Analyzer.

Key endpoints:
  GET  /api/health                        liveness
  POST /api/analyze/thread                upload jstack → structured analysis (synchronous)
  POST /api/analyze/heap                  small heap dumps → synchronous analysis
  POST /api/analyze/heap/async            kick off async parse of an uploaded heap dump
  POST /api/analyze/heap/path             kick off async parse of a server-side .hprof path
  GET  /api/jobs/{job_id}                 poll an in-progress analysis
  DELETE /api/jobs/{job_id}               clean up
  POST /api/source/upload                 upload a zip of source code → session_id
  POST /api/source/path                   index a server-side source directory
  GET  /api/source/{session}/lookup       resolve class+line → file & snippet
  DELETE /api/source/{session}            release source session
  POST /api/llm/summarize                 optional Claude-powered diagnosis
"""
from __future__ import annotations
import os
import io
import shutil
import tempfile
import zipfile
import asyncio
import logging
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, UploadFile, File, HTTPException, Form
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import httpx

from .schemas import (
    ThreadDumpAnalysis, HeapDumpAnalysis, GCLogAnalysis,
    LLMSummaryRequest, LLMSummaryResponse,
    CorrelationRequest, CorrelationResponse,
    HeapCompareRequest, HeapComparison, ThreadCompareRequest, ThreadComparison,
    JobStatus, SourceUploadResponse, SourceLookupResponse,
)
from .analyzers.diagnostics import analyze as analyze_thread_dump
from .analyzers.heap_dump import parse_heap_dump
from .analyzers.gc_log import parse_gc_log
from .analyzers.correlate import correlate as correlate_dumps
from .analyzers.compare import compare_heaps, compare_threads
from .analyzers.llm import generate_llm_summary, LLMRequestError
from .analyzers.source import SourceIndex
from .sessions import SOURCES, JOBS


logging.basicConfig(level=logging.INFO)
log = logging.getLogger("java-dump-analyzer")

app = FastAPI(
    title="Java Dump Analyzer",
    description="Analyze JVM thread dumps and heap dumps with actionable diagnostics.",
    version="0.2.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- Limits ---
MAX_THREAD_DUMP_BYTES = 50 * 1024 * 1024            # 50 MB
MAX_SYNC_HEAP_DUMP_BYTES = 200 * 1024 * 1024        # 200 MB sync threshold
MAX_HEAP_DUMP_BYTES = 50 * 1024 * 1024 * 1024       # 50 GB
MAX_SOURCE_ZIP_BYTES = 500 * 1024 * 1024            # 500 MB

TMP_DIR = Path(os.environ.get("DUMP_TMP_DIR", "/tmp/postmortem"))
TMP_DIR.mkdir(parents=True, exist_ok=True)


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "version": app.version,
        "tmp_dir": str(TMP_DIR),
        "active_sources": len(SOURCES._sessions),
        "active_jobs": len(JOBS._jobs),
    }


# ============================================================================
# Thread dump analysis (synchronous; thread dumps are small text)
# ============================================================================

@app.post("/api/analyze/thread", response_model=ThreadDumpAnalysis)
async def analyze_thread_endpoint(
    file: UploadFile = File(...),
    source_session: Optional[str] = Form(None),
):
    raw = await file.read()
    if len(raw) > MAX_THREAD_DUMP_BYTES:
        raise HTTPException(413, "Thread dump too large (max 50MB)")
    try:
        text = raw.decode("utf-8", errors="replace")
    except Exception as e:
        raise HTTPException(400, f"Could not decode text: {e}")

    source_index = None
    if source_session:
        sess = SOURCES.get(source_session)
        if not sess:
            raise HTTPException(404, f"Source session not found: {source_session}")
        source_index = sess["index"]

    log.info("Analyzing thread dump: %s (%d bytes, source=%s)",
             file.filename, len(raw), bool(source_index))
    try:
        result = analyze_thread_dump(text, source=source_index)
    except Exception as e:
        log.exception("Thread analysis failed")
        raise HTTPException(500, f"Analysis failed: {e}")
    return result


# ============================================================================
# GC log analysis (synchronous; GC logs are text, parsed line-by-line)
# ============================================================================

MAX_GC_LOG_BYTES = 200 * 1024 * 1024   # 200 MB of GC text is a very long run


@app.post("/api/analyze/gc", response_model=GCLogAnalysis)
async def analyze_gc_endpoint(file: UploadFile = File(...)):
    raw = await file.read()
    if len(raw) > MAX_GC_LOG_BYTES:
        raise HTTPException(413, "GC log too large (max 200MB)")
    try:
        text = raw.decode("utf-8", errors="replace")
    except Exception as e:
        raise HTTPException(400, f"Could not decode text: {e}")

    log.info("Analyzing GC log: %s (%d bytes)", file.filename, len(raw))
    try:
        result = parse_gc_log(text)
    except Exception as e:
        log.exception("GC log analysis failed")
        raise HTTPException(500, f"Analysis failed: {e}")
    return result


# ============================================================================
# Heap dump analysis — synchronous (small dumps) and async (large dumps)
# ============================================================================

def _resolve_source(source_session):
    if not source_session:
        return None
    sess = SOURCES.get(source_session)
    return sess["index"] if sess else None


@app.post("/api/analyze/heap", response_model=HeapDumpAnalysis)
async def analyze_heap_sync(
    file: UploadFile = File(...),
    quick: bool = Form(False),
    source_session: Optional[str] = Form(None),
):
    """Synchronous heap analysis for smaller dumps (< 200 MB).

    For larger files, use /api/analyze/heap/async — clients get a job id
    they can poll for progress.
    """
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".hprof", dir=TMP_DIR)
    total = 0
    try:
        while True:
            chunk = await file.read(8 * 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_SYNC_HEAP_DUMP_BYTES:
                raise HTTPException(
                    413,
                    f"File too large for sync endpoint (max {MAX_SYNC_HEAP_DUMP_BYTES // (1024*1024)} MB). "
                    "Use /api/analyze/heap/async instead.",
                )
            tmp.write(chunk)
        tmp.flush()
        tmp.close()

        log.info("Analyzing heap dump (sync): %s (%d bytes)", file.filename, total)
        with open(tmp.name, "rb") as fp:
            max_bytes = 256 * 1024 * 1024 if quick else None
            result = parse_heap_dump(fp, max_bytes=max_bytes, source=_resolve_source(source_session))
        return result
    except HTTPException:
        raise
    except Exception as e:
        log.exception("Heap analysis failed")
        raise HTTPException(500, f"Analysis failed: {e}")
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass


@app.post("/api/analyze/heap/async", response_model=JobStatus)
async def analyze_heap_async(
    file: UploadFile = File(...),
    quick: bool = Form(False),
    source_session: Optional[str] = Form(None),
):
    """
    Upload a heap dump in chunks and parse it asynchronously. Returns a JobStatus
    immediately; poll /api/jobs/{job_id} for progress. Supports files up to 50 GB.
    """
    job_id = JOBS.create(total_bytes=0)
    tmp_path = TMP_DIR / f"heap_{job_id}.hprof"
    total = 0
    try:
        with open(tmp_path, "wb") as out:
            while True:
                chunk = await file.read(8 * 1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_HEAP_DUMP_BYTES:
                    raise HTTPException(413, "Heap dump exceeds 50GB limit")
                out.write(chunk)
    except HTTPException:
        try: tmp_path.unlink(missing_ok=True)
        except Exception: pass
        JOBS.mark_error(job_id, "upload too large")
        raise
    except Exception as e:
        try: tmp_path.unlink(missing_ok=True)
        except Exception: pass
        JOBS.mark_error(job_id, f"upload failed: {e}")
        raise HTTPException(500, f"Upload failed: {e}")

    log.info("Uploaded heap dump for async parse: %s (%d bytes, job=%s)",
             file.filename, total, job_id)
    JOBS._jobs[job_id]["bytes_total"] = total
    JOBS.mark_running(job_id, tempfile=str(tmp_path))
    asyncio.create_task(_run_heap_parse(job_id, tmp_path, quick, source_session=source_session))
    return JobStatus(**JOBS.get(job_id))


class HeapPathRequest(BaseModel):
    path: str
    quick: bool = False
    source_session: Optional[str] = None


@app.post("/api/analyze/heap/path", response_model=JobStatus)
async def analyze_heap_path(req: HeapPathRequest):
    """
    Parse a .hprof file that already exists on the server's filesystem.

    Skips the upload entirely — perfect for self-hosted setups where a
    multi-GB dump is sitting next to the running app.
    """
    src = Path(req.path).expanduser().resolve()
    if not src.exists():
        raise HTTPException(404, f"File not found: {src}")
    if not src.is_file():
        raise HTTPException(400, f"Not a regular file: {src}")
    if src.stat().st_size > MAX_HEAP_DUMP_BYTES:
        raise HTTPException(413, "File exceeds 50GB limit")

    job_id = JOBS.create(total_bytes=src.stat().st_size)
    JOBS.mark_running(job_id, tempfile=None)
    log.info("Parsing server-side heap path: %s (%d bytes, job=%s)",
             src, src.stat().st_size, job_id)
    asyncio.create_task(_run_heap_parse(job_id, src, req.quick, delete_after=False, source_session=req.source_session))
    return JobStatus(**JOBS.get(job_id))


async def _run_heap_parse(
    job_id: str,
    path: Path,
    quick: bool,
    delete_after: bool = True,
    source_session: Optional[str] = None,
) -> None:
    """Background task: parse the file, report progress, store result."""
    try:
        cb = JOBS.progress_callback(job_id)
        src_index = _resolve_source(source_session)
        def _do_parse():
            with open(path, "rb") as fp:
                max_bytes = 256 * 1024 * 1024 if quick else None
                return parse_heap_dump(fp, max_bytes=max_bytes, progress_callback=cb, source=src_index)
        result = await asyncio.to_thread(_do_parse)
        JOBS.mark_done(job_id, result.model_dump())
        log.info("Heap parse complete: job=%s", job_id)
    except Exception as e:
        log.exception("Heap parse failed: job=%s", job_id)
        JOBS.mark_error(job_id, str(e))
    finally:
        if delete_after:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass


@app.get("/api/jobs/{job_id}", response_model=JobStatus)
def get_job(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(404, f"Job not found: {job_id}")
    if job["status"] != "done":
        job = {**job, "result": None}
    job.pop("tempfile", None)
    return JobStatus(**job)


@app.delete("/api/jobs/{job_id}")
def delete_job(job_id: str):
    if JOBS.remove(job_id):
        return {"deleted": True}
    raise HTTPException(404, "Job not found")


# ============================================================================
# Source code repository — upload, lookup, release
# ============================================================================

@app.post("/api/source/upload", response_model=SourceUploadResponse)
async def upload_source(file: UploadFile = File(...)):
    """
    Accept a .zip of source code, extract it to a temp dir, and build an
    in-memory class-name → file index.

    Returns a session_id to pass into /api/analyze/thread (as form field
    `source_session`) for findings enriched with exact source locations.
    """
    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(400, "Expected a .zip archive of source code")

    raw = await file.read()
    if len(raw) > MAX_SOURCE_ZIP_BYTES:
        raise HTTPException(413, f"Zip too large (max {MAX_SOURCE_ZIP_BYTES // (1024*1024)} MB)")

    tempdir = Path(tempfile.mkdtemp(prefix="postmortem_src_", dir=TMP_DIR))
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            # Path traversal safety
            for name in zf.namelist():
                normalized = os.path.normpath(name)
                if normalized.startswith("..") or os.path.isabs(normalized):
                    raise HTTPException(400, f"Unsafe path in zip: {name}")
            zf.extractall(tempdir)
    except zipfile.BadZipFile:
        shutil.rmtree(tempdir, ignore_errors=True)
        raise HTTPException(400, "Not a valid zip archive")
    except HTTPException:
        shutil.rmtree(tempdir, ignore_errors=True)
        raise

    # If the zip contains a single top-level directory, point root at it
    root = tempdir
    entries = list(tempdir.iterdir())
    if len(entries) == 1 and entries[0].is_dir():
        root = entries[0]

    log.info("Indexing source at %s", root)
    index = SourceIndex(root)
    await asyncio.to_thread(index.build)
    session_id = SOURCES.add(root, index, tempdir=tempdir)
    log.info("Source session %s indexed: %d files, %d classes",
             session_id, index.files_indexed, index.classes_indexed)

    return SourceUploadResponse(
        session_id=session_id,
        files_indexed=index.files_indexed,
        classes_indexed=index.classes_indexed,
        root_dir=str(root),
        languages=index.languages,
    )


class SourcePathRequest(BaseModel):
    path: str


@app.post("/api/source/path", response_model=SourceUploadResponse)
async def use_source_path(req: SourcePathRequest):
    """Index a source directory that already lives on the server's filesystem."""
    root = Path(req.path).expanduser().resolve()
    if not root.exists():
        raise HTTPException(404, f"Directory not found: {root}")
    if not root.is_dir():
        raise HTTPException(400, f"Not a directory: {root}")

    log.info("Indexing source at server-side path: %s", root)
    index = SourceIndex(root)
    await asyncio.to_thread(index.build)
    session_id = SOURCES.add(root, index, tempdir=None)
    return SourceUploadResponse(
        session_id=session_id,
        files_indexed=index.files_indexed,
        classes_indexed=index.classes_indexed,
        root_dir=str(root),
        languages=index.languages,
    )


class SourceGitRequest(BaseModel):
    url: str
    token: Optional[str] = None   # optional PAT for private repos; used once, never stored


@app.post("/api/source/git", response_model=SourceUploadResponse)
async def use_source_git(req: SourceGitRequest):
    """Fetch source from a GitHub / Bitbucket / GitLab URL and index it.

    The repo is downloaded as an archive (no full git history) into a temp dir,
    indexed, then the temp dir is cleaned up when the session is released.
    An optional access token may be supplied for private repos; it is used for
    the single download and never persisted.
    """
    from .analyzers.git_source import fetch_repo, GitFetchError

    try:
        root, meta = await asyncio.to_thread(fetch_repo, req.url, req.token, TMP_DIR)
    except GitFetchError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        log.exception("Git fetch failed")
        raise HTTPException(500, f"Could not fetch repository: {e}")

    log.info("Fetched repo %s/%s via %s; indexing %s",
             meta.get("owner"), meta.get("repo"), meta.get("method"), root)
    index = SourceIndex(root)
    await asyncio.to_thread(index.build)
    # The tempdir to clean up is the fetch working dir (parent of root when archive
    # produced a single top-level folder).
    cleanup_dir = root if root.parent == TMP_DIR else root.parent
    session_id = SOURCES.add(root, index, tempdir=cleanup_dir)

    label = f"{meta.get('host')}/{meta.get('owner')}/{meta.get('repo')}"
    if meta.get("ref"):
        label += f"@{meta['ref']}"
    return SourceUploadResponse(
        session_id=session_id,
        files_indexed=index.files_indexed,
        classes_indexed=index.classes_indexed,
        root_dir=label,
        languages=index.languages,
    )


@app.get("/api/source/{session_id}/lookup", response_model=SourceLookupResponse)
def lookup_source(session_id: str, class_name: str, line: Optional[int] = None):
    """Resolve a class + line to a file path and surrounding code snippet."""
    sess = SOURCES.get(session_id)
    if not sess:
        raise HTTPException(404, "Source session not found")
    resolved = sess["index"].lookup(class_name, line)
    if not resolved:
        return SourceLookupResponse(found=False)
    abs_path, snippet = resolved
    return SourceLookupResponse(
        found=True,
        file_path=sess["index"].relative_path(abs_path),
        snippet=snippet,
    )


@app.delete("/api/source/{session_id}")
def release_source(session_id: str):
    if SOURCES.remove(session_id):
        return {"released": True}
    raise HTTPException(404, "Source session not found")


# ============================================================================
# Cross-dump correlation (thread × heap × source)
# ============================================================================

@app.post("/api/correlate", response_model=CorrelationResponse)
async def correlate_endpoint(req: CorrelationRequest):
    """Cross-reference a heap analysis with a thread analysis to produce
    double-confirmed, line-precise findings. Optionally enriched with source."""
    source_index = _resolve_source(req.source_session)
    try:
        result = await asyncio.to_thread(
            correlate_dumps, req.heap, req.thread, source_index, req.gc
        )
    except Exception as e:
        log.exception("Correlation failed")
        raise HTTPException(500, f"Correlation failed: {e}")
    return CorrelationResponse(**result)


# ============================================================================
# Dump comparison / delta (two captures → what changed)
# ============================================================================

@app.post("/api/compare/heap", response_model=HeapComparison)
async def compare_heap_endpoint(req: HeapCompareRequest):
    """Diff two heap analyses → growers, new classes, leak-suspect findings."""
    source_index = _resolve_source(req.source_session)
    try:
        result = await asyncio.to_thread(compare_heaps, req.before, req.after, source_index)
    except Exception as e:
        log.exception("Heap comparison failed")
        raise HTTPException(500, f"Heap comparison failed: {e}")
    return HeapComparison(**result)


@app.post("/api/compare/threads", response_model=ThreadComparison)
async def compare_threads_endpoint(req: ThreadCompareRequest):
    """Diff two thread dumps → threads stuck in the same place across both."""
    try:
        result = await asyncio.to_thread(compare_threads, req.before, req.after)
    except Exception as e:
        log.exception("Thread comparison failed")
        raise HTTPException(500, f"Thread comparison failed: {e}")
    return ThreadComparison(**result)


# ============================================================================
# LLM diagnosis (optional)
# ============================================================================

@app.post("/api/llm/summarize", response_model=LLMSummaryResponse)
async def llm_summarize(req: LLMSummaryRequest):
    if not req.api_key:
        return LLMSummaryResponse(
            summary="",
            enabled=False,
            error="No API key provided. Add one in settings to enable LLM-powered diagnosis.",
        )
    try:
        summary = await generate_llm_summary(
            req.analysis, req.kind, req.api_key, model=req.model
        )
        return LLMSummaryResponse(summary=summary, enabled=True)
    except LLMRequestError as e:
        # The API explained itself — pass that through verbatim rather than a
        # bare status line, which is unactionable.
        log.warning("LLM request rejected (%s): %s", e.status, e.api_message)
        return LLMSummaryResponse(
            summary="", enabled=True,
            error=e.api_message + (f"\n\n{e.hint}" if e.hint else ""),
        )
    except httpx.TimeoutException:
        log.warning("LLM call timed out")
        return LLMSummaryResponse(
            summary="", enabled=True,
            error="The request to api.anthropic.com timed out after 120s. "
                  "Large unified analyses can be slow — retry, or run the single-dump "
                  "diagnosis instead.",
        )
    except httpx.RequestError as e:
        log.warning("LLM call could not reach the API: %s", e)
        return LLMSummaryResponse(
            summary="", enabled=True,
            error=f"Could not reach api.anthropic.com: {e}. Check the backend's network "
                  "access and any outbound proxy.",
        )
    except Exception as e:
        log.exception("LLM call failed")
        return LLMSummaryResponse(summary="", enabled=True, error=f"LLM call failed: {e}")


# ============================================================================
# Background GC task (periodic cleanup of stale sessions/jobs)
# ============================================================================

@app.on_event("startup")
async def _start_gc():
    async def _gc_loop():
        while True:
            await asyncio.sleep(300)  # every 5 minutes
            try:
                dropped_jobs = JOBS.gc(max_age_seconds=3600)
                dropped_sources = SOURCES.gc(max_age_seconds=24 * 3600)
                if dropped_jobs or dropped_sources:
                    log.info("GC: dropped %d jobs, %d sources", dropped_jobs, dropped_sources)
            except Exception as e:
                log.warning("GC loop error: %s", e)
    asyncio.create_task(_gc_loop())
