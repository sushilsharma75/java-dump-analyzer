"""
Lightweight in-memory session and job stores.

The MVP is a single-process self-hosted tool, so a process-local dict is fine.
For a multi-instance deployment you'd swap these for Redis-backed equivalents.
"""
from __future__ import annotations
import time
import uuid
import threading
import shutil
import logging
from pathlib import Path
from typing import Dict, Optional, Any, Callable
from .analyzers.source import SourceIndex


log = logging.getLogger("java-dump-analyzer.sessions")


class SourceSessionStore:
    """Holds extracted source repos keyed by session id. Cleans them up on demand."""

    def __init__(self):
        self._sessions: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

    def add(self, root: Path, source_index: SourceIndex, tempdir: Optional[Path] = None) -> str:
        sid = uuid.uuid4().hex[:16]
        with self._lock:
            self._sessions[sid] = {
                "session_id": sid,
                "root": root,
                "index": source_index,
                "tempdir": tempdir,  # to delete on cleanup
                "created_at": time.time(),
            }
        return sid

    def get(self, session_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self._sessions.get(session_id)

    def remove(self, session_id: str) -> bool:
        with self._lock:
            sess = self._sessions.pop(session_id, None)
        if not sess:
            return False
        td = sess.get("tempdir")
        if td:
            try:
                shutil.rmtree(td, ignore_errors=True)
            except Exception as e:
                log.warning("Could not delete tempdir %s: %s", td, e)
        return True

    def gc(self, max_age_seconds: float = 24 * 3600) -> int:
        """Remove sessions older than `max_age_seconds`. Returns count removed."""
        now = time.time()
        to_drop = []
        with self._lock:
            for sid, sess in self._sessions.items():
                if now - sess["created_at"] > max_age_seconds:
                    to_drop.append(sid)
        for sid in to_drop:
            self.remove(sid)
        return len(to_drop)


class JobStore:
    """Tracks background analysis jobs (mainly for large heap dumps)."""

    def __init__(self):
        self._jobs: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

    def create(self, total_bytes: int = 0) -> str:
        job_id = uuid.uuid4().hex[:16]
        with self._lock:
            self._jobs[job_id] = {
                "job_id": job_id,
                "status": "queued",
                "bytes_processed": 0,
                "bytes_total": total_bytes,
                "records_seen": 0,
                "instances_seen": 0,
                "started_at": time.time(),
                "elapsed_seconds": 0.0,
                "eta_seconds": None,
                "error": None,
                "result": None,
                "tempfile": None,  # path to delete on cleanup
            }
        return job_id

    def get(self, job_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return None
            # Refresh derived fields
            job = dict(job)  # shallow copy so the caller can't mutate state
            job["elapsed_seconds"] = time.time() - job["started_at"]
            if job["bytes_processed"] > 0 and job["bytes_total"] > 0 and job["status"] == "running":
                rate = job["bytes_processed"] / max(job["elapsed_seconds"], 0.01)
                remaining = job["bytes_total"] - job["bytes_processed"]
                job["eta_seconds"] = remaining / rate if rate > 0 else None
            return job

    def progress_callback(self, job_id: str) -> Callable[[int, int, int], None]:
        """Return a callable to pass into the parser for progress updates."""
        def _cb(bytes_processed: int, records: int, instances: int):
            with self._lock:
                job = self._jobs.get(job_id)
                if not job:
                    return
                job["bytes_processed"] = bytes_processed
                job["records_seen"] = records
                job["instances_seen"] = instances
        return _cb

    def mark_running(self, job_id: str, tempfile: Optional[str] = None) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job:
                job["status"] = "running"
                job["started_at"] = time.time()
                if tempfile:
                    job["tempfile"] = tempfile

    def mark_done(self, job_id: str, result: Dict[str, Any]) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job:
                job["status"] = "done"
                job["result"] = result
                job["bytes_processed"] = job["bytes_total"]

    def mark_error(self, job_id: str, error: str) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job:
                job["status"] = "error"
                job["error"] = error

    def remove(self, job_id: str) -> bool:
        with self._lock:
            job = self._jobs.pop(job_id, None)
        if not job:
            return False
        tf = job.get("tempfile")
        if tf:
            try:
                Path(tf).unlink(missing_ok=True)
            except Exception as e:
                log.warning("Could not delete tempfile %s: %s", tf, e)
        return True

    def gc(self, max_age_seconds: float = 3600) -> int:
        """Remove finished jobs older than max_age_seconds."""
        now = time.time()
        to_drop = []
        with self._lock:
            for jid, job in self._jobs.items():
                age = now - job["started_at"]
                if job["status"] in ("done", "error") and age > max_age_seconds:
                    to_drop.append(jid)
        for jid in to_drop:
            self.remove(jid)
        return len(to_drop)


# Process-wide singletons
SOURCES = SourceSessionStore()
JOBS = JobStore()
