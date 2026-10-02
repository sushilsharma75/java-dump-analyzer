"""Saved heap checkpoints and cooperative background scan control.

Only progress metadata is streamed. Reports are fetched once per revision.
A restart preserves reports but does not resume a partially executed scan.
"""
import json
import os
import threading
import time
import uuid

from . import artifacts
from .sessions import JOBS


class HeapCancelled(BaseException):
    """Must escape best-effort analyzer exception handlers."""


def saved_job(job_id):
    try:
        path = artifacts.path_for(job_id, '.job')
        data = json.loads(path.read_text(encoding='utf-8'))
    except (ValueError, FileNotFoundError):
        return None
    if data['status'] in ('running', 'queued'):
        data.update(status='interrupted', stage='Interrupted by backend restart',
                    error='The backend restarted. The latest saved report is available; unfinished scans must be run again.')
    return data


def public_job(job):
    return {k: v for k, v in job.items() if k not in ('tempfile', 'result', 'stage_started_at')}


def persist_job(job):
    path = artifacts.path_for(job['job_id'], '.job')
    tmp = path.with_suffix('.' + uuid.uuid4().hex + '.tmp')
    tmp.write_text(json.dumps(public_job(job)), encoding='utf-8')
    tmp.replace(path)


class HeapRun:
    def __init__(self, job_id, identifier):
        self.job_id = job_id
        self.identifier = identifier
        self.cancelled = threading.Event()
        self.current_stage = ''
        self.scan_pass = 0
        self.last_tick = 0
        self.input_format = {'format': 'hprof', 'compression': None}
        JOBS.update(job_id, analysis_id=None, revision=0)
        JOBS.on_cancel(job_id, self.cancelled.set)
        persist_job(JOBS.get(job_id))

    def check(self):
        if self.cancelled.is_set():
            raise HeapCancelled()

    def stage(self, name):
        self.check()
        if name != self.current_stage:
            # Analyzer messages append live counters after a colon. Updating
            # those details does not start a new stage or a new file scan.
            changed_stage = name.partition(':')[0] != self.current_stage.partition(':')[0]
            self.current_stage = name
            updates = {'stage': name}
            if changed_stage:
                self.scan_pass = 0
                self.last_tick = 0
                updates.update(stage_started_at=time.time(),
                               scan_pass=0, scan_bytes=0, scan_total=0)
            JOBS.update(self.job_id, **updates)
            persist_job(JOBS.get(self.job_id))

    def progress(self, position, total, new_pass=False):
        self.check()
        if new_pass or not self.scan_pass:
            self.scan_pass += 1
        now = time.monotonic()
        if new_pass or now - self.last_tick >= .25 or position >= total:
            self.last_tick = now
            JOBS.update(self.job_id, scan_pass=self.scan_pass,
                        scan_bytes=min(position, total), scan_total=total)

    def publish(self, result, status='running'):
        result = result.model_dump() if hasattr(result, 'model_dump') else dict(result)
        job = JOBS.get(self.job_id)
        # A removed job cannot resurrect itself or recreate deleted reports.
        if not job:
            raise HeapCancelled()
        revision = job.get('revision', 0) + 1
        result.update(analysis_id=self.identifier, input_format=self.input_format,
                      background_job={'job_id': self.job_id, 'status': status, 'revision': revision})
        if any(s['stage'] == 'object index' and s['status'] == 'completed' for s in result['stages']):
            result['object_index_id'] = self.identifier
        if status in ('cancelled', 'error'):
            result['summary'] = result['summary'].replace(
                'Background analysis is unfinished; further findings may follow.',
                'Background analysis ' + status + '; this report contains the completed stages.')
        if status != 'running':
            for stage in result['stages']:
                if stage['status'] == 'pending':
                    stage.update(status='cancelled' if status == 'cancelled' else 'failed',
                                 reason='Background analysis ' + status + '; saved results remain available')
        with artifacts.LOCK:
            try:
                previous = artifacts.read(self.identifier)['analysis']
            except FileNotFoundError:
                previous = {}
            # User annotations can change while a background checkpoint is built.
            for field in ('investigation_notes', 'capture'):
                if field in previous:
                    result[field] = previous[field]
            provenance = result.get('source_provenance') or {}
            build_id = (result.get('capture') or {}).get('build_id')
            matched = bool(provenance.get('manifest_valid') and build_id and build_id == provenance.get('build_id'))
            provenance['build_verified'] = matched
            for finding in result.get('findings', []):
                for loc in finding.get('source_locations', []):
                    loc['build_verified'] = matched
            artifacts.save(result, 'heap')
        JOBS.update(self.job_id, result=result, analysis_id=self.identifier, revision=revision)
        persist_job(JOBS.get(self.job_id))

    def finish(self, status, error=None):
        job = JOBS.get(self.job_id)
        if not job:
            return
        if not (job.get('result') or {}).get('object_index_id'):
            # A cancelled/failed catalog is unusable and may otherwise occupy GBs.
            artifacts.path_for(self.identifier, '.sqlite').unlink(missing_ok=True)
            artifacts.path_for(self.identifier, '.sqlite-journal').unlink(missing_ok=True)
        if job.get('result'):
            self.publish(job['result'], status)
        JOBS.update(self.job_id, status=status, error=error,
                    stage={'done': 'Complete', 'cancelled': 'Background analysis cancelled',
                           'error': 'Background analysis failed'}[status])
        persist_job(JOBS.get(self.job_id))
        JOBS.clear_cancel(self.job_id)


class ScanStream:
    """Observe buffered file I/O, without a callback for every heap object.

    Progress is the file position of the current scan, including skipped bytes.
    Rewinds start another pass. Seeking to EOF for a size query is not a scan.
    """
    def __init__(self, fp, run):
        self.fp = fp
        self.run = run
        self.total = os.fstat(fp.fileno()).st_size
        self.moved = False

    def read(self, size=-1):
        self.run.check()
        data = self.fp.read(size)
        self.moved = self.moved or bool(data)
        self.run.progress(self.fp.tell(), self.total)
        return data

    def seek(self, offset, whence=0):
        self.run.check()
        result = self.fp.seek(offset, whence)
        if whence == 0 and offset == 0 and self.moved:
            self.run.progress(0, self.total, new_pass=True)
            self.moved = False
        elif whence == os.SEEK_CUR:
            self.run.progress(result, self.total)
        return result

    def __getattr__(self, name):
        return getattr(self.fp, name)
