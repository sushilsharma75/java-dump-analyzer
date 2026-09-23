"""Large raw uploads, background log indexing, and persistent incident queries."""
import asyncio
import re
import threading
import uuid

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, Field

from . import artifacts
from .paths import dump_directory
from .sessions import JOBS, SOURCES
from .analyzers import server_log
from .analyzers.incident import analyze_incident
from .analyzers.evidence import stamp
from .schemas import Finding, Severity

router = APIRouter()
MAX_LOG_BYTES = 5 * 1024 ** 3
UPLOAD_CHUNK = 1024 * 1024
_tasks = set()
# One log index at a time bounds aggregate memory and disk contention.
_worker_lock = asyncio.Semaphore(1)


@router.on_event('startup')
def discard_interrupted_log_jobs():
    """Single-process service: no worker from the previous process can resume."""
    for path in dump_directory().glob('log_*.upload'):
        if re.fullmatch(r'log_[a-f0-9]{32}\.upload', path.name):
            path.unlink(missing_ok=True)
    for path in artifacts.ROOT.glob('*.log.sqlite*'):
        match = re.fullmatch(r'([a-f0-9]{32})\.log\.sqlite(?:-journal|-wal|-shm)?', path.name)
        if match and not artifacts.path_for(match[1]).exists():
            path.unlink(missing_ok=True)


def _source(session):
    if not session:
        return None
    found = SOURCES.get(session)
    if not found:
        raise HTTPException(404, 'Source session expired or unavailable; attach source again')
    return found['index']


def _saved(identifier, kind):
    try:
        item = artifacts.read(identifier)
    except (ValueError, FileNotFoundError):
        raise HTTPException(404, 'Analysis not found')
    if item['kind'] != kind:
        raise HTTPException(422, f'Expected a saved {kind} analysis')
    return item['analysis']


def _log_index(identifier):
    data = _saved(identifier, 'server_log')
    path = artifacts.path_for(identifier, '.log.sqlite')
    if not path.is_file():
        raise HTTPException(409, 'Server log event index unavailable; upload the log again')
    return data, path


def _offset(value):
    if value and not re.fullmatch(r'[+-](?:0\d|1[0-4]):[0-5]\d', value):
        raise HTTPException(422, 'Timezone offset must be ±HH:MM (for example +05:30)')
    return value


@router.post('/api/analyze/server-log')
async def upload_log(request: Request, filename: str = Query('server.log', max_length=255),
                     timezone_offset: str | None = None):
    """Raw request body avoids multipart pre-spooling an entire 5 GiB upload."""
    _offset(timezone_offset)
    content_type = request.headers.get('content-type', '').split(';')[0]
    if content_type not in ('application/octet-stream', 'text/plain', 'application/x-ndjson'):
        raise HTTPException(415, 'Send the log as a raw application/octet-stream body')
    try:
        length = int(request.headers.get('content-length', '0'))
    except ValueError:
        raise HTTPException(400, 'Invalid Content-Length')
    if length < 0:
        raise HTTPException(400, 'Invalid Content-Length')
    if length > MAX_LOG_BYTES:
        raise HTTPException(413, 'Server log exceeds the 5 GiB limit')
    root = dump_directory()
    root.mkdir(parents=True, exist_ok=True)
    identifier = uuid.uuid4().hex
    path = root / f'log_{identifier}.upload'
    total = 0
    try:
        with path.open('xb') as out:
            async for received in request.stream():
                total += len(received)
                if total > MAX_LOG_BYTES:
                    raise HTTPException(413, 'Server log exceeds the 5 GiB limit')
                # ASGI chunks can vary in size; all disk writes are bounded/off-loop.
                for start in range(0, len(received), UPLOAD_CHUNK):
                    await asyncio.to_thread(out.write, received[start:start + UPLOAD_CHUNK])
        if not total:
            raise HTTPException(400, 'Server log is empty')
        if length and total != length:
            raise HTTPException(400, 'Incomplete upload: Content-Length does not match received bytes')
        job_id = JOBS.create(total_bytes=total)
        cancel = threading.Event()
        JOBS.on_cancel(job_id, cancel.set)
        task = asyncio.create_task(_run_log(job_id, identifier, path, filename, timezone_offset, cancel))
        _tasks.add(task)
        task.add_done_callback(_tasks.discard)
        return {k: v for k, v in JOBS.get(job_id).items() if k != 'tempfile'}
    except BaseException:
        path.unlink(missing_ok=True)
        raise


async def _run_log(job_id, identifier, path, filename, offset, cancel):
    index = artifacts.path_for(identifier, '.log.sqlite')
    saved = False
    try:
        async with _worker_lock:
            if cancel.is_set():
                raise server_log.Cancelled()
            JOBS.mark_running(job_id)
            JOBS.stage_callback(job_id)('Scanning server log')
            def work():
                with path.open('rb') as fp:
                    prefix = fp.read(4096)
                    if prefix.startswith(b'\x1f\x8b') or b'\0' in prefix:
                        raise ValueError('Expected an uncompressed UTF-8 text or JSON-lines log')
                    fp.seek(0)
                    result = server_log.build_log_index(fp, index, offset=offset,
                        progress=JOBS.progress_callback(job_id), cancelled=cancel.is_set)
                result.update(analysis_id=identifier, filename=filename, log_index_id=identifier)
                findings = []
                for item in result['exceptions'][:10]:
                    findings.append(Finding(severity=Severity.WARNING, category='server_log',
                        title=f"Logged {item['exception']} ({item['count']:,} events)",
                        description='An exception name was recorded in the log. Inspect the event and its causes before attributing a defect.',
                        evidence=[f"{item['count']} log events contain this terminal exception name"],
                        confidence='medium', conclusion='observation',
                        verification=['Inspect the event stack, matching source build and nearby requests.']))
                result['findings'] = [f.model_dump() for f in stamp(findings)]
                db = server_log.connect(index)
                try:
                    result['sample_events'] = [server_log.event_dict(r, identifier) for r in db.execute(
                        "SELECT * FROM events ORDER BY CASE level WHEN 'FATAL' THEN 0 WHEN 'ERROR' THEN 1 WHEN 'WARN' THEN 2 ELSE 3 END,id LIMIT 20")]
                finally:
                    db.close()
                return result
            worker = asyncio.create_task(asyncio.to_thread(work))
            try:
                result = await asyncio.shield(worker)
            except asyncio.CancelledError:
                cancel.set()
                try:
                    await worker
                except server_log.Cancelled:
                    pass
                raise
            if cancel.is_set():
                raise server_log.Cancelled()
            JOBS.stage_callback(job_id)('Saving server log report')
            artifacts.save(result, 'server_log')
            saved = True
            JOBS.mark_done(job_id, result)
    except server_log.Cancelled:
        JOBS.mark_error(job_id, 'Server log analysis cancelled')
    except Exception as exc:
        JOBS.mark_error(job_id, f'Server log analysis failed: {exc}')
    finally:
        path.unlink(missing_ok=True)
        if not saved:
            index.unlink(missing_ok=True)
        JOBS.clear_cancel(job_id)


@router.get('/api/server-logs/{identifier}/events')
def events(identifier: str, after: int = Query(0, ge=0), limit: int = Query(25, ge=1, le=100),
           level: str | None = Query(None, pattern='^(TRACE|DEBUG|INFO|WARN|ERROR|FATAL|UNKNOWN)$'),
           query: str | None = Query(None, max_length=128), thread: str | None = Query(None, max_length=256),
           trace_id: str | None = Query(None, max_length=128), request_id: str | None = Query(None, max_length=128),
           since: str | None = None, until: str | None = None):
    _, path = _log_index(identifier)
    dates = []
    for value in (since, until):
        parsed = server_log.parse_time(value) if value else None
        if value and not parsed:
            raise HTTPException(422, 'Time filters require ISO timestamps with a timezone offset')
        dates.append(parsed)
    if all(dates) and dates[0] > dates[1]:
        raise HTTPException(422, 'The start time must precede the end time')
    return server_log.search_events(path, identifier, after=after, limit=limit, level=level, query=query,
                                   thread=thread, trace_id=trace_id, request_id=request_id,
                                   since=dates[0], until=dates[1])


@router.get('/api/server-logs/{identifier}/events/{event_id}')
def event(identifier: str, event_id: int, source_session: str | None = None):
    data, path = _log_index(identifier)
    source = _source(source_session)
    db = server_log.connect(path)
    try:
        row = db.execute('SELECT * FROM events WHERE id=?', (event_id,)).fetchone()
        if not row:
            raise HTTPException(404, 'Log event not found')
        build = (data.get('capture') or {}).get('build_id')
        matched = bool(source and source.provenance.get('manifest_valid') and build and build == source.provenance.get('build_id'))
        result = server_log.event_source(server_log.event_dict(row, identifier), source, matched)
        for frame in result['frames']:
            if frame.get('source'):
                frame['source']['context'] = source.context(frame['class_name'], frame['method'], frame['line'])
        return result
    finally:
        db.close()


class IncidentRequest(BaseModel):
    server_log_id: str
    heap_id: str | None = None
    thread_id: str | None = None
    gc_id: str | None = None
    source_session: str | None = None
    window_seconds: int = Field(300, ge=1, le=86400)


@router.post('/api/analyze/incident')
def incident(req: IncidentRequest):
    if not (req.heap_id or req.thread_id):
        raise HTTPException(422, 'Attach at least one heap or thread analysis alongside the server log')
    log, path = _log_index(req.server_log_id)
    source = _source(req.source_session)
    bundles = {kind: _saved(identifier, kind) if identifier else None for kind, identifier in (
        ('heap', req.heap_id), ('thread', req.thread_id), ('gc', req.gc_id))}
    if source and bundles['heap']:
        from .analyzers.heap_trace import enrich_root_paths
        heap = bundles['heap']
        index = artifacts.path_for(req.heap_id, '.sqlite')
        if heap.get('object_index_id') and index.is_file():
            build = (heap.get('capture') or {}).get('build_id')
            matched = bool(source.provenance.get('manifest_valid') and build and build == source.provenance.get('build_id'))
            for entry in heap.get('dominators', []):
                if entry.get('root_paths'):
                    enrich_root_paths(index, entry['root_paths'], source, matched)
    result = jsonable_encoder(analyze_incident(log, path, source=source, window_seconds=req.window_seconds, **bundles))
    return artifacts.save(result, 'incident')
