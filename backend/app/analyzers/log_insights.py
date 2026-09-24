"""What a server log adds to a dump: out-of-memory events, restarts, redeploys
and the error timeline before the capture.

A log cannot show what retains memory; the heap graph does that. It shows when
the JVM failed, the code path that was allocating at the time, and lifecycle
events (restarts, redeploys) that change how a dump must be read.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta

from ..schemas import Finding, Severity, SourceLocation
from . import server_log
from .source import is_user_code

BUCKET_MINUTES = 10
TIMELINE_BEFORE = timedelta(hours=2)
TIMELINE_AFTER = timedelta(minutes=20)
_LEVEL_RANK = "CASE e.level WHEN 'FATAL' THEN 0 WHEN 'ERROR' THEN 1 WHEN 'WARN' THEN 2 ELSE 3 END"

# What each OutOfMemoryError message means for reading the attached evidence.
_OOM_KINDS = [
    ('java heap space', 'The Java heap was full.',
     'Objects retained on the heap; the heap dump retention path shows what holds them.'),
    ('gc overhead limit', 'The JVM spent almost all its time in GC while recovering very little heap.',
     'The live set is close to the maximum heap; the heap dump retention path shows what holds it.'),
    ('metaspace', 'Class metadata space was exhausted.',
     'Too many loaded classes, commonly a classloader kept alive by a redeploy. The object histogram alone will not show it; check stale deployments.'),
    ('compressed class space', 'Compressed class space was exhausted.',
     'Too many loaded classes, commonly a classloader kept alive by a redeploy; check stale deployments.'),
    ('direct buffer memory', 'Off-heap NIO direct buffer memory was exhausted.',
     'Direct buffers live outside the Java heap; the heap dump shows only small DirectByteBuffer objects. Check buffer pooling and -XX:MaxDirectMemorySize.'),
    ('native thread', 'The OS refused to create another thread.',
     'Thread count or native memory limits; a thread dump is more relevant than the heap histogram.'),
    ('requested array size', 'A single array allocation exceeded the VM limit.',
     'One oversized allocation; the logged stack is the allocation site to fix.'),
]


def ensure_markers(db):
    """Return (legacy, warnings). Indexes built before marker extraction get a
    TEMP markers table recovered from event header lines and exception names."""
    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='markers'").fetchone():
        return False, []
    db.execute('CREATE TEMP TABLE markers(event_id INTEGER, kind TEXT, detail TEXT)')
    rows = db.execute("""SELECT id, message, exception, excerpt FROM events WHERE exception LIKE '%OutOfMemoryError'
        OR message LIKE '%OutOfMemoryError%' OR message LIKE '%eploy%' OR message LIKE '%WFLYSRV00%'
        OR message LIKE '%Server startup in%' OR message LIKE '%Started % in % seconds%' OR message LIKE '%Dumping heap to%'""")
    found = []
    for row in rows:
        text = row['message'] or ''
        if (row['exception'] or '').endswith('OutOfMemoryError') and 'OutOfMemoryError' not in text:
            text = next((line for line in (row['excerpt'] or '').splitlines() if 'OutOfMemoryError' in line), text)
        for kind, pattern in server_log.MARKERS:
            hit = pattern.search(text)
            if hit:
                detail = (hit[1] or '').strip() if hit.groups() else ''
                if kind in ('deploy', 'undeploy'):
                    detail = server_log.artifact_name(detail)
                found.append((row['id'], kind, detail[:200]))
                break
    db.executemany('INSERT INTO markers VALUES(?,?,?)', found)
    db.execute('CREATE INDEX temp.marker_kind ON markers(kind,event_id)')
    return True, ['This log was indexed before memory/lifecycle event extraction; those events were recovered '
                  'from header lines and exception names only. Re-upload the log for complete detection.']


def _when(row):
    return row['timestamp'] or row['raw_timestamp']


def _minutes(a, b):
    return (datetime.fromisoformat(b) - datetime.fromisoformat(a)).total_seconds() / 60


def _relation(ts, captures):
    """Plain phrases relating an aligned log timestamp to each dump capture."""
    out = []
    for kind, at in captures:
        delta = _minutes(ts, at)
        if abs(delta) < 1:
            out.append(f'within a minute of the {kind} capture')
        else:
            out.append(f"{abs(delta):,.0f} min {'before' if delta > 0 else 'after'} the {kind} capture")
    return out


def _oom_kind(detail):
    low = (detail or '').lower()
    return next(((meaning, cause) for key, meaning, cause in _OOM_KINDS if key in low),
                ('The JVM could not satisfy a memory request.', 'Compare the logged stack with the heap retention path.'))


def _user_frame(frames):
    return next((f for f in frames if is_user_code(f['class_name'])), None)


def _location(frame, source, build_verified, role):
    loc = SourceLocation(class_name=frame['class_name'], method=frame['method'], file=frame.get('file'),
                         line=frame.get('line'), is_user_code=True, role=role, build_verified=build_verified)
    if source:
        found = source.lookup(frame['class_name'], frame.get('line'))
        if found:
            loc.repo_path = source.relative_path(found[0])
            loc.snippet = found[1]
            loc.resolution = 'source_file'
    return loc


def oom_findings(db, captures, aligned, heap_classes, deploy_count, source, build_verified):
    findings, events = [], []
    groups = db.execute("""SELECT m.detail, count(*) n, min(e.id) first_id, max(e.id) last_id
        FROM markers m JOIN events e ON e.id=m.event_id WHERE m.kind='oom' GROUP BY m.detail ORDER BY n DESC LIMIT 6""").fetchall()
    for group in groups:
        detail = group['detail'] or 'unspecified'
        first = db.execute('SELECT * FROM events WHERE id=?', (group['first_id'],)).fetchone()
        last = db.execute('SELECT * FROM events WHERE id=?', (group['last_id'],)).fetchone()
        meaning, cause = _oom_kind(detail)
        # The most frequent first application frame across a bounded sample of these events.
        paths, examples = {}, {}
        for row in db.execute("""SELECT e.id, e.frames FROM markers m JOIN events e ON e.id=m.event_id
                                 WHERE m.kind='oom' AND m.detail IS ? ORDER BY e.id LIMIT 200""", (group['detail'],)):
            frame = _user_frame(json.loads(row['frames']))
            if frame:
                key = (frame['class_name'], frame['method'], frame.get('line'))
                paths[key] = paths.get(key, 0) + 1
                examples.setdefault(key, frame)
        evidence = [f"{group['n']:,} log events contain OutOfMemoryError: {detail}",
                    f"First at {_when(first) or 'unknown time'} (line {first['start_line']:,}, thread {first['thread'] or 'unknown'})"]
        if group['n'] > 1:
            evidence.append(f"Last at {_when(last) or 'unknown time'} (line {last['start_line']:,})")
        title = f'OutOfMemoryError: {detail} logged {group["n"]:,}×'
        if aligned and first['timestamp'] and captures:
            rel = _relation(first['timestamp'], captures)
            evidence.append('First occurrence ' + '; '.join(rel))
            title += f' (first {rel[0]})'
        locations, overlap = [], []
        if paths:
            (cls, method, line), hits = max(paths.items(), key=lambda item: item[1])
            evidence.append(f"Most frequent application frame at the failure: {cls}.{method}"
                            f"{f':{line}' if line else ''} ({hits} of {sum(paths.values())} sampled events with application frames)")
            locations.append(_location(examples[(cls, method, line)], source, build_verified, 'oom_stack_frame'))
        frames = json.loads(first['frames'])
        for cls in dict.fromkeys(f['class_name'] for f in frames):
            if cls in heap_classes:
                overlap.append(f'{cls} ({heap_classes[cls]})')
        if overlap:
            evidence.append('Classes on the failing stack that are also prominent in the heap: ' + ', '.join(overlap[:5]))
        if 'metaspace' in detail.lower() or 'class space' in detail.lower():
            evidence.append(f'The log records {deploy_count:,} deploy/redeploy events' if deploy_count else
                            'The log records no deploy/redeploy events')
        findings.append(Finding(severity=Severity.CRITICAL, category='server_log_memory', title=title,
            description=f'{meaning} The logged stack shows the code that was allocating when the JVM failed.',
            likely_cause=cause, evidence=evidence, source_locations=locations, conclusion='observation',
            confidence='high', impact='Requests failing with OutOfMemoryError; the JVM may be unstable until restarted.',
            limitations=['The failing allocation is often not the code that fills the heap: any request can be the one that runs out.',
                         'Compare this stack with the heap retention path before changing code.'],
            verification=['Open the first event below and compare its stack with the heap retention path.',
                          'Check whether the same code path appears across many OutOfMemoryError events.']))
        events.append({'kind': 'oom', 'detail': detail, 'count': group['n'], 'first_event': first['id'],
                       'first_at': _when(first), 'last_at': _when(last)})
    return findings, events


def lifecycle_findings(db, captures, aligned, heap):
    """Restarts between an OOM and the capture; redeploys versus stale classloaders."""
    findings = []
    starts = db.execute("""SELECT e.*, m.detail FROM markers m JOIN events e ON e.id=m.event_id
                           WHERE m.kind='server_start' ORDER BY e.id""").fetchall()
    heap_capture = next((at for kind, at in captures if kind == 'heap'), None)
    # The latest OOM before the capture: an earlier episode followed by a restart
    # and a fresh OOM still leaves the dump showing the failing state.
    last_oom = db.execute("""SELECT e.* FROM markers m JOIN events e ON e.id=m.event_id
                             WHERE m.kind='oom' AND e.timestamp <= ? ORDER BY e.timestamp DESC, e.id DESC LIMIT 1""",
                          (heap_capture,)).fetchone() if heap_capture and aligned else None
    if last_oom:
        restarts = [s for s in starts if s['timestamp'] and last_oom['timestamp'] < s['timestamp'] < heap_capture]
        if restarts:
            findings.append(Finding(severity=Severity.WARNING, category='server_log_lifecycle',
                title='Server restarted after the OutOfMemoryError and before the heap dump',
                description='The heap dump was taken from the restarted JVM, so it may not contain the state that caused the OutOfMemoryError.',
                evidence=[f"Last OutOfMemoryError before the capture at {last_oom['timestamp']} (line {last_oom['start_line']:,})",
                          *[f"Server start at {s['timestamp']} (line {s['start_line']:,})" for s in restarts[:3]],
                          f'Heap captured at {heap_capture}'],
                likely_cause='A restart clears the heap; a leak must build up again before a dump shows it.',
                remediation='Capture with -XX:+HeapDumpOnOutOfMemoryError, or take the dump before restarting.',
                conclusion='observation', confidence='high'))
    dumps = db.execute("""SELECT e.*, m.detail FROM markers m JOIN events e ON e.id=m.event_id
                          WHERE m.kind='heap_dump' ORDER BY e.id LIMIT 3""").fetchall()
    if dumps:
        near = [d for d in dumps if aligned and d['timestamp'] and heap_capture and abs(_minutes(d['timestamp'], heap_capture)) <= 30]
        findings.append(Finding(severity=Severity.INFO, category='server_log_lifecycle',
            title='The log records an automatic heap dump' + (' at the time of this capture' if near else ''),
            description='-XX:+HeapDumpOnOutOfMemoryError wrote a dump when the JVM ran out of memory. '
                        + ('This matches the attached heap capture time, so the dump reflects the failing state.' if near else
                           'Confirm the attached heap dump is this file.'),
            evidence=[f"Dumping heap to {d['detail']} at {_when(d) or 'unknown time'} (line {d['start_line']:,})" for d in dumps],
            conclusion='observation', confidence='high' if near else 'medium'))

    deploys = {}
    for row in db.execute("""SELECT m.kind, m.detail, count(*) n, max(coalesce(e.timestamp, e.raw_timestamp)) last
                             FROM markers m JOIN events e ON e.id=m.event_id
                             WHERE m.kind IN ('deploy','undeploy') GROUP BY m.kind, m.detail"""):
        deploys.setdefault(row['detail'], {})[row['kind']] = (row['n'], row['last'])
    webapps = [d for d in (heap or {}).get('deployments') or [] if d.get('is_webapp')]
    loaders = {}
    for dep in webapps:
        name = server_log.artifact_name(dep.get('artifact') or dep.get('name') or '')
        loaders.setdefault(name, []).append(dep)
    for name, deps in loaders.items():
        stale = [d for d in deps if d.get('stale')]
        seen = deploys.get(name, {})
        deploy_n = seen.get('deploy', (0, None))[0]
        if stale and deploy_n:
            findings.append(Finding(severity=Severity.CRITICAL, category='server_log_lifecycle',
                title=f'Redeploy leak corroborated by the log: {name} deployed {deploy_n}× and the heap still holds {len(deps)} classloaders',
                description='Each redeploy should release the previous classloader. The heap still holds more than one for this application, and the log shows the redeploys that created them.',
                evidence=[f'Log: {deploy_n} deploy events for {name}, last at {seen["deploy"][1] or "unknown time"}',
                          f'Log: {seen.get("undeploy", (0, None))[0]} undeploy events for {name}',
                          f'Heap: {len(deps)} classloaders for {name}; {sum(d.get("live_thread_count", 0) for d in stale)} live threads attributed to them'],
                likely_cause='A thread, static field, JDBC driver or cache registered by the old deployment keeps its classloader reachable.',
                remediation='Stop threads and deregister drivers/listeners on undeploy; restart instead of hot-redeploying until fixed.',
                conclusion='observation', confidence='high'))
        elif stale:
            findings.append(Finding(severity=Severity.INFO, category='server_log_lifecycle',
                title=f'No deploy events for {name} in the log',
                description='The heap holds more than one classloader for this application, but the log does not cover the redeploy that created them.',
                evidence=[f'Heap: {len(deps)} classloaders for {name}'], conclusion='observation', confidence='medium',
                limitations=['The redeploy may predate the log file, or its message format is not recognized.']))
        elif deploy_n >= 2 and len(deps) == 1:
            findings.append(Finding(severity=Severity.INFO, category='server_log_lifecycle',
                title=f'{name} was deployed {deploy_n}× ({deploy_n - 1} redeploys) and the heap holds a single classloader for it',
                description='The redeploys recorded in the log did not leave old classloaders behind in this heap.',
                evidence=[f'Log: {deploy_n} deploy events for {name}'], conclusion='observation', confidence='medium'))
    return findings, sum(n for kinds in deploys.values() for n, _ in [kinds.get('deploy', (0, None))])


def _floor(dt):
    return dt.replace(minute=dt.minute - dt.minute % BUCKET_MINUTES, second=0, microsecond=0)


def timeline(db, captures, aligned):
    """Events per 10-minute bucket leading up to the latest capture."""
    if aligned:
        column, basis = 'e.timestamp', 'UTC'
        anchor = max((datetime.fromisoformat(at) for _, at in captures), default=None)
        if anchor is None:
            end = db.execute('SELECT max(timestamp) FROM events').fetchone()[0]
            anchor = datetime.fromisoformat(end) if end else None
    else:
        # Unaligned timestamps: the log's own local clock, not comparable to capture times.
        column, basis = "(substr(e.raw_timestamp,1,10)||'T'||substr(e.raw_timestamp,12,8))", 'log local time (no offset; not aligned with captures)'
        end = db.execute(f'SELECT max({column}) FROM events e WHERE e.raw_timestamp IS NOT NULL').fetchone()[0]
        try:
            anchor = datetime.fromisoformat(end) if end else None
        except ValueError:
            anchor = None
    if anchor is None:
        return None
    start, stop = _floor(anchor - TIMELINE_BEFORE), anchor + TIMELINE_AFTER
    if aligned:
        lo, hi = start.isoformat(timespec='milliseconds'), stop.isoformat(timespec='milliseconds')
    else:
        lo, hi = start.replace(tzinfo=None).isoformat(timespec='seconds'), stop.replace(tzinfo=None).isoformat(timespec='seconds')
    key = f'substr({column},1,15)'
    buckets = {}
    cursor = start
    while cursor <= stop:
        buckets[cursor.strftime('%Y-%m-%dT%H:%M')[:15]] = {'start': cursor.isoformat(timespec='minutes'), 'total': 0,
            'errors': 0, 'warnings': 0, 'oom': 0, 'deploy': 0, 'undeploy': 0, 'server_start': 0, 'heap_dump': 0}
        cursor += timedelta(minutes=BUCKET_MINUTES)
    for row in db.execute(f"""SELECT {key} b, count(*) n, sum(e.level IN ('ERROR','FATAL')) err, sum(e.level='WARN') warn
                              FROM events e WHERE {column} BETWEEN ? AND ? GROUP BY b""", (lo, hi)):
        if row['b'] in buckets:
            buckets[row['b']].update(total=row['n'], errors=row['err'], warnings=row['warn'])
    for row in db.execute(f"""SELECT {key} b, m.kind, count(*) n FROM markers m JOIN events e ON e.id=m.event_id
                              WHERE {column} BETWEEN ? AND ? GROUP BY b, m.kind""", (lo, hi)):
        if row['b'] in buckets and row['kind'] in buckets[row['b']]:
            buckets[row['b']][row['kind']] = row['n']
    note = None
    if not any(b['total'] for b in buckets.values()):
        note = 'No log events in this range; the log may not cover the time of the capture.'
    marks = []
    if aligned:
        for kind, at in captures:
            b = _floor(datetime.fromisoformat(at)).strftime('%Y-%m-%dT%H:%M')[:15]
            if b in buckets:
                marks.append({'kind': kind, 'at': at, 'bucket': buckets[b]['start']})
    return {'basis': basis, 'bucket_minutes': BUCKET_MINUTES, 'buckets': list(buckets.values()), 'captures': marks, 'note': note}


def timeline_findings(line, aligned):
    """A sustained rise in errors just before the capture."""
    if not line or not aligned or not line['captures']:
        return []
    starts = [b['start'] for b in line['buckets']]
    cut = starts.index(max(c['bucket'] for c in line['captures'])) + 1
    recent, earlier = line['buckets'][max(0, cut - 3):cut], line['buckets'][:max(0, cut - 3)]
    if not recent or not earlier:
        return []
    now = sum(b['errors'] for b in recent) / len(recent)
    before = sum(b['errors'] for b in earlier) / len(earlier)
    if now < 5 or now < 3 * max(before, 1):
        return []
    return [Finding(severity=Severity.WARNING, category='server_log_timeline',
        title=f'Errors rose to {now:,.0f} per {BUCKET_MINUTES} min before the capture (from {before:,.1f})',
        description='Error volume increased sharply in the 30 minutes before the dump was captured.',
        evidence=[f"{b['start']}: {b['errors']:,} errors, {b['warnings']:,} warnings, {b['oom']:,} OutOfMemoryError"
                  for b in recent],
        conclusion='observation', confidence='medium',
        limitations=['A rise in errors shows when the failure became visible, not what caused it.'])]
