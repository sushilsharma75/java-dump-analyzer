"""Streaming JVM application logs into a disk-backed event index.

The entire input is scanned. Individual line/event excerpts and frame lists are
bounded; every omission is counted. No list grows with the input file size.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from datetime import datetime, timezone, timedelta

LINE_BYTES = 64 * 1024
EVENT_CHARS = 32 * 1024
MAX_FRAMES = 128
MAX_EVENT_LINES = 256
LEVEL = re.compile(r'\b(TRACE|DEBUG|INFO|WARN(?:ING)?|ERROR|FATAL|SEVERE)\b')
DATE = re.compile(r'\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?')
FRAME = re.compile(r'^\s*at\s+(?:[^\s(]*/)?(?P<class>[\w$]+(?:\.[\w$]+)*)\.(?P<method>[\w$<>]+)\((?P<file>[^():]+)(?::(?P<line>\d+))?\)')
EXCEPTION = re.compile(r'(?<![\w.])((?:[\w$]+\.)*[\w$]*(?:Exception|Error|Throwable))\b')
IDENTIFIERS = {
    'trace_id': re.compile(r'\b(?:trace[_-]?id|traceId)\s*[=:]\s*["\']?([\w.-]{1,128})', re.I),
    'request_id': re.compile(r'\b(?:request[_-]?id|requestId|correlation[_-]?id)\s*[=:]\s*["\']?([\w.-]{1,128})', re.I),
}


class Cancelled(Exception):
    pass


def connect(path):
    db = sqlite3.connect(str(path), timeout=60)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA cache_size=-8192')
    db.execute('PRAGMA temp_store=FILE')
    return db


def parse_time(value, offset=None):
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace(',', '.').replace('Z', '+00:00'))
        if dt.tzinfo is None:
            if not offset:
                return None
            sign = 1 if offset[0] == '+' else -1
            dt = dt.replace(tzinfo=timezone(sign * timedelta(hours=int(offset[1:3]), minutes=int(offset[4:6]))))
        return dt.astimezone(timezone.utc).isoformat(timespec='milliseconds')
    except (TypeError, ValueError):
        return None


def _header(text):
    """Recognize common Logback/Log4j/WildFly and JSON-lines headers."""
    if text.lstrip().startswith(('at ', 'Caused by:', 'Suppressed:', '... ')):
        return None
    item = None
    if text.lstrip().startswith('{'):
        try:
            value = json.loads(text)
            if isinstance(value, dict):
                item = value
        except (ValueError, RecursionError):
            pass
    if item is not None:
        def val(*keys):
            return next((str(item[k])[:4096] for k in keys if item.get(k) is not None), None)
        msg = next((str(item[k])[:LINE_BYTES] for k in ('message', 'msg', 'formattedMessage') if item.get(k) is not None), '')
        stack = val('stack_trace', 'stacktrace', 'exception') or ''
        # Keep multiline stack content bounded by the physical line limit.
        for key in ('stack_trace', 'stacktrace', 'exception'):
            if isinstance(item.get(key), str):
                stack = item[key][:LINE_BYTES]
                break
        return {'level': (val('level', 'log.level', 'severity') or 'UNKNOWN').upper(),
                'raw_timestamp': val('@timestamp', 'timestamp', 'time', 'date'),
                'thread': val('thread_name', 'thread', 'threadName'),
                'logger': val('logger_name', 'logger', 'loggerName'),
                'trace_id': val('trace_id', 'traceId', 'trace.id'),
                'request_id': val('request_id', 'requestId', 'correlationId'),
                'message': msg, 'body': msg + ('\n' + stack if stack else ''), 'format': 'json'}
    date = DATE.search(text[:160])
    level = LEVEL.search(text[:512])
    if not date and not level:
        return None
    thread = logger = None
    if level:
        after = text[level.end():]
        # Spring puts the thread before the logger; WildFly puts it after.
        brackets = re.findall(r'\[([^\]\r\n]{1,256})\]', text[:1024])
        if brackets:
            thread = next((v for v in brackets if not LEVEL.fullmatch(v) and not DATE.fullmatch(v)), None)
        paren = re.search(r'\(([^)\r\n]{1,256})\)', after[:512])
        if paren:
            thread = paren[1]
        log = re.search(r'(?<![\w.])([\w$]+(?:\.[\w$]+){1,})\s*(?:\s+-|\s*:|\])', after[:1024])
        if log:
            logger = log[1]
    return {'level': level[1].upper() if level else 'UNKNOWN',
            'raw_timestamp': date[0] if date else None, 'thread': thread, 'logger': logger,
            'trace_id': None, 'request_id': None, 'message': text.rstrip(), 'body': text,
            'format': 'text'}


def build_log_index(fp, path, *, offset=None, progress=None, cancelled=lambda: False):
    db = connect(path)
    counts = {'bytes': 0, 'lines': 0, 'events': 0, 'oversized_lines': 0,
              'truncated_events': 0, 'omitted_frames': 0, 'unrecognized_events': 0,
              'unaligned_timestamps': 0, 'replacement_characters': 0}
    digest = hashlib.sha256()
    current = None
    last_progress = 0
    try:
        db.executescript('''
            CREATE TABLE events(id INTEGER PRIMARY KEY, start_line INTEGER, end_line INTEGER,
                byte_start INTEGER, byte_end INTEGER, level TEXT, timestamp TEXT, raw_timestamp TEXT,
                thread TEXT, logger TEXT, trace_id TEXT, request_id TEXT, message TEXT,
                exception TEXT, frames TEXT, excerpt TEXT, truncated INTEGER, format TEXT);
            CREATE TABLE frames(event_id INTEGER, class_name TEXT, method TEXT, line INTEGER);
            CREATE INDEX event_level ON events(level,id);
            CREATE INDEX event_time ON events(timestamp,id);
            CREATE INDEX event_thread ON events(thread,id);
            CREATE INDEX event_trace ON events(trace_id,id);
            CREATE INDEX event_request ON events(request_id,id);
            CREATE INDEX event_logger ON events(logger,id);
            CREATE INDEX frame_class ON frames(class_name,event_id);
        ''')

        def flush():
            if current is None:
                return
            counts['events'] += 1
            eid = counts['events']
            current['id'] = eid
            current['exception'] = current['exceptions'][-1] if current['exceptions'] else None
            counts['truncated_events'] += int(current['truncated'])
            counts['unrecognized_events'] += int(current['level'] == 'UNKNOWN')
            counts['unaligned_timestamps'] += int(bool(current['raw_timestamp']) and not current['timestamp'])
            db.execute('INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', (
                eid, current['start_line'], current['end_line'], current['byte_start'], current['byte_end'],
                current['level'], current['timestamp'], current['raw_timestamp'], current['thread'],
                current['logger'], current['trace_id'], current['request_id'], current['message'][:4096],
                current['exception'], json.dumps(current['frames']), current['excerpt'],
                int(current['truncated']), current['format']))
            db.executemany('INSERT INTO frames VALUES(?,?,?,?)',
                           [(eid, f['class_name'], f['method'], f['line']) for f in current['frames']])
            if eid % 2000 == 0:
                db.commit()

        while True:
            if cancelled():
                raise Cancelled('Server log analysis cancelled')
            start = counts['bytes']
            raw = fp.readline(LINE_BYTES)
            if not raw:
                break
            digest.update(raw)
            counts['bytes'] += len(raw)
            oversized = not raw.endswith(b'\n') and len(raw) == LINE_BYTES
            if oversized:
                counts['oversized_lines'] += 1
                while not raw.endswith(b'\n'):
                    tail = fp.readline(LINE_BYTES)
                    if not tail:
                        break
                    digest.update(tail)
                    counts['bytes'] += len(tail)
                    if cancelled():
                        raise Cancelled('Server log analysis cancelled')
                    if counts['bytes'] - last_progress >= 1024 * 1024:
                        if progress: progress(counts['bytes'], counts['events'], counts['lines'])
                        last_progress = counts['bytes']
                    if tail.endswith(b'\n'):
                        break
            counts['lines'] += 1
            text = raw.decode('utf-8', errors='replace').lstrip('\ufeff')
            counts['replacement_characters'] += text.count('\ufffd')
            header = _header(text)
            # Stack continuation, including nested causes, stays with its event.
            if current is not None and (header or current['line_count'] >= MAX_EVENT_LINES):
                if not header:
                    current['truncated'] = True
                flush()
                current = None
            if current is None:
                current = header or {'level': 'UNKNOWN', 'raw_timestamp': None, 'thread': None,
                                     'logger': None, 'trace_id': None, 'request_id': None,
                                     'message': text.rstrip(), 'body': text, 'format': 'unrecognized'}
                current.update(start_line=counts['lines'], byte_start=start, excerpt='', frames=[],
                               exceptions=[], truncated=False, line_count=0)
                current['level'] = {'WARNING': 'WARN', 'SEVERE': 'ERROR'}.get(current['level'], current['level'])
                if current['level'] not in ('TRACE', 'DEBUG', 'INFO', 'WARN', 'ERROR', 'FATAL'):
                    current['level'] = 'UNKNOWN'
                current['timestamp'] = parse_time(current['raw_timestamp'], offset)
            current['line_count'] += 1
            current['end_line'], current['byte_end'] = counts['lines'], counts['bytes']
            body = header['body'] if header else text
            room = EVENT_CHARS - len(current['excerpt'])
            current['excerpt'] += body[:room]
            current['truncated'] |= oversized or len(body) > room
            for key, pattern in IDENTIFIERS.items():
                hit = pattern.search(body)
                if hit and not current[key]:
                    current[key] = hit[1]
            for line in body.splitlines():
                exc = EXCEPTION.search(line)
                if exc:
                    current['exceptions'] = (current['exceptions'] + [exc[1]])[-16:]
                fr = FRAME.match(line)
                if fr:
                    if len(current['frames']) < MAX_FRAMES:
                        current['frames'].append({'class_name': fr['class'], 'method': fr['method'],
                                                  'file': fr['file'], 'line': int(fr['line']) if fr['line'] else None})
                    else:
                        counts['omitted_frames'] += 1
                        current['truncated'] = True
            if counts['bytes'] - last_progress >= 1024 * 1024:
                if progress: progress(counts['bytes'], counts['events'], counts['lines'])
                last_progress = counts['bytes']
        flush()
        db.commit()
        if progress: progress(counts['bytes'], counts['events'], counts['lines'])
        levels = {r['level']: r['n'] for r in db.execute('SELECT level,count(*) n FROM events GROUP BY level')}
        exceptions = [dict(r) for r in db.execute('SELECT exception,count(*) count FROM events WHERE exception IS NOT NULL GROUP BY exception ORDER BY count DESC,exception LIMIT 30')]
        span = db.execute('SELECT min(timestamp),max(timestamp),count(timestamp) FROM events').fetchone()
        return {'summary': f"{counts['events']:,} log events · {levels.get('ERROR', 0) + levels.get('FATAL', 0):,} errors · {counts['lines']:,} lines",
                'file_size_bytes': counts['bytes'], 'sha256': digest.hexdigest(), 'counts': counts,
                'levels': levels, 'exceptions': exceptions,
                'time_range': {'start': span[0], 'end': span[1], 'aligned_events': span[2], 'assumed_offset': offset},
                'capture': {}, 'findings': [], 'parse_coverage': {'status': 'completed', 'full_scan': True,
                    'excerpt_limits': {'line_bytes': LINE_BYTES, 'event_characters': EVENT_CHARS, 'frames_per_event': MAX_FRAMES, 'lines_per_event': MAX_EVENT_LINES}},
                'stages': [{'stage': 'server log scan', 'status': 'completed'},
                           {'stage': 'event extraction', 'status': 'partial' if counts['unrecognized_events'] or counts['truncated_events'] or counts['omitted_frames'] else 'completed'}],
                'limitations': ['Log/source matches are contextual evidence, not allocation history or proof of a retaining call.',
                                'Plain UTF-8 text and JSON-lines are supported; unknown formats and truncated excerpts are counted.',
                                'Timestamps without an offset cannot be aligned unless a timezone offset is supplied.',
                                'Exception summaries use the last exception named in each retained event; causes and suppressed exceptions remain in the excerpt.']}
    finally:
        db.close()


def event_dict(row, identifier):
    event = dict(row)
    event['frames'] = json.loads(event['frames'])
    event['evidence_id'] = f"E-{identifier[:12]}L{event['id']}"
    return event


def event_source(event, source, build_verified=False):
    if not source:
        return event
    for frame in event['frames']:
        found = source.lookup(frame['class_name'], frame['line'])
        if found:
            frame['source'] = {'class_name': frame['class_name'], 'method': frame['method'], 'line': frame['line'],
                               'repo_path': source.relative_path(found[0]), 'snippet': found[1].model_dump() if found[1] else None,
                               'role': 'logged_frame', 'is_user_code': True, 'build_verified': build_verified}
    return event


def search_events(path, identifier, *, after=0, limit=50, level=None, query=None, thread=None,
                  trace_id=None, request_id=None, since=None, until=None):
    terms, values = ['id > ?'], [after]
    for column, value in [('level', level), ('thread', thread), ('trace_id', trace_id),
                          ('request_id', request_id)]:
        if value:
            terms.append(f'{column} = ?')
            values.append(value)
    for op, value in [('>=', since), ('<=', until)]:
        if value:
            terms.append(f'timestamp {op} ?')
            values.append(value)
    if query:
        terms.append("excerpt LIKE ? ESCAPE '\\'")
        values.append('%' + query.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_') + '%')
    db = connect(path)
    try:
        rows = db.execute('SELECT * FROM events WHERE ' + ' AND '.join(terms) + ' ORDER BY id LIMIT ?', values + [limit + 1]).fetchall()
        return {'events': [event_dict(r, identifier) for r in rows[:limit]],
                'next_cursor': rows[limit - 1]['id'] if len(rows) > limit else None}
    finally:
        db.close()
