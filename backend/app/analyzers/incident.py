"""Evidence joins across saved logs, dumps, and the attached source build."""
from datetime import datetime, timedelta

from . import log_insights, server_log
from .correlate import correlate
from .evidence import compatibility, stamp
from .heap_deployments import _JVM_THREAD_NAMES


def analyze_incident(log, log_path, heap=None, thread=None, gc=None, source=None, window_seconds=300):
    bundles = {k: v for k, v in [('heap', heap), ('thread', thread), ('gc', gc)] if v}
    warnings, conflicts = [], []
    capture = log.get('capture') or {}
    for kind, dump in bundles.items():
        other = dump.get('capture') or {}
        for key in ('process_id', 'process_start', 'build_id'):
            if capture.get(key) and other.get(key) and capture[key] != other[key]:
                conflicts.append(f'Server log and {kind} capture {key} differ.')
            elif not capture.get(key) or not other.get(key):
                warnings.append(f'Server log/{kind} {key} is unverified.')
    if heap and thread:
        ok, notes = compatibility(heap, thread)
        (warnings if ok else conflicts).extend(notes)
    items = list(bundles.items())
    for i, (left_kind, left) in enumerate(items):
        for right_kind, right in items[i + 1:]:
            for key in ('process_id', 'process_start', 'build_id'):
                a, b = (left.get('capture') or {}).get(key), (right.get('capture') or {}).get(key)
                if a and b and a != b:
                    conflicts.append(f'{left_kind}/{right_kind} capture {key} differ.')
    if conflicts:
        return {'summary': 'Combined analysis blocked by incompatible captures.', 'status': 'incompatible',
                'findings': [], 'matches': [], 'limitations': conflicts + warnings, 'inputs': _inputs(log, bundles)}

    from .source import is_user_code
    classes, thread_names, heap_evidence = set(), set(), {}
    if heap:
        for entry in (heap.get('top_classes_by_size', []) + heap.get('top_classes_by_count', []))[:100]:
            cls = entry.get('class_name')
            # JDK/framework histogram classes (String, byte[], HashMap$Node) appear
            # in unrelated log frames everywhere; only application classes discriminate.
            if cls and is_user_code(cls):
                classes.add(cls)
                heap_evidence.setdefault(cls, []).append({'kind': 'histogram', 'class_name': cls,
                    'instances': entry.get('instance_count'), 'shallow_bytes': entry.get('shallow_size_bytes')})
        # Classes the heap analysis itself singled out (retention holders, static
        # fields, source-linked suspects) discriminate far better than histogram rank.
        for finding in heap.get('findings', []):
            for loc in finding.get('source_locations') or []:
                cls = loc.get('class_name')
                if cls and is_user_code(cls):
                    classes.add(cls)
                    heap_evidence.setdefault(cls, []).append({'kind': 'heap_finding', 'class_name': cls,
                        'finding': finding.get('title'), 'evidence_id': finding.get('evidence_id')})
        for entry in heap.get('dominators', [])[:25]:
            if entry.get('class_name') and is_user_code(entry['class_name']):
                classes.add(entry['class_name'])
                heap_evidence.setdefault(entry['class_name'], []).append({'kind': 'dominator',
                    'object_id': entry['object_id'], 'retained_bytes': entry.get('retained_bytes')})
            for path in entry.get('root_paths', {}).get('paths', []):
                for edge in path['edges']:
                    cls = (edge.get('owner') or {}).get('name')
                    if not cls and '.' in edge['field'] and not edge['field'].startswith('<'):
                        cls = edge['field'].rsplit('.', 1)[0]
                    if cls and is_user_code(cls):
                        classes.add(cls)
                        heap_evidence.setdefault(cls, []).append({'kind': 'recorded_retaining_edge',
                            'src': edge['src'], 'dst': edge['dst'], 'field': edge['field'], 'strength': edge['strength']})
    # A heap dump records live thread names too, even without a thread dump.
    # JVM-internal and unattributed threads (main, Finalizer, GC) name nothing specific.
    heap_threads = {t['name']: t for t in ((heap or {}).get('thread_ownership') or {}).get('threads', [])
                    if t.get('name') and t.get('live') and t['name'] != 'main'
                    and (t.get('deployment_id') or t.get('is_user_code'))
                    and not t['name'].startswith(_JVM_THREAD_NAMES)}
    frame_threads = {}
    for t in (thread or {}).get('threads', []):
        if t.get('name'):
            thread_names.add(t['name'])
        for frame in t.get('stack', []):
            cls = frame.get('class_name')
            # java.lang.Thread.run and framework frames are on nearly every logged stack.
            if cls and is_user_code(cls):
                classes.add(cls)
                frame_threads.setdefault((cls, frame.get('method')), set()).add(t.get('name', '?'))
    # Source references bridge value classes in the heap to application owner methods.
    source_candidates = {}
    if source and heap:
        for entry in heap.get('top_classes_by_size', [])[:20]:
            for ref in source.find_references(entry.get('class_name', ''), max_results=8):
                source_candidates.setdefault(ref['repo_path'], []).append({
                    'heap_class': entry['class_name'], 'method': ref.get('method'), 'line': ref['line'],
                    'role': 'source reference candidate; not an allocation or retention proof'})
        for cls, path in source._fqcn_to_path.items():
            if source.relative_path(path) in source_candidates:
                classes.add(cls)
    selected_classes = sorted(classes, key=lambda c: (not is_user_code(c), c))[:500]
    selected_threads = sorted(thread_names | set(heap_threads), key=lambda t: (t not in thread_names, t))[:400]
    windows = []
    log_events = (log.get('counts') or {}).get('events') or 0
    aligned_events = (log.get('time_range') or {}).get('aligned_events') or 0
    # Timestamps without an offset are stored unaligned (NULL); a time filter
    # would silently discard them, so it needs most of the log to be aligned.
    log_aligned = bool(log_events) and aligned_events * 2 >= log_events
    if not log_aligned:
        warnings.append(f'Only {aligned_events:,} of {log_events:,} log events have timezone-aligned timestamps; '
                        'the capture-time window was not applied. Re-upload the log with its timezone offset to enable it.')
    for kind, dump in bundles.items():
        at = server_log.parse_time((dump.get('capture') or {}).get('captured_at'))
        if at:
            dt = datetime.fromisoformat(at)
            windows.append((kind, (dt - timedelta(seconds=window_seconds)).isoformat(timespec='milliseconds'),
                            (dt + timedelta(seconds=window_seconds)).isoformat(timespec='milliseconds')))
        else:
            warnings.append(f'{kind} capture time is absent or has no timezone; temporal alignment is unverified.')
    db = server_log.connect(log_path)
    try:
        _, marker_notes = log_insights.ensure_markers(db)
        warnings.extend(marker_notes)
        db.execute('CREATE TEMP TABLE wanted_classes(name TEXT PRIMARY KEY)')
        db.execute('CREATE TEMP TABLE wanted_threads(name TEXT PRIMARY KEY)')
        db.executemany('INSERT INTO wanted_classes VALUES(?)', [(c,) for c in selected_classes])
        db.executemany('INSERT INTO wanted_threads VALUES(?)', [(t,) for t in selected_threads])
        # An indexed UNION avoids a Cartesian match over all log events.
        ids = '''SELECT f.event_id id FROM frames f JOIN wanted_classes w ON w.name=f.class_name
                 UNION SELECT e.id FROM events e JOIN wanted_classes w ON w.name=e.logger
                 UNION SELECT e.id FROM events e JOIN wanted_threads w ON w.name=e.thread
                 UNION SELECT event_id FROM markers WHERE kind='oom' '''
        where, args = '', []
        # Only claim aligned evidence when every attached dump has an aligned capture.
        if log_aligned and windows and len(windows) == len(bundles):
            where = ' AND (' + ' OR '.join('e.timestamp BETWEEN ? AND ?' for _ in windows) + ')'
            args = [value for _, lo, hi in windows for value in (lo, hi)]
        base = ' FROM events e JOIN (' + ids + ') hits ON hits.id=e.id WHERE 1=1'
        total = db.execute('SELECT count(*)' + base + where, args).fetchone()[0]
        window_fallback = False
        if where and not total:
            # Leaks build up long before a capture; nothing in the window is not
            # evidence that nothing matched. Show whole-log matches, labelled low confidence.
            window_fallback = True
            warnings.append(f'No matching events within ±{window_seconds:,} s of the capture; showing matches from the whole log.')
            where, args = '', []
            total = db.execute('SELECT count(*)' + base, args).fetchone()[0]
        base += where
        rows = db.execute('SELECT e.*' + base + " ORDER BY CASE e.level WHEN 'FATAL' THEN 0 WHEN 'ERROR' THEN 1 WHEN 'WARN' THEN 2 ELSE 3 END,e.id LIMIT 500", args).fetchall()
        oom_ids = {r[0]: r[1] for r in db.execute("SELECT event_id, detail FROM markers WHERE kind='oom' AND event_id IN (%s)"
                                                    % ','.join(str(r['id']) for r in rows))} if rows else {}
        matches = []
        build = capture.get('build_id')
        build_verified = bool(source and source.provenance.get('manifest_valid') and build and build == source.provenance.get('build_id'))
        for row in rows:
            event = server_log.event_source(server_log.event_dict(row, log['analysis_id']), source, build_verified)
            links, seen = [], set()
            def add(link):
                key = str(link)
                if key not in seen:
                    seen.add(key)
                    links.append(link)
            if event['id'] in oom_ids:
                add({'kind': 'memory_event', 'detail': f"OutOfMemoryError: {oom_ids[event['id']] or 'unspecified'}"})
            for frame in event['frames']:
                cls = frame['class_name']
                for name in sorted(frame_threads.get((cls, frame['method']), set()))[:10]:
                    add({'kind': 'same_class_and_method', 'thread': name, 'class_name': cls, 'method': frame['method']})
                for evidence in heap_evidence.get(cls, [])[:10]:
                    add({'kind': 'heap_class_overlap', 'class_name': cls, 'heap_evidence': evidence})
                loc = frame.get('source')
                if loc:
                    for candidate in source_candidates.get(loc['repo_path'], [])[:8]:
                        if candidate['method'] == frame['method']:
                            add({'kind': 'source_reference_candidate', **candidate})
            if event['thread'] in thread_names:
                add({'kind': 'same_thread_name', 'thread': event['thread'], 'limitation': 'Thread names can be reused; this is not thread identity proof.'})
            if event['thread'] in heap_threads:
                t = heap_threads[event['thread']]
                add({'kind': 'heap_thread_name', 'thread': event['thread'], 'thread_class': t.get('class_name'),
                     'deployment_id': t.get('deployment_id'), 'limitation': 'Thread names can be reused; this is not thread identity proof.'})
            if event['logger'] in classes:
                add({'kind': 'logger_class_overlap', 'class_name': event['logger']})
                for evidence in heap_evidence.get(event['logger'], [])[:10]:
                    add({'kind': 'heap_class_overlap', 'class_name': event['logger'], 'heap_evidence': evidence})
            aligned = [kind for kind, lo, hi in windows if event['timestamp'] and lo <= event['timestamp'] <= hi]
            score = sum(_weight(link) for link in links) + (2 if aligned else 0)
            matches.append({'event': event, 'links': links[:40], 'links_omitted': max(0, len(links) - 40),
                            'aligned_with': aligned, 'confidence': 'medium' if aligned else 'low',
                            'score': score, 'explanation': _explain(links)})
        # Strongest shared evidence first; severity, then file order break ties.
        rank = {'FATAL': 0, 'ERROR': 1, 'WARN': 2}
        matches.sort(key=lambda m: (-m['score'], rank.get(m['event']['level'], 3), m['event']['id']))
        matches = matches[:100]
        captures = _captures(bundles)
        heap_classes = {cls: max((e['kind'] for e in ev), key=lambda k: _HEAP_WEIGHTS.get(k, 1)).replace('_', ' ')
                        for cls, ev in heap_evidence.items()}
        life, deploy_count = log_insights.lifecycle_findings(db, captures, log_aligned, heap)
        ooms, memory_events = log_insights.oom_findings(db, captures, log_aligned, heap_classes, deploy_count, source, build_verified)
        line = log_insights.timeline(db, captures, log_aligned)
        log_findings = [f.model_dump() for f in stamp(ooms + life + log_insights.timeline_findings(line, log_aligned))]
        correlation = correlate(heap, thread, source, gc) if heap and thread else None
        return {'summary': _summary(memory_events, log_findings, total, len(matches)),
                'status': 'completed', 'inputs': _inputs(log, bundles), 'matches': matches,
                'findings': log_findings + (correlation or {}).get('findings', []), 'correlation': correlation,
                'log_findings': log_findings, 'memory_events': memory_events, 'timeline': line,
                'source_provenance': dict(source.provenance) if source else None,
                'coverage': {'matching_events': total, 'included_events': len(matches), 'omitted_events': total - len(matches),
                             'candidate_classes': len(classes), 'searched_classes': len(selected_classes),
                             'candidate_threads': len(thread_names), 'heap_threads': len(heap_threads),
                             'searched_threads': len(selected_threads),
                             'window_seconds': window_seconds, 'time_filter_applied': bool(where),
                             'time_filter_fallback': window_fallback, 'log_aligned_events': aligned_events,
                             'selection': 'strongest shared evidence first (memory events, heap finding classes, frames matching thread stacks), then severity; top 100 of up to 500 severity-ordered candidates'},
                'limitations': list(dict.fromkeys(warnings)) + [
                    'Matches identify shared context, not causation or the historical allocation stack.',
                    'Only indexed frames and excerpts are searched; log extraction limits still apply.',
                    'Logger names must match full class names. Abbreviated logger names remain unresolved.',
                    'Request and trace IDs connect log events; dumps generally do not contain those IDs.'],
                'server_log': log,
                'heap': _heap_summary(heap), 'thread': _thread_summary(thread), 'gc': gc}
    finally:
        db.close()


_WEIGHTS = {'memory_event': 5, 'same_class_and_method': 3, 'heap_thread_name': 2, 'same_thread_name': 2,
            'source_reference_candidate': 2, 'logger_class_overlap': 1}
_HEAP_WEIGHTS = {'heap_finding': 4, 'dominator': 3, 'recorded_retaining_edge': 3, 'histogram': 1}


def _weight(link):
    if link['kind'] == 'heap_class_overlap':
        return _HEAP_WEIGHTS.get(link['heap_evidence']['kind'], 1)
    return _WEIGHTS.get(link['kind'], 1)


def _explain(links):
    """One readable sentence per kind of shared evidence."""
    out = []
    for link in links:
        kind = link['kind']
        if kind == 'memory_event':
            text = f"This event is an {link['detail']}."
        elif kind == 'heap_class_overlap':
            ev = link['heap_evidence']
            text = {'heap_finding': f"{link['class_name']} is named by the heap finding \"{ev.get('finding')}\".",
                    'dominator': f"{link['class_name']} is a top retained-size object in the heap.",
                    'recorded_retaining_edge': f"{link['class_name']} is on a recorded GC-root retention path.",
                    }.get(ev['kind'], f"{link['class_name']} is among the largest heap classes.")
        elif kind == 'same_class_and_method':
            text = f"Thread dump thread {link['thread']} was also in {link['class_name']}.{link['method']}."
        elif kind == 'heap_thread_name':
            text = f"Thread {link['thread']} is alive in the heap dump."
        elif kind == 'same_thread_name':
            text = f"Thread {link['thread']} also appears in the thread dump."
        elif kind == 'source_reference_candidate':
            text = f"{link['method']} references heap class {link['heap_class']} in source (line {link['line']})."
        else:
            text = f"Logger {link.get('class_name')} also appears in the dumps."
        if text not in out:
            out.append(text)
    return out[:8]


def _captures(bundles):
    out = []
    for kind, dump in bundles.items():
        at = server_log.parse_time((dump.get('capture') or {}).get('captured_at'))
        if at:
            out.append((kind, at))
    return out


def _summary(memory_events, findings, total, shown):
    parts = []
    for event in memory_events[:2]:
        parts.append(f"{event['count']:,} OutOfMemoryError ({event['detail']}) in the log, first at {event['first_at'] or 'unknown time'}")
    other = [f for f in findings if f['category'] != 'server_log_memory' and f['severity'] != 'info']
    if other:
        parts.append(other[0]['title'])
    parts.append(f'{total:,} log events share classes, threads or memory events with the dumps; showing the strongest {shown}')
    return ' · '.join(parts) + '.'


def _inputs(log, bundles):
    return {'server_log': log['analysis_id'], **{k: v.get('analysis_id') for k, v in bundles.items()}}


def _heap_summary(heap):
    if not heap:
        return None
    return {k: heap.get(k) for k in ('analysis_id', 'summary', 'capture', 'findings', 'dominators', 'stages', 'top_classes_by_size')}


def _thread_summary(thread):
    if not thread:
        return None
    return {**{k: thread.get(k) for k in ('analysis_id', 'summary', 'capture', 'findings', 'stages')},
            'threads': [{**t, 'raw': None} for t in thread.get('threads', [])[:80]],
            'threads_omitted': max(0, len(thread.get('threads', [])) - 80)}
