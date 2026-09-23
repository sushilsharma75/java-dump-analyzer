"""Evidence joins across saved logs, dumps, and the attached source build."""
from datetime import datetime, timedelta

from . import server_log
from .correlate import correlate
from .evidence import compatibility


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

    classes, thread_names, heap_evidence = set(), set(), {}
    if heap:
        for entry in (heap.get('top_classes_by_size', []) + heap.get('top_classes_by_count', []))[:100]:
            cls = entry.get('class_name')
            if cls:
                classes.add(cls)
                heap_evidence.setdefault(cls, []).append({'kind': 'histogram', 'class_name': cls,
                    'instances': entry.get('instance_count'), 'shallow_bytes': entry.get('shallow_size_bytes')})
        for entry in heap.get('dominators', [])[:25]:
            if entry.get('class_name'):
                classes.add(entry['class_name'])
                heap_evidence.setdefault(entry['class_name'], []).append({'kind': 'dominator',
                    'object_id': entry['object_id'], 'retained_bytes': entry.get('retained_bytes')})
            for path in entry.get('root_paths', {}).get('paths', []):
                for edge in path['edges']:
                    cls = (edge.get('owner') or {}).get('name')
                    if not cls and '.' in edge['field'] and not edge['field'].startswith('<'):
                        cls = edge['field'].rsplit('.', 1)[0]
                    if cls:
                        classes.add(cls)
                        heap_evidence.setdefault(cls, []).append({'kind': 'recorded_retaining_edge',
                            'src': edge['src'], 'dst': edge['dst'], 'field': edge['field'], 'strength': edge['strength']})
    frame_threads = {}
    for t in (thread or {}).get('threads', []):
        if t.get('name'):
            thread_names.add(t['name'])
        for frame in t.get('stack', []):
            cls = frame.get('class_name')
            if cls:
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
    from .source import is_user_code
    selected_classes = sorted(classes, key=lambda c: (not is_user_code(c), c))[:500]
    selected_threads = sorted(thread_names)[:200]
    windows = []
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
        db.execute('CREATE TEMP TABLE wanted_classes(name TEXT PRIMARY KEY)')
        db.execute('CREATE TEMP TABLE wanted_threads(name TEXT PRIMARY KEY)')
        db.executemany('INSERT INTO wanted_classes VALUES(?)', [(c,) for c in selected_classes])
        db.executemany('INSERT INTO wanted_threads VALUES(?)', [(t,) for t in selected_threads])
        # An indexed UNION avoids a Cartesian match over all log events.
        ids = '''SELECT f.event_id id FROM frames f JOIN wanted_classes w ON w.name=f.class_name
                 UNION SELECT e.id FROM events e JOIN wanted_classes w ON w.name=e.logger
                 UNION SELECT e.id FROM events e JOIN wanted_threads w ON w.name=e.thread'''
        where, args = '', []
        # Only claim aligned evidence when every attached dump has an aligned capture.
        if windows and len(windows) == len(bundles):
            where = ' AND (' + ' OR '.join('e.timestamp BETWEEN ? AND ?' for _ in windows) + ')'
            args = [value for _, lo, hi in windows for value in (lo, hi)]
        base = ' FROM events e JOIN (' + ids + ') hits ON hits.id=e.id WHERE 1=1' + where
        total = db.execute('SELECT count(*)' + base, args).fetchone()[0]
        rows = db.execute('SELECT e.*' + base + " ORDER BY CASE e.level WHEN 'FATAL' THEN 0 WHEN 'ERROR' THEN 1 WHEN 'WARN' THEN 2 ELSE 3 END,e.id LIMIT 100", args).fetchall()
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
            if event['logger'] in classes:
                add({'kind': 'logger_class_overlap', 'class_name': event['logger']})
                for evidence in heap_evidence.get(event['logger'], [])[:10]:
                    add({'kind': 'heap_class_overlap', 'class_name': event['logger'], 'heap_evidence': evidence})
            aligned = [kind for kind, lo, hi in windows if event['timestamp'] and lo <= event['timestamp'] <= hi]
            matches.append({'event': event, 'links': links[:40], 'links_omitted': max(0, len(links) - 40),
                            'aligned_with': aligned, 'confidence': 'medium' if aligned else 'low'})
        correlation = correlate(heap, thread, source, gc) if heap and thread else None
        return {'summary': f'{total:,} matching log events; showing {len(matches)} with dump and source evidence.',
                'status': 'completed', 'inputs': _inputs(log, bundles), 'matches': matches,
                'findings': (correlation or {}).get('findings', []), 'correlation': correlation,
                'source_provenance': dict(source.provenance) if source else None,
                'coverage': {'matching_events': total, 'included_events': len(matches), 'omitted_events': total - len(matches),
                             'candidate_classes': len(classes), 'searched_classes': len(selected_classes),
                             'candidate_threads': len(thread_names), 'searched_threads': len(selected_threads),
                             'window_seconds': window_seconds, 'time_filter_applied': bool(where),
                             'selection': 'error/warning priority, then file order; exact class, method and thread-name matches'},
                'limitations': list(dict.fromkeys(warnings)) + [
                    'Matches identify shared context, not causation or the historical allocation stack.',
                    'Only indexed frames and excerpts are searched; log extraction limits still apply.',
                    'Logger names must match full class names. Abbreviated logger names remain unresolved.',
                    'Request and trace IDs connect log events; dumps generally do not contain those IDs.'],
                'server_log': log,
                'heap': _heap_summary(heap), 'thread': _thread_summary(thread), 'gc': gc}
    finally:
        db.close()


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
