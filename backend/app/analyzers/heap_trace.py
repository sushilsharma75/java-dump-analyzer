"""Join recorded retention paths to source context without inventing call edges."""

import json


ROOT_KINDS = {
    '0x1': 'JNI global', '0x2': 'JNI local', '0x3': 'Java local',
    '0x4': 'Native stack', '0x5': 'Sticky class', '0x6': 'Thread block',
    '0x7': 'Monitor', '0x8': 'Thread object', '0xff': 'Unknown root',
}


def enrich_root_paths(path, data, source=None, build_verified=False):
    from .heap_index import connect

    db = connect(path)
    objects, locations = {}, {}

    def object_info(oid):
        if oid not in objects:
            row = db.execute(
                'SELECT o.oid,o.kind,c.name FROM objects o LEFT JOIN classes c '
                'ON c.cid=o.class_id WHERE o.oid=?', (oid,),
            ).fetchone()
            objects[oid] = dict(row) if row else {'oid': oid, 'kind': 'unavailable'}
        return objects[oid]

    def location(cls, field=None, method=None, line=None, static=False):
        key = (cls, field, method, line, static)
        if key in locations:
            return locations[key]
        loc = None
        if source and cls:
            if field:
                loc = (source.find_static_field if static else source.find_field)(cls, field)
            elif line and line > 0:
                found = source.lookup(cls, line)
                if found and found[1] and found[1].lines:
                    loc = {'repo_path': source.relative_path(found[0]), 'line': line, 'snippet': found[1]}
            if loc:
                loc = {**loc, 'class_name': cls, 'method': method or '',
                       'role': 'retaining_field' if field else 'executing_frame',
                       'resolution': 'declared_field' if field else 'recorded_frame',
                       'is_user_code': True, 'build_verified': build_verified}
                if hasattr(loc.get('snippet'), 'model_dump'):
                    loc['snippet'] = loc['snippet'].model_dump()
                loc['context'] = source.context(cls, method, loc['line'])
                loc['context']['build_verified'] = build_verified
        locations[key] = loc
        return loc

    try:
        for trace in data.get('paths', []):
            for edge in trace['edges']:
                edge.pop('source', None)
                edge['owner'] = object_info(edge['src'])
                edge['target'] = object_info(edge['dst'])
                field = edge['field']
                cls = name = None
                if field.startswith('static:'):
                    cls, name = edge['owner'].get('name'), field[7:]
                elif '.' in field and not field.startswith('<'):
                    cls, name = field.rsplit('.', 1)
                loc = location(cls, field=name, static=field.startswith('static:'))
                if loc:
                    edge['source'] = loc
                edge['source_status'] = ('resolved' if loc else 'source_not_attached' if not source
                                         else 'field_unresolved' if name else 'no_source_field')
            for root in trace['root']:
                root['kind_name'] = ROOT_KINDS.get(root['kind'], root['kind'])
                root['object'] = object_info(root['oid'])
                root.pop('frames', None)
                root['stack_status'] = 'not recorded'
                if root.get('thread') is None:
                    continue
                # Thread-object root's frame column is the stack TRACE serial.
                # Java/JNI local root's frame column is an index into that trace.
                thread = db.execute("SELECT * FROM roots WHERE kind='0x8' AND thread=?",
                                    (root['thread'],)).fetchone()
                stack = db.execute('SELECT frames FROM traces WHERE thread=? AND serial=?',
                                   (root['thread'], thread['frame'])).fetchone() if thread else None
                if not stack:
                    continue
                frames = []
                for index, fid in enumerate(json.loads(stack['frames'])):
                    row = db.execute(
                        'SELECT f.line,m.value method_name,s.value file_name,c.name class_name '
                        'FROM frames f LEFT JOIN strings m ON m.id=f.method '
                        'LEFT JOIN strings s ON s.id=f.file LEFT JOIN class_serial cs ON cs.serial=f.serial '
                        'LEFT JOIN classes c ON c.cid=cs.cid WHERE f.id=?', (fid,),
                    ).fetchone()
                    if row:
                        frame = dict(row)
                        frame['index'] = index
                        frame['holds_root'] = root['kind'] in ('0x2', '0x3') and root['frame'] == index
                        frame['source'] = location(frame['class_name'], method=frame['method_name'], line=frame['line'])
                        frames.append(frame)
                root['frames'] = frames
                root['stack_status'] = 'available'
        data['source_attached'] = source is not None
        return data
    finally:
        db.close()
