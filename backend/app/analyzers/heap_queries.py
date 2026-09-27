"""Read-only, paginated investigations over a completed native heap index.

Retained sets use dominator subtrees, with UNION preventing double counting when
the selection contains both a parent and its child. Queries have a time budget.
"""
from contextlib import contextmanager
import sqlite3
import time

from .heap_index import connect, root_paths


class Unavailable(ValueError):
    pass


@contextmanager
def query_db(path, dominators=False):
    if not path.is_file():
        raise Unavailable("Object index is unavailable")
    db = connect(path)
    deadline = time.monotonic() + 20
    db.set_progress_handler(lambda: int(time.monotonic() > deadline), 10000)
    try:
        db.execute("PRAGMA query_only=ON")
        if dominators and not db.execute("SELECT 1 FROM meta WHERE key='dominators_complete'").fetchone():
            # Old indexes have no completion marker. A finished virtual root is
            # not sufficient to establish that an interrupted traversal finished.
            raise Unavailable("Retained analysis unavailable; reanalyze this dump to build a completed dominator index")
        yield db
    except sqlite3.OperationalError as exc:
        if "interrupt" in str(exc):
            raise Unavailable("Query exceeded its 20-second budget; narrow the selection") from exc
        raise
    finally:
        db.close()


NAME = "COALESCE(c.name,CASE WHEN o.kind LIKE 'primitive:%' THEN o.kind ELSE o.class_id END)"
NAMES = {"primitive:4": "boolean[]", "primitive:5": "char[]", "primitive:6": "float[]",
         "primitive:7": "double[]", "primitive:8": "byte[]", "primitive:9": "short[]",
         "primitive:10": "int[]", "primitive:11": "long[]"}


def rows(cursor):
    result = [dict(r) for r in cursor]
    for row in result:
        for k in ("class_name", "name"):
            if k in row:
                row[k] = NAMES.get(row[k], row[k])
    return result


def histogram(analysis, query="", sort="shallow_size_bytes", descending=True, group="class", offset=0, limit=50):
    """Full saved histogram also works when graph indexing was skipped."""
    available = "histogram" in analysis and bool(analysis.get("histogram_complete"))
    source = analysis.get("histogram")
    if source is None or not source and not available:
        source = list({r["class_name"]: r for r in analysis.get("top_classes_by_size", []) + analysis.get("top_classes_by_count", [])}.values())
    grouped = {}
    for row in source:
        if query.casefold() not in row["class_name"].casefold():
            continue
        name = row["class_name"] if group == "class" else row["class_name"].rpartition(".")[0] or "(default package)"
        item = grouped.setdefault(name, {"class_name": name, "instance_count": 0, "shallow_size_bytes": 0})
        for key in ("instance_count", "shallow_size_bytes"):
            item[key] += row[key]
    entries = sorted(grouped.values(), key=lambda r: (r[sort], r["class_name"]), reverse=descending)
    return {"rows": entries[offset:offset + limit], "total": len(entries), "offset": offset,
            "complete": available, "scope": "all parsed objects", "group": group}


def dominators(path, parent="0x0", offset=0, limit=50, group="object"):
    with query_db(path, True) as db:
        owner = db.execute("SELECT * FROM dom WHERE oid=?", (parent,)).fetchone()
        if not owner:
            raise Unavailable("Object is not in the reachable dominator tree")
        base = " FROM dom d JOIN objects o ON o.oid=d.oid LEFT JOIN classes c ON c.cid=o.class_id WHERE d.parent=? AND d.oid!=?"
        if group == "object":
            fields = f"o.oid,{NAME} class_name,o.shallow shallow_bytes,d.retained retained_bytes,(SELECT count(*) FROM dom child WHERE child.parent=d.oid AND child.oid!=d.oid) children"
            count = db.execute("SELECT count(*)" + base, (parent, parent)).fetchone()[0]
            result = rows(db.execute("SELECT " + fields + base + " ORDER BY d.retained DESC,d.oid LIMIT ? OFFSET ?", (parent, parent, limit, offset)))
        else:
            key = "COALESCE(c.loader,'0x0')" if group == "loader" else NAME
            sql = f"SELECT {key} class_name,count(*) instance_count,sum(o.shallow) shallow_bytes,sum(d.retained) retained_bytes" + base + f" GROUP BY {key}"
            count = db.execute("SELECT count(*) FROM (" + sql + ")", (parent, parent)).fetchone()[0]
            result = rows(db.execute(sql + " ORDER BY retained_bytes DESC,class_name LIMIT ? OFFSET ?", (parent, parent, limit, offset)))
        return {"rows": result, "total": count, "parent": parent, "parent_of_parent": owner["parent"],
                "retained_bytes": owner["retained"], "offset": offset, "group": group}


def retained_set(path, selection, offset=0, limit=50, view="histogram"):
    if not selection or len(selection) > 200 or "0x0" in selection:
        raise ValueError("Select between 1 and 200 real objects")
    marks = ",".join("?" for _ in selection)
    cte = f"WITH RECURSIVE selected(oid) AS (SELECT oid FROM dom WHERE oid IN ({marks}) UNION SELECT d.oid FROM dom d JOIN selected s ON d.parent=s.oid WHERE d.oid!=d.parent) "
    if len(set(selection)) > 1:
        # Remove the selected objects, then compute what becomes unreachable.
        # This includes shared descendants that no individual object dominates.
        cte = f"WITH RECURSIVE remaining(oid) AS (SELECT '0x0' UNION SELECT e.dst FROM remaining r JOIN edges e ON e.src=r.oid JOIN objects o ON o.oid=e.dst WHERE e.strength='strong' AND e.dst NOT IN ({marks})), selected(oid) AS (SELECT oid FROM dom WHERE oid!='0x0' EXCEPT SELECT oid FROM remaining) "
    base = " FROM selected s JOIN objects o ON o.oid=s.oid LEFT JOIN classes c ON c.cid=o.class_id"
    with query_db(path, True) as db:
        found = db.execute(f"SELECT count(*) FROM dom WHERE oid IN ({marks})", selection).fetchone()[0]
        if found != len(set(selection)):
            raise Unavailable("Selection contains an unknown or unreachable object")
        totals = db.execute(cte + "SELECT count(*),COALESCE(sum(o.shallow),0)" + base, selection).fetchone()
        if view == "objects":
            sql = f"SELECT o.oid,{NAME} class_name,o.shallow shallow_bytes" + base
            total = totals[0]
            order = "shallow_bytes DESC,o.oid"
        else:
            sql = f"SELECT {NAME} class_name,COALESCE(c.loader,'0x0') loader,count(*) instance_count,sum(o.shallow) shallow_size_bytes" + base + " GROUP BY o.class_id,c.name,c.loader,o.kind"
            total = db.execute(cte + "SELECT count(*) FROM (" + sql + ")", selection).fetchone()[0]
            order = "shallow_size_bytes DESC,class_name,loader"
        result = rows(db.execute(cte + sql + " ORDER BY " + order + " LIMIT ? OFFSET ?", [*selection, limit, offset]))
        return {"rows": result, "total": total, "object_count": totals[0], "retained_bytes": totals[1],
                "offset": offset, "selection": selection, "semantics": "Objects becoming unreachable when the selection is removed, under the indexed strong-reference and size model"}


def root_browser(path, offset=0, limit=50, kind=""):
    with query_db(path) as db:
        base = " FROM roots r LEFT JOIN objects o ON o.oid=r.oid LEFT JOIN classes c ON c.cid=o.class_id WHERE (?='' OR r.kind=?)"
        return {"rows": rows(db.execute(f"SELECT r.*,{NAME} class_name" + base + " ORDER BY r.kind,r.oid LIMIT ? OFFSET ?", (kind, kind, limit, offset))),
                "total": db.execute("SELECT count(*)" + base, (kind, kind)).fetchone()[0], "offset": offset}


def unreachable(path, offset=0, limit=50):
    with query_db(path, True) as db:
        sql = f"SELECT {NAME} class_name,count(*) instance_count,sum(o.shallow) shallow_size_bytes FROM objects o LEFT JOIN classes c ON c.cid=o.class_id LEFT JOIN dom d ON d.oid=o.oid WHERE d.oid IS NULL AND o.kind!='class' GROUP BY o.class_id,c.name,o.kind"
        return {"rows": rows(db.execute(sql + " ORDER BY shallow_size_bytes DESC,class_name LIMIT ? OFFSET ?", (limit, offset))),
                "total": db.execute("SELECT count(*) FROM (" + sql + ")").fetchone()[0], "offset": offset, "scope": "Unreachable under the indexed reference policy"}


def loaders(path, offset=0, limit=50):
    with query_db(path) as db:
        sql = "SELECT c.loader oid,count(DISTINCT c.cid) classes,count(o.oid) instance_count,COALESCE(sum(o.shallow),0) shallow_size_bytes FROM classes c LEFT JOIN objects o ON o.class_id=c.cid AND o.kind!='class' GROUP BY c.loader"
        return {"rows": rows(db.execute(sql + " ORDER BY shallow_size_bytes DESC,oid LIMIT ? OFFSET ?", (limit, offset))),
                "total": db.execute("SELECT count(*) FROM (" + sql + ")").fetchone()[0], "offset": offset}


def suspects(path, threshold=10, min_bytes=1048576, offset=0, limit=50):
    """Individual owners and disjoint root children grouped by defining class."""
    with query_db(path, True) as db:
        total = db.execute("SELECT retained FROM dom WHERE oid='0x0'").fetchone()[0]
        cutoff = max(min_bytes, total * threshold / 100)
        base = " FROM dom d JOIN objects o ON o.oid=d.oid LEFT JOIN classes c ON c.cid=o.class_id WHERE d.parent='0x0' AND d.oid!='0x0'"
        individual = rows(db.execute(f"SELECT o.oid,{NAME} class_name,c.loader loader,d.retained retained_bytes,'individual' kind,1 instance_count" + base + " AND d.retained>=?", (cutoff,)))
        groups = rows(db.execute(f"SELECT NULL oid,{NAME} class_name,c.loader loader,sum(d.retained) retained_bytes,'group' kind,count(*) instance_count,o.class_id,o.kind object_kind" + base + " GROUP BY o.class_id,c.name,c.loader,o.kind HAVING count(*)>1 AND sum(d.retained)>=?", (cutoff,)))
        result = sorted(individual + groups, key=lambda r: (-r["retained_bytes"], r["class_name"]))
        for item in result[offset:offset + limit]:
            if item["kind"] == "group":
                item["sample_ids"] = [r[0] for r in db.execute("SELECT o.oid" + base + " AND o.class_id=? AND o.kind=? ORDER BY d.retained DESC,o.oid LIMIT 20", (item["class_id"], item["object_kind"]))]
            else:
                item["sample_ids"] = [item["oid"]]
            item["pct_of_reachable"] = round(item["retained_bytes"] / total * 100, 2) if total else 0
        return {"rows": result[offset:offset + limit], "total": len(result), "offset": offset,
                "threshold_percent": threshold, "minimum_bytes": min_bytes,
                "note": "Ownership observations, not proof of a leak. Group and individual rows overlap; do not add them."}


def merged_paths(path, selection, source=None, build_verified=False):
    if not selection or len(selection) > 20:
        raise ValueError("Select between 1 and 20 objects")
    edges, roots, paths, partial = {}, {}, [], False
    for oid in selection:
        result = root_paths(path, oid, max_nodes=2000, max_depth=40, source=source, build_verified=build_verified)
        partial |= result["partial"]
        for p in result["paths"]:
            paths.append({**p, "target": oid})
            for e in p["edges"]:
                key = (e["src"], e["dst"], e["field"])
                edges.setdefault(key, {**e, "targets": []})["targets"].append(oid)
            for r in p["root"]:
                roots[(r["oid"], r["kind"], r.get("thread"), r.get("frame"))] = r
    return {"paths": paths, "edges": list(edges.values()), "roots": list(roots.values()),
            "partial": partial, "source_attached": source is not None,
            "note": "Merged representative paths; at most 2,000 visited nodes per selected object. Not an exhaustive path search."}


def waste(path, query="duplicate_arrays", offset=0, limit=50):
    with query_db(path) as db:
        if query == "duplicate_arrays":
            sql = "SELECT min(o.oid) oid,h.etype element_type,o.length,count(*) copies,sum(o.shallow)-max(o.shallow) potential_bytes FROM array_hashes h JOIN objects o ON o.oid=h.oid GROUP BY h.etype,h.digest,o.length HAVING count(*)>1"
            order = "potential_bytes DESC,oid"
        elif query == "empty_arrays":
            sql = f"SELECT o.oid,{NAME} class_name,o.shallow shallow_bytes FROM objects o LEFT JOIN classes c ON c.cid=o.class_id WHERE (o.kind='object_array' OR o.kind LIKE 'primitive:%') AND o.length=0"
            order = "shallow_bytes DESC,oid"
        elif query == "sparse_arrays":
            sql = "SELECT o.oid,o.length capacity,count(e.dst) occupied,o.shallow shallow_bytes FROM objects o LEFT JOIN edges e ON e.src=o.oid AND e.field LIKE '[%' WHERE o.kind='object_array' AND o.length>0 GROUP BY o.oid HAVING count(e.dst)*2<o.length"
            order = "shallow_bytes DESC,oid"
        elif query == "constant_arrays":
            sql = "SELECT o.oid,o.kind class_name,o.length,o.shallow shallow_bytes,json_extract(o.values_json,'$.constant') constant_value FROM objects o WHERE o.kind LIKE 'primitive:%' AND o.length>0 AND json_type(o.values_json,'$.constant') IS NOT NULL"
            order = "shallow_bytes DESC,oid"
        elif query == "duplicate_strings":
            # Only full backing arrays: historical substring sharing requires
            # hashing the selected slice, which the persistent index does not hold.
            sql = '''SELECT min(s.oid) oid,count(*) copies,sum(s.shallow) string_object_bytes,
                     h.etype element_type,a.length backing_length,
                     count(DISTINCT a.oid) distinct_backing_arrays
                     FROM objects s JOIN classes c ON c.cid=s.class_id
                     JOIN edges e ON e.src=s.oid AND e.field='java.lang.String.value'
                     JOIN objects a ON a.oid=e.dst JOIN array_hashes h ON h.oid=a.oid
                     WHERE c.name='java.lang.String'
                     AND json_type(s.values_json,'$."java.lang.String.offset"') IS NULL
                     AND json_type(s.values_json,'$."java.lang.String.count"') IS NULL
                     AND (h.etype=5 OR (h.etype=8 AND json_extract(s.values_json,'$."java.lang.String.coder"') IN (0,1)))
                     GROUP BY h.digest,h.etype,a.length,json_extract(s.values_json,'$."java.lang.String.coder"')
                     HAVING count(*)>1'''
            order = "string_object_bytes DESC,oid"
        elif query == "threadlocals":
            sql = '''SELECT owner.src thread_object,entry.oid oid,value.dst value_object,key.dst key_object,
                     CASE WHEN key.dst IS NULL THEN 'no recorded key; inspect stale-entry lifecycle' ELSE 'key recorded' END key_status
                     FROM edges owner JOIN edges table_edge ON table_edge.src=owner.dst AND table_edge.field LIKE '%.table'
                     JOIN edges slot ON slot.src=table_edge.dst AND slot.field LIKE '[%'
                     JOIN objects entry ON entry.oid=slot.dst JOIN classes c ON c.cid=entry.class_id
                     LEFT JOIN edges value ON value.src=entry.oid AND value.field LIKE '%.value'
                     LEFT JOIN edges key ON key.src=entry.oid AND key.field='java.lang.ref.Reference.referent'
                     WHERE owner.field IN ('java.lang.Thread.threadLocals','java.lang.Thread.inheritableThreadLocals')
                     AND c.name='java.lang.ThreadLocal$ThreadLocalMap$Entry' '''
            order = "thread_object,oid"
        elif query == "references":
            sql = '''SELECT c.name class_name,count(*) instance_count,count(e.dst) recorded_referents,
                     sum(o.shallow) shallow_size_bytes FROM objects o JOIN classes c ON c.cid=o.class_id
                     LEFT JOIN edges e ON e.src=o.oid AND e.field='java.lang.ref.Reference.referent'
                     WHERE o.kind='instance' AND (c.name IN ('java.lang.ref.SoftReference','java.lang.ref.WeakReference','java.lang.ref.PhantomReference','java.lang.ref.Finalizer') OR e.dst IS NOT NULL)
                     GROUP BY c.cid,c.name'''
            order = "shallow_size_bytes DESC,class_name"
        elif query == "collections":
            sql = '''SELECT o.oid,c.name class_name,
                     COALESCE(json_extract(o.values_json,'$."java.util.ArrayList.size"'),json_extract(o.values_json,'$."java.util.HashMap.size"')) logical_size,
                     a.length capacity,(SELECT count(*) FROM edges slot WHERE slot.src=a.oid AND slot.field LIKE '[%') occupied,
                     a.shallow backing_bytes,o.shallow shallow_bytes
                     FROM objects o JOIN classes c ON c.cid=o.class_id
                     LEFT JOIN edges e ON e.src=o.oid AND e.field IN ('java.util.ArrayList.elementData','java.util.HashMap.table')
                     LEFT JOIN objects a ON a.oid=e.dst
                     WHERE o.kind='instance' AND c.name IN ('java.util.ArrayList','java.util.HashMap','java.util.LinkedHashMap')'''
            order = "backing_bytes DESC,oid"
        else:
            raise ValueError("Unknown memory-waste query")
        note = "Potential savings require checking mutability, identity and application lifecycle; they are not guaranteed reclaimable bytes."
        if query == 'duplicate_strings':
            note = "Equal full String backing contents and coder. Historical offset/count layouts are excluded. Shared backing arrays are counted separately; string-object bytes are not estimated savings."
        if query in ('threadlocals', 'references'):
            note = "Recorded references for supported HotSpot field layouts; absence of a key is an investigation lead, not proof of a leak. This does not simulate reference processing or finalizer queues."
        if query == 'constant_arrays':
            note = "Constant values are recorded in newly built indexes only. Reanalyze older snapshots before interpreting empty results."
        if query == 'collections':
            note = "Recognized ArrayList/HashMap/LinkedHashMap field layouts only. Map occupied slots are buckets, not logical entries. Null capacity means no recorded backing array."
        return {"rows": rows(db.execute(sql + " ORDER BY " + order + " LIMIT ? OFFSET ?", (limit, offset))),
                "total": db.execute("SELECT count(*) FROM (" + sql + ")").fetchone()[0], "offset": offset,
                "note": note}


def collection_entries(path, oid, offset=0, limit=50):
    with query_db(path) as db:
        obj = db.execute("SELECT o.values_json,c.name FROM objects o JOIN classes c ON c.cid=o.class_id WHERE o.oid=?", (oid,)).fetchone()
        if not obj or obj['name'] not in ('java.util.ArrayList', 'java.util.HashMap', 'java.util.LinkedHashMap'):
            raise Unavailable('No semantic adapter for this collection layout')
        import json
        values = json.loads(obj['values_json'])
        is_list = obj['name'] == 'java.util.ArrayList'
        size_field = 'java.util.ArrayList.size' if is_list else 'java.util.HashMap.size'
        size = values.get(size_field)
        if not isinstance(size, int) or size < 0:
            raise Unavailable('Collection size field is unavailable or invalid')
        backing = db.execute("SELECT dst FROM edges WHERE src=? AND field=?", (oid, 'java.util.ArrayList.elementData' if is_list else 'java.util.HashMap.table')).fetchone()
        if not backing:
            return {'rows': [], 'total': 0, 'offset': offset, 'complete': size == 0, 'note': 'No recorded backing array', 'logical_size': size}
        if is_list:
            capacity = db.execute('SELECT length FROM objects WHERE oid=?', (backing[0],)).fetchone()
            if not capacity or size > capacity[0]:
                raise Unavailable('ArrayList size exceeds recorded capacity')
            # Null slots have no edges. Reconstruct only the requested logical page.
            result = []
            for i in range(offset, min(size, offset + limit)):
                edge = db.execute('SELECT dst FROM edges WHERE src=? AND field=?', (backing[0], f'[{i}]')).fetchone()
                result.append({'index': i, 'value_object': edge[0] if edge else None})
            return {'rows': result, 'total': size, 'offset': offset, 'complete': True, 'logical_size': size, 'note': 'Logical ArrayList elements, including nulls; excludes unused capacity.'}
        cte = "WITH RECURSIVE nodes(oid) AS (SELECT dst FROM edges WHERE src=? AND field LIKE '[%' UNION SELECT e.dst FROM nodes n JOIN edges e ON e.src=n.oid WHERE e.field='java.util.HashMap$Node.next' OR e.field='java.util.HashMap$Entry.next') "
        sql = "SELECT n.oid,key.dst key_object,value.dst value_object FROM nodes n LEFT JOIN edges key ON key.src=n.oid AND key.field IN ('java.util.HashMap$Node.key','java.util.HashMap$Entry.key') LEFT JOIN edges value ON value.src=n.oid AND value.field IN ('java.util.HashMap$Node.value','java.util.HashMap$Entry.value')"
        total = db.execute(cte + 'SELECT count(*) FROM nodes', (backing[0],)).fetchone()[0]
        return {'rows': rows(db.execute(cte + sql + ' ORDER BY n.oid LIMIT ? OFFSET ?', (backing[0], limit, offset))),
                'total': total, 'offset': offset, 'logical_size': size, 'complete': total == size,
                'note': 'HashMap bucket chains using known Node/Entry fields. Completeness compares traversed entries with the recorded size; null keys/values have no edge.'}
