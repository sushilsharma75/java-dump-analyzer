"""Persistent SQLite object graph, bounded payload reads and on-demand investigation.

Object IDs are hex strings (HPROF IDs may exceed SQLite's signed integer range).
Payloads stay in the dump while building; the finished index is self-contained.
No memory allocation proportional to an array's length is needed.
"""

from __future__ import annotations
import json
import math
import sqlite3
import struct
import hashlib
from collections import deque
from .heap_graph import _open
from .heap_dump import TYPE_SIZES, _normalize_class_name
from .heap_sizing import size_model


def hx(n):
    return hex(n)


def connect(path):
    db = sqlite3.connect(str(path), timeout=60)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA temp_store=FILE")
    db.execute("PRAGMA cache_size=-16384")
    return db


def json_primitive(value, ty):
    # Preserve 64-bit integers for JavaScript clients and keep wire JSON finite.
    if ty == 11:
        return str(value)
    if isinstance(value, float) and not math.isfinite(value):
        return str(value)
    return value


def build_index(fp, path, progress=None, model=None):
    """Two passes: catalog records, then decode field references using complete layouts."""
    db = connect(path)
    try:
        db.executescript("""
        CREATE TABLE objects(oid TEXT PRIMARY KEY, class_id TEXT, kind TEXT, shallow INTEGER, length INTEGER, offset INTEGER, values_json TEXT);
        CREATE TABLE edges(src TEXT, dst TEXT, field TEXT, strength TEXT);
        CREATE TABLE array_hashes(oid TEXT PRIMARY KEY, digest TEXT, etype INTEGER);
        CREATE TABLE roots(oid TEXT, kind TEXT, thread INTEGER, frame INTEGER);
        CREATE TABLE classes(cid TEXT PRIMARY KEY, name TEXT, super TEXT, loader TEXT, fields TEXT);
        CREATE TABLE strings(id TEXT PRIMARY KEY, value TEXT);
        CREATE TABLE frames(id TEXT PRIMARY KEY, method TEXT, file TEXT, serial INTEGER, line INTEGER);
        CREATE TABLE traces(serial INTEGER, thread INTEGER, frames TEXT);
        CREATE TABLE class_serial(serial INTEGER PRIMARY KEY, cid TEXT);
        CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT);
        """)
        fp.seek(0, 2)
        file_size = fp.tell()
        reader, width = _open(fp)
        model = model or size_model(width, file_size)
        rid = lambda: reader.id(width)

        def edge(a, b, field, strength="strong"):
            if b:
                db.execute(
                    "INSERT INTO edges VALUES(?,?,?,?)", (hx(a), hx(b), field, strength)
                )

        def value(ty):
            if ty == 2:
                return rid()
            fmt = {
                4: "B",
                5: "H",
                6: "f",
                7: "d",
                8: "b",
                9: "h",
                10: "i",
                11: "q",
            }.get(ty)
            if not fmt:
                raise ValueError(f"Unknown HPROF field type {ty}")
            return struct.unpack(">" + fmt, reader.read(TYPE_SIZES[ty]))[0]

        records = 0
        while reader.pos < file_size:
            tag = reader.u1()
            reader.u4()
            length = reader.u4()
            end = reader.pos + length
            if end > file_size:
                raise ValueError("Truncated HPROF record")
            if tag == 1:
                sid = rid()
                raw = reader.read(length - width)
                db.execute(
                    "INSERT OR REPLACE INTO strings VALUES(?,?)",
                    (hx(sid), raw.decode("utf-8", "replace")),
                )
            elif tag == 2:
                serial = reader.u4()
                cid = rid()
                reader.u4()
                name = rid()
                db.execute(
                    "INSERT OR REPLACE INTO class_serial VALUES(?,?)", (serial, hx(cid))
                )
                db.execute(
                    "INSERT OR REPLACE INTO meta VALUES(?,?)",
                    ("name:" + hx(cid), hx(name)),
                )
            elif tag == 4:
                fid = rid()
                method = rid()
                rid()
                file = rid()
                serial = reader.u4()
                line = struct.unpack(">i", reader.read(4))[0]
                db.execute(
                    "INSERT INTO frames VALUES(?,?,?,?,?)",
                    (hx(fid), hx(method), hx(file), serial, line),
                )
            elif tag == 5:
                serial = reader.u4()
                thread = reader.u4()
                n = reader.u4()
                frames = [hx(rid()) for _ in range(n)]
                db.execute(
                    "INSERT INTO traces VALUES(?,?,?)",
                    (serial, thread, json.dumps(frames)),
                )
            elif tag in (0x0C, 0x1C):
                while reader.pos < end:
                    sub = reader.u1()
                    if sub == 0x20:
                        cid = rid()
                        reader.u4()
                        sup = rid()
                        loader = rid()
                        signers = rid()
                        domain = rid()
                        rid()
                        rid()
                        reader.u4()
                        for _ in range(reader.u2()):
                            slot = reader.u2()
                            ty = reader.u1()
                            v = value(ty)
                            if ty == 2:
                                edge(cid, v, "constant_pool:" + str(slot))
                        for _ in range(reader.u2()):
                            name = rid()
                            ty = reader.u1()
                            v = value(ty)
                            if ty == 2:
                                edge(cid, v, "static:" + hx(name))
                        fields = [(hx(rid()), reader.u1()) for _ in range(reader.u2())]
                        db.execute(
                            "INSERT INTO classes VALUES(?,?,?,?,?)",
                            (hx(cid), "", hx(sup), hx(loader), json.dumps(fields)),
                        )
                        db.execute(
                            "INSERT OR IGNORE INTO objects VALUES(?,?,?,?,?,?,?)",
                            (hx(cid), hx(cid), "class", 0, 0, 0, "{}"),
                        )
                        edge(cid, sup, "<superclass>")
                        edge(cid, loader, "<classloader>")
                        if loader:
                            edge(loader, cid, "<definedClass>")
                        edge(cid, signers, "<signers>")
                        edge(cid, domain, "<protectionDomain>")
                    elif sub == 0x21:
                        oid = rid()
                        reader.u4()
                        cid = rid()
                        n = reader.u4()
                        db.execute(
                            "INSERT INTO objects VALUES(?,?,?,?,?,?,?)",
                            (hx(oid), hx(cid), "instance", 0, n, reader.pos, "{}"),
                        )
                        reader.skip(n)
                    elif sub in (0x22, 0x23):
                        oid = rid()
                        reader.u4()
                        n = reader.u4()
                        if sub == 0x22:
                            cid = rid()
                            kind = "object_array"
                            size = model.object_array_size(n)
                            nbytes = n * width
                        else:
                            ty = reader.u1()
                            cid = 0
                            kind = "primitive:" + str(ty)
                            size = model.prim_array_size(n, TYPE_SIZES[ty])
                            nbytes = n * TYPE_SIZES[ty]
                        db.execute(
                            "INSERT INTO objects VALUES(?,?,?,?,?,?,?)",
                            (hx(oid), hx(cid), kind, size, n, reader.pos, "{}"),
                        )
                        reader.skip(nbytes)
                    elif sub in (
                        0xFF,
                        1,
                        2,
                        3,
                        4,
                        5,
                        6,
                        7,
                        8,
                        0x89,
                        0x8A,
                        0x8B,
                        0x8C,
                        0x8D,
                        0x8E,
                        0x90,
                    ):
                        oid = rid()
                        thread = frame = None
                        if sub == 1:
                            rid()
                        elif sub in (2, 3, 8):
                            thread = reader.u4()
                            frame = reader.u4()
                        elif sub in (4, 6):
                            thread = reader.u4()
                        elif sub == 0x8E:
                            thread = reader.u4()
                            frame = reader.u4()
                        if sub != 0x90:
                            db.execute(
                                "INSERT INTO roots VALUES(?,?,?,?)",
                                (hx(oid), hex(sub), thread, frame),
                            )
                    elif sub == 0xFE:
                        reader.u4()
                        rid()
                    else:
                        raise ValueError(
                            f"Unsupported HPROF heap tag {sub:#x} at {reader.pos - 1}"
                        )
                    if reader.pos > end:
                        raise ValueError("Heap subrecord exceeds segment")
            else:
                reader.skip(length)
            if reader.pos != end:
                raise ValueError("HPROF record length mismatch")
            records += 1
            if records % 1000 == 0:
                db.commit()
        db.execute(
            "UPDATE classes SET name=COALESCE((SELECT value FROM strings WHERE id=(SELECT value FROM meta WHERE key='name:'||classes.cid)),cid)"
        )
        for row in db.execute("SELECT cid,name FROM classes").fetchall():
            db.execute(
                "UPDATE classes SET name=? WHERE cid=?",
                (_normalize_class_name(row["name"]), row["cid"]),
            )
        classes = {r["cid"]: dict(r) for r in db.execute("SELECT * FROM classes")}
        strings = {
            r["id"]: r["value"]
            for r in db.execute(
                "SELECT * FROM strings WHERE id IN (SELECT substr(field,8) FROM edges WHERE field LIKE 'static:%')"
            )
        }
        for sid, name in strings.items():
            db.execute(
                "UPDATE edges SET field=? WHERE field=?",
                ("static:" + name, "static:" + sid),
            )
        layout_cache = {}

        def layout(cid):
            if cid in layout_cache:
                return layout_cache[cid]
            fields = []
            seen = set()
            while cid in classes and cid not in seen:
                seen.add(cid)
                c = classes[cid]
                for name, ty in json.loads(c["fields"]):
                    row = db.execute(
                        "SELECT value FROM strings WHERE id=?", (name,)
                    ).fetchone()
                    field = row[0] if row else name
                    strength = (
                        "weak"
                        if c["name"] == "java.lang.ref.Reference"
                        and field == "referent"
                        else "strong"
                    )
                    fields.append((c["name"] + "." + field, ty, strength))
                cid = c["super"]
            return fields

        count = 0
        for obj in db.execute("SELECT * FROM objects WHERE kind!='class'"):
            if reader.pos != obj["offset"]:
                fp.seek(obj["offset"])
                reader._buf = b""
                reader._buf_pos = 0
                reader.pos = obj["offset"]
            oid = int(obj["oid"], 16)
            cid = int(obj["class_id"], 16)
            edge(oid, cid, "<class>")
            values = {}
            if obj["kind"] == "instance":
                fields = layout(obj["class_id"])
                layout_cache[obj["class_id"]] = fields
                used = 0
                for field, ty, strength in fields:
                    used += width if ty == 2 else TYPE_SIZES[ty]
                    if used > obj["length"]:
                        raise ValueError("Instance layout exceeds payload")
                    v = value(ty)
                    if ty == 2:
                        edge(oid, v, field, strength)
                    else:
                        values[field] = json_primitive(v, ty)
                if used != obj["length"]:
                    raise ValueError("Incomplete instance class layout")
                shallow = model.instance_size(
                    obj["length"], sum(ty == 2 for _, ty, _ in fields), width
                )
                db.execute(
                    "UPDATE objects SET shallow=?, values_json=? WHERE oid=?",
                    (shallow, json.dumps(values), obj["oid"]),
                )
            elif obj["kind"] == "object_array":
                for i in range(obj["length"]):
                    edge(oid, rid(), f"[{i}]")
            else:
                ty = int(obj["kind"].split(":")[1])
                width_bytes = TYPE_SIZES[ty]
                remaining = obj["length"] * width_bytes
                digest = hashlib.sha256()
                sample = b""
                while remaining:
                    chunk = reader.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise ValueError("Truncated primitive array")
                    if len(sample) < 32 * width_bytes:
                        sample += chunk[: 32 * width_bytes - len(sample)]
                    digest.update(chunk)
                    remaining -= len(chunk)
                fmt = {
                    4: "B",
                    5: "H",
                    6: "f",
                    7: "d",
                    8: "b",
                    9: "h",
                    10: "i",
                    11: "q",
                }[ty]
                values["sample"] = [
                    json_primitive(v[0], ty)
                    for v in struct.iter_unpack(">" + fmt, sample)
                ]
                db.execute(
                    "INSERT INTO array_hashes VALUES(?,?,?)",
                    (obj["oid"], digest.hexdigest(), ty),
                )
                db.execute(
                    "UPDATE objects SET values_json=? WHERE oid=?",
                    (json.dumps(values), obj["oid"]),
                )
            count += 1
            if count % 5000 == 0:
                db.commit()
                if progress:
                    progress(count)
        db.executescript(
            "CREATE INDEX outgoing ON edges(src); CREATE INDEX incoming ON edges(dst); CREATE INDEX root_oid ON roots(oid); CREATE INDEX object_class ON objects(class_id);"
        )
        db.execute(
            "INSERT OR REPLACE INTO meta VALUES(?,?)", ("sizing_model", model.name)
        )
        db.execute("INSERT OR REPLACE INTO meta VALUES(?,?)", ("complete", "true"))
        db.commit()
        return {"objects": count, "sizing_model": model.name}
    finally:
        db.close()


def object_detail(path, oid, offset=0, limit=100):
    db = connect(path)
    try:
        obj = db.execute(
            "SELECT o.*,c.name FROM objects o LEFT JOIN classes c ON o.class_id=c.cid WHERE oid=?",
            (oid,),
        ).fetchone()
        if not obj:
            return None
        out = dict(obj)
        out.pop("offset", None)
        out["values"] = json.loads(out.pop("values_json"))
        for direction, column in [("outgoing", "src"), ("incoming", "dst")]:
            out[direction] = [
                dict(r)
                for r in db.execute(
                    f"SELECT * FROM edges WHERE {column}=? ORDER BY rowid LIMIT ? OFFSET ?",
                    (oid, limit, offset),
                )
            ]
            out[direction + "_count"] = db.execute(
                f"SELECT count(*) FROM edges WHERE {column}=?", (oid,)
            ).fetchone()[0]
        out["roots"] = [
            dict(r) for r in db.execute("SELECT * FROM roots WHERE oid=?", (oid,))
        ]
        # Collection metrics are observations of fields and backing-array capacity.
        size = next(
            (
                v
                for k, v in out["values"].items()
                if k.endswith(".size") and isinstance(v, int)
            ),
            None,
        )
        backing = db.execute(
            "SELECT o.length,e.field FROM edges e JOIN objects o ON o.oid=e.dst WHERE e.src=? AND o.kind='object_array' AND (e.field LIKE '%.elementData' OR e.field LIKE '%.table' OR e.field LIKE '%.queue') LIMIT 1",
            (oid,),
        ).fetchone()
        if size is not None:
            out["collection"] = {"size": size, "empty": size == 0}
            if backing:
                capacity = backing["length"]
                out["collection"].update(
                    capacity=capacity, fill_ratio=size / capacity if capacity else None
                )
                arr = db.execute(
                    "SELECT dst FROM edges WHERE src=? AND field=?",
                    (oid, backing["field"]),
                ).fetchone()[0]
                occupied = db.execute(
                    "SELECT count(*) FROM edges WHERE src=? AND field LIKE '[%'", (arr,)
                ).fetchone()[0]
                out["collection"]["occupied_slots"] = occupied
                out["collection"]["collision_entries_lower_bound"] = (
                    max(0, size - occupied)
                    if backing["field"].endswith(".table")
                    else 0
                )
        return out
    finally:
        db.close()


def root_paths(path, oid, max_nodes=10000, max_depth=40, include_weak=False):
    db = connect(path)
    try:
        queue = deque([(oid, [])])
        seen = {oid}
        paths = []
        limited = False
        while queue and len(paths) < 5:
            current, chain = queue.popleft()
            roots = [
                dict(r)
                for r in db.execute("SELECT * FROM roots WHERE oid=?", (current,))
            ]
            if roots:
                paths.append({"root": roots, "edges": list(reversed(chain))})
                continue
            if len(chain) >= max_depth:
                limited = True
                continue
            for row in db.execute("SELECT * FROM edges WHERE dst=?", (current,)):
                e = dict(row)
                if not include_weak and e["strength"] != "strong":
                    continue
                if e["src"] in seen:
                    continue
                if len(seen) >= max_nodes:
                    limited = True
                    break
                seen.add(e["src"])
                queue.append((e["src"], chain + [e]))
        return {
            "paths": paths,
            "visited": len(seen),
            "partial": limited or bool(queue),
            "reference_policy": "all" if include_weak else "strong only",
            "note": "Representative paths; no path within the search budget is not proof of unreachability.",
        }
    finally:
        db.close()


def search_objects(path, class_name="", offset=0, limit=50):
    db = connect(path)
    try:
        return [
            dict(r)
            for r in db.execute(
                "SELECT o.oid,o.kind,o.shallow,o.length,c.name FROM objects o LEFT JOIN classes c ON o.class_id=c.cid WHERE c.name LIKE ? ORDER BY o.oid LIMIT ? OFFSET ?",
                ("%" + class_name + "%", limit, offset),
            )
        ]
    finally:
        db.close()


def heap_threads(path):
    db = connect(path)
    try:
        out = []
        for r in db.execute("SELECT * FROM roots WHERE kind='0x8'"):
            trace = db.execute(
                "SELECT frames FROM traces WHERE serial=? AND thread=?",
                (r["frame"], r["thread"]),
            ).fetchone()
            frames = []
            for fid in json.loads(trace[0]) if trace else []:
                f = db.execute(
                    "SELECT f.*,m.value method_name,s.value file_name,c.name class_name FROM frames f LEFT JOIN strings m ON m.id=f.method LEFT JOIN strings s ON s.id=f.file LEFT JOIN class_serial cs ON cs.serial=f.serial LEFT JOIN classes c ON c.cid=cs.cid WHERE f.id=?",
                    (fid,),
                ).fetchone()
                if f:
                    frames.append(dict(f))
            locals_ = [
                dict(x)
                for x in db.execute(
                    "SELECT * FROM roots WHERE thread=? AND kind IN ('0x2','0x3')",
                    (r["thread"],),
                )
            ]
            out.append(
                {
                    "object_id": r["oid"],
                    "thread_serial": r["thread"],
                    "frames": frames,
                    "locals": locals_,
                    "stack_status": "available" if trace else "not recorded",
                }
            )
        return out
    finally:
        db.close()


def retained(path, top_n=25):
    """Disk-backed immediate dominators (iterative reverse-postorder algorithm).

    The graph and traversal stack live in SQLite. Convergence time depends on
    graph shape; this favors bounded RAM over the in-memory algorithm's speed.
    Retained bytes are exact for this graph and the explicitly assumed layout.
    """
    db = connect(path)
    try:
        db.executescript("""
        DROP TABLE IF EXISTS dom;
        CREATE TABLE dom(oid TEXT PRIMARY KEY, rank INTEGER, parent TEXT, retained INTEGER);
        CREATE TEMP TABLE work(seq INTEGER PRIMARY KEY AUTOINCREMENT, oid TEXT, leaving INTEGER);
        """)
        db.execute(
            "INSERT OR IGNORE INTO objects VALUES('0x0','0x0','virtual',0,0,0,'{}')"
        )
        db.execute("DELETE FROM edges WHERE src='0x0'")
        db.execute(
            "INSERT INTO edges SELECT DISTINCT '0x0',r.oid,'<root>','strong' FROM roots r JOIN objects o ON o.oid=r.oid"
        )
        db.execute("INSERT INTO work(oid,leaving) VALUES('0x0',0)")
        post = 0
        while True:
            w = db.execute("SELECT * FROM work ORDER BY seq DESC LIMIT 1").fetchone()
            if not w:
                break
            db.execute("DELETE FROM work WHERE seq=?", (w["seq"],))
            if w["leaving"]:
                db.execute("UPDATE dom SET rank=? WHERE oid=?", (post, w["oid"]))
                post += 1
                continue
            if db.execute("SELECT 1 FROM dom WHERE oid=?", (w["oid"],)).fetchone():
                continue
            db.execute("INSERT INTO dom VALUES(?,NULL,NULL,0)", (w["oid"],))
            db.execute("INSERT INTO work(oid,leaving) VALUES(?,1)", (w["oid"],))
            db.execute(
                "INSERT INTO work(oid,leaving) SELECT DISTINCT e.dst,0 FROM edges e JOIN objects o ON o.oid=e.dst LEFT JOIN dom d ON d.oid=e.dst WHERE e.src=? AND e.strength='strong' AND d.oid IS NULL",
                (w["oid"],),
            )
        db.execute("UPDATE dom SET rank=?-rank", (post - 1,))
        db.execute("CREATE INDEX IF NOT EXISTS dom_rank ON dom(rank)")
        db.execute("UPDATE dom SET parent='0x0' WHERE oid='0x0'")

        def intersect(a, b):
            while a != b:
                ra = db.execute(
                    "SELECT rank,parent FROM dom WHERE oid=?", (a,)
                ).fetchone()
                rb = db.execute(
                    "SELECT rank,parent FROM dom WHERE oid=?", (b,)
                ).fetchone()
                if ra["rank"] > rb["rank"]:
                    a = ra["parent"]
                else:
                    b = rb["parent"]
            return a

        changed = True
        iterations = 0
        while changed:
            changed = False
            iterations += 1
            for node in db.execute(
                "SELECT oid,parent FROM dom WHERE rank>0 ORDER BY rank"
            ):
                parent = None
                for pred in db.execute(
                    "SELECT DISTINCT e.src FROM edges e JOIN dom d ON d.oid=e.src WHERE e.dst=? AND e.strength='strong' AND d.parent IS NOT NULL",
                    (node["oid"],),
                ):
                    parent = pred[0] if parent is None else intersect(parent, pred[0])
                if parent and parent != node["parent"]:
                    db.execute(
                        "UPDATE dom SET parent=? WHERE oid=?", (parent, node["oid"])
                    )
                    changed = True
            db.commit()
        db.execute(
            "UPDATE dom SET retained=(SELECT shallow FROM objects WHERE objects.oid=dom.oid)"
        )
        for row in db.execute(
            "SELECT oid,parent,retained FROM dom WHERE rank>0 ORDER BY rank DESC"
        ):
            # Fetch the accumulated value again (SQLite cursors may prefetch).
            size = db.execute(
                "SELECT retained FROM dom WHERE oid=?", (row["oid"],)
            ).fetchone()[0]
            db.execute(
                "UPDATE dom SET retained=retained+? WHERE oid=?", (size, row["parent"])
            )
        db.commit()
        reachable = db.execute("SELECT retained FROM dom WHERE oid='0x0'").fetchone()[0]
        unreachable = db.execute(
            "SELECT count(*),COALESCE(sum(shallow),0) FROM objects o LEFT JOIN dom d ON d.oid=o.oid WHERE d.oid IS NULL AND o.kind!='class'"
        ).fetchone()
        entries = []

        def name(oid):
            r = db.execute(
                "SELECT o.kind,c.name FROM objects o LEFT JOIN classes c ON c.cid=o.class_id WHERE oid=?",
                (oid,),
            ).fetchone()
            if not r:
                return oid
            if r["kind"].startswith("primitive:"):
                return {
                    4: "boolean[]",
                    5: "char[]",
                    6: "float[]",
                    7: "double[]",
                    8: "byte[]",
                    9: "short[]",
                    10: "int[]",
                    11: "long[]",
                }.get(int(r["kind"].split(":")[1]), r["kind"])
            n = r["name"] or oid
            if r["kind"] == "class":
                return "class " + n
            if r["kind"] == "object_array" and not n.endswith("[]"):
                return n + "[]"
            return n

        for r in db.execute(
            "SELECT d.*,o.shallow FROM dom d JOIN objects o ON o.oid=d.oid WHERE d.parent='0x0' AND d.oid!='0x0' AND d.retained>0 ORDER BY d.retained DESC LIMIT ?",
            (top_n,),
        ):
            chain = []
            cursor = r["oid"]
            size = r["retained"]
            for _ in range(5):
                child = db.execute(
                    "SELECT oid,retained FROM dom WHERE parent=? AND oid!=? ORDER BY retained DESC LIMIT 1",
                    (cursor, cursor),
                ).fetchone()
                if not child or child["retained"] < size * 0.8:
                    break
                cursor = child["oid"]
                size = child["retained"]
                chain.append(name(cursor))
            entries.append(
                dict(
                    class_name=name(r["oid"]),
                    object_id=r["oid"],
                    shallow_bytes=r["shallow"],
                    retained_bytes=r["retained"],
                    pct_of_reachable=round(r["retained"] / reachable * 100, 1)
                    if reachable
                    else 0,
                    chain=chain,
                    accumulation_object_id=cursor,
                )
            )
        return dict(
            entries=entries,
            reachable_bytes=reachable,
            unreachable_count=unreachable[0],
            unreachable_bytes=unreachable[1],
            iterations=iterations,
        )
    finally:
        db.close()


def duplicate_arrays(path):
    db = connect(path)
    try:
        db.execute(
            "CREATE INDEX IF NOT EXISTS array_digest ON array_hashes(etype,digest)"
        )
        rows = db.execute(
            "SELECT a.etype,a.digest,count(*) copies,max(o.shallow) bytes,min(o.oid) example FROM array_hashes a JOIN objects o ON a.oid=o.oid GROUP BY a.etype,a.digest HAVING count(*)>1 ORDER BY (count(*)-1)*max(o.shallow) DESC"
        )
        groups = []
        potential = 0
        for row in rows:
            potential += (row["copies"] - 1) * row["bytes"]
            if len(groups) < 20:
                groups.append(dict(row))
        return {
            "potential_duplicate_bytes": potential,
            "groups": groups,
            "limitation": "Equal contents do not imply interchangeable mutable arrays or guaranteed reclaimable memory.",
        }
    finally:
        db.close()
