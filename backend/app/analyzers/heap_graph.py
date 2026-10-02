"""Sampled reverse reference tracing with bounded frontiers and streamed arrays.

Each reported chain follows connected object IDs. A field observation is not
proof of GC-root reachability, unbounded growth, or exact retained size.
Memory scales with class/root metadata and the configured sample, not array length.
"""
from __future__ import annotations
import struct
from .heap_control import check_budget
from typing import BinaryIO, Dict, List, Optional, Set, Tuple

from ..schemas import Finding, Severity, SourceLocation
from .source import is_user_code
from .heap_dump import (
    _Reader, _normalize_class_name, TYPE_SIZES,
    TAG_UTF8, TAG_LOAD_CLASS, TAG_HEAP_DUMP, TAG_HEAP_DUMP_SEGMENT,
    HEAP_CLASS_DUMP, HEAP_INSTANCE_DUMP, HEAP_OBJECT_ARRAY_DUMP, HEAP_PRIMITIVE_ARRAY_DUMP,
    HEAP_ROOT_UNKNOWN, HEAP_ROOT_JNI_GLOBAL, HEAP_ROOT_JNI_LOCAL, HEAP_ROOT_JAVA_FRAME,
    HEAP_ROOT_NATIVE_STACK, HEAP_ROOT_STICKY_CLASS, HEAP_ROOT_THREAD_BLOCK,
    HEAP_ROOT_MONITOR_USED, HEAP_ROOT_THREAD_OBJ,
)

# Primitive array element type codes, keyed by the JLS base name.
_PRIM_ETYPE = {"boolean": 4, "char": 5, "float": 6, "double": 7,
               "byte": 8, "short": 9, "int": 10, "long": 11}


class _TraceComplete(Exception):
    """Stop a pass once its sample or first terminal is determined."""


def _open(fp: BinaryIO) -> Tuple[_Reader, int]:
    """Seek to start, parse the hprof header, return a reader at the first record."""
    fp.seek(0)
    reader = _Reader(fp)
    hb = bytearray()
    while True:
        b = reader.read(1)
        if not b:
            raise ValueError("EOF in header")
        if b == b"\x00":
            break
        hb.extend(b)
        if len(hb) > 64:
            raise ValueError("not an hprof header")
    if not bytes(hb).startswith(b"JAVA PROFILE"):
        raise ValueError("not an hprof header")
    id_size = reader.u4()
    reader.u4(); reader.u4()  # timestamp
    return reader, id_size


def _parse_class_dump(reader: _Reader, id_size: int):
    """Return (class_id, super_id, instance_fields, static_object_fields)."""
    cid = reader.id(id_size)
    reader.u4()                         # stack trace serial
    super_id = reader.id(id_size)
    for _ in range(5):                  # loader, signers, prot-domain, reserved1/2
        reader.id(id_size)
    reader.u4()                         # instance size
    cp = reader.u2()
    for _ in range(cp):
        reader.u2()
        t = reader.u1()
        reader.skip(id_size if t == 2 else TYPE_SIZES.get(t, 0))
    n_static = reader.u2()
    statics: List[Tuple[int, int, int]] = []
    for _ in range(n_static):
        nid = reader.id(id_size)
        t = reader.u1()
        if t == 2:
            val = reader.id(id_size)
            if val:
                statics.append((cid, nid, val))
        else:
            reader.skip(TYPE_SIZES.get(t, 0))
    n_fields = reader.u2()
    fields: List[Tuple[int, int]] = []
    for _ in range(n_fields):
        nid = reader.id(id_size)
        t = reader.u1()
        fields.append((nid, t))
    return cid, super_id, fields, statics


def _walk(reader: _Reader, id_size: int, *, on_utf8=None, on_load_class=None,
          on_class=None, on_root=None, on_instance=None, on_objarray=None,
          on_primarray=None, on_instance_header=None, on_progress=None,
          instance_filter=None) -> None:
    """Walk every top-level record, dispatching to the provided callbacks.

    Object/array bodies are only read when the matching callback is given;
    otherwise they're skipped, keeping passes that don't need bodies cheap.
    """
    while True:
        tagb = reader.read(1)
        if not tagb:
            break
        tag = tagb[0]
        reader.u4()  # timestamp delta
        length = reader.u4()
        if tag in (TAG_HEAP_DUMP, TAG_HEAP_DUMP_SEGMENT):
            seg_end = reader.pos + length
            _walk_segment(reader, seg_end, id_size, on_class, on_root,
                          on_instance, on_objarray, on_primarray,
                          on_instance_header, on_progress, instance_filter)
        elif tag == TAG_UTF8:
            sid = reader.id(id_size)
            data = reader.read(length - id_size)
            if on_utf8:
                on_utf8(sid, data.decode("utf-8", errors="replace"))
        elif tag == TAG_LOAD_CLASS:
            reader.u4()
            class_obj = reader.id(id_size)
            reader.u4()
            name_id = reader.id(id_size)
            if on_load_class:
                on_load_class(class_obj, name_id)
        else:
            reader.skip(length)


def _walk_segment(reader, seg_end, id_size, on_class, on_root,
                  on_instance, on_objarray, on_primarray,
                  on_instance_header=None, on_progress=None, instance_filter=None) -> None:
    instance_header = struct.Struct(">QIQI" if id_size == 8 else ">IIII")
    array_header = struct.Struct(">QIIQ" if id_size == 8 else ">IIII")
    primitive_header = struct.Struct(">QIIB" if id_size == 8 else ">IIIB")
    objects = 0
    while reader.pos < seg_end:
        # Decode common headers directly from the read-ahead buffer. Avoid
        # allocating a tag byte and a header byte string for every object.
        if reader._buf_pos >= len(reader._buf):
            reader._ensure(1)
        sub = reader._buf[reader._buf_pos]
        reader._buf_pos += 1
        reader.pos += 1
        if sub == HEAP_INSTANCE_DUMP:
            reader._ensure(instance_header.size)
            oid, _, cid, nbytes = instance_header.unpack_from(reader._buf, reader._buf_pos)
            reader._buf_pos += instance_header.size
            reader.pos += instance_header.size
            if on_instance_header:
                on_instance_header(oid, cid)
            if on_instance and (instance_filter is None or instance_filter(oid, cid)):
                on_instance(oid, cid, reader.read(nbytes))
            else:
                reader.skip(nbytes)
        elif sub == HEAP_OBJECT_ARRAY_DUMP:
            reader._ensure(array_header.size)
            oid, _, n, elem = array_header.unpack_from(reader._buf, reader._buf_pos)
            reader._buf_pos += array_header.size
            reader.pos += array_header.size
            if on_objarray:
                # Callbacks may stop after a match; consume the remaining payload
                # without materializing millions of array entries.
                array_end = reader.pos + n * id_size
                def elements():
                    remaining = n
                    fmt = ">Q" if id_size == 8 else ">I"
                    while remaining:
                        check_budget()
                        count = min(8192, remaining)
                        payload = reader.read(count * id_size)
                        if len(payload) != count * id_size:
                            raise ValueError("Truncated object array")
                        yield from (v[0] for v in struct.iter_unpack(fmt, payload))
                        remaining -= count
                on_objarray(oid, elem, elements())
                reader.skip(array_end - reader.pos)
            else:
                reader.skip(n * id_size)
        elif sub == HEAP_PRIMITIVE_ARRAY_DUMP:
            reader._ensure(primitive_header.size)
            oid, _, n, t = primitive_header.unpack_from(reader._buf, reader._buf_pos)
            reader._buf_pos += primitive_header.size
            reader.pos += primitive_header.size
            if on_primarray:
                on_primarray(oid, t, n)
            reader.skip(n * TYPE_SIZES.get(t, 0))
        elif sub == HEAP_CLASS_DUMP:
            res = _parse_class_dump(reader, id_size)
            if on_class:
                on_class(*res)
        elif sub in (HEAP_ROOT_UNKNOWN, HEAP_ROOT_STICKY_CLASS, HEAP_ROOT_MONITOR_USED):
            rid = reader.id(id_size)
            if on_root:
                on_root(rid)
        elif sub == HEAP_ROOT_JNI_GLOBAL:
            rid = reader.id(id_size); reader.id(id_size)
            if on_root:
                on_root(rid)
        elif sub in (HEAP_ROOT_JNI_LOCAL, HEAP_ROOT_JAVA_FRAME, HEAP_ROOT_THREAD_OBJ):
            rid = reader.id(id_size); reader.skip(8)
            if on_root:
                on_root(rid)
        elif sub in (HEAP_ROOT_NATIVE_STACK, HEAP_ROOT_THREAD_BLOCK):
            rid = reader.id(id_size); reader.skip(4)
            if on_root:
                on_root(rid)
        elif sub in (0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x90):
            rid = reader.id(id_size)
            if on_root and sub != 0x90:
                on_root(rid)
        elif sub == 0x8E:
            rid = reader.id(id_size)
            reader.skip(8)
            if on_root:
                on_root(rid)
        elif sub == 0xFE:
            reader.skip(4 + id_size)
        else:
            raise ValueError(f"Unsupported HPROF heap tag {sub:#x} at {reader.pos - 1}")
        if reader.pos > seg_end:
            raise ValueError("Heap subrecord exceeds segment")
        objects += 1
        if objects % 8192 == 0:
            check_budget()
        if on_progress and objects % 1_000_000 == 0:
            on_progress(reader.pos)


class _Tracer:
    def __init__(self, fp: BinaryIO, sample_cap: int = 2000, max_levels: int = 6,
                 stage_callback=None):
        self.fp = fp
        self.sample_cap = sample_cap
        self.max_levels = max_levels
        self.strings: Dict[int, str] = {}
        self.class_name_id: Dict[int, int] = {}
        self.layouts_own: Dict[int, List[Tuple[int, int]]] = {}
        self.supers: Dict[int, int] = {}
        self.static_targets: Dict[int, Tuple[str, str]] = {}  # obj_id -> (class, field)
        self.roots: Set[int] = set()
        self.id_size = 8
        self._layout_cache: Dict[int, List[Tuple[int, int, bool]]] = {}
        self.class_name_by_id: Dict[int, str] = {}
        self.stage = stage_callback or (lambda message: None)
        self._ref_cache = {}
        self._unpack_ref = struct.Struct(">Q").unpack_from

    # ---- pass 1: tables, layouts, roots, static targets ----
    def load_meta(self, scan, statics):
        """Reuse the complete histogram pass; no full metadata rescan."""
        self.id_size = scan.id_size
        self._unpack_ref = struct.Struct(">Q" if self.id_size == 8 else ">I").unpack_from
        self.strings = scan.strings
        self.class_name_id = scan.class_obj_to_name_id
        self.layouts_own = scan.class_fields
        self.supers = {cid: meta[0] for cid, meta in scan.class_meta.items()}
        self.roots = scan.gc_roots
        self.class_name_by_id = {
            cid: _normalize_class_name(self.strings.get(nid, ""))
            for cid, nid in self.class_name_id.items()
        }
        for cid, nid, val in statics:
            self.static_targets[val] = (
                self.class_name_by_id.get(cid, "?"), self.strings.get(nid, "?"))

    def scan_meta(self) -> None:
        reader, self.id_size = _open(self.fp)
        self._unpack_ref = struct.Struct(">Q" if self.id_size == 8 else ">I").unpack_from
        statics: List[Tuple[int, int, int]] = []

        def on_class(cid, sup, fields, sts):
            self.layouts_own[cid] = fields
            self.supers[cid] = sup
            statics.extend(sts)

        _walk(reader, self.id_size,
              on_utf8=lambda sid, t: self.strings.__setitem__(sid, t),
              on_load_class=lambda c, nid: self.class_name_id.__setitem__(c, nid),
              on_class=on_class,
              on_root=lambda rid: self.roots.add(rid),
              on_progress=lambda pos: self.stage(f"Tracing retention metadata: {pos:,} bytes"))

        self.class_name_by_id = {
            cid: _normalize_class_name(self.strings.get(nid, ""))
            for cid, nid in self.class_name_id.items()
        }
        for cid, nid, val in statics:
            self.static_targets[val] = (
                self.class_name_by_id.get(cid, "?"), self.strings.get(nid, "?"))

    def full_layout(self, cid: int, _seen=None) -> List[Tuple[int, int, bool]]:
        if cid in self._layout_cache:
            return self._layout_cache[cid]
        _seen = _seen or set()
        if cid in _seen:
            return []
        _seen.add(cid)
        own = [(nid, ty, not (self.class_name_by_id.get(cid) == "java.lang.ref.Reference"
                                    and self.strings.get(nid) == "referent"))
               for nid, ty in self.layouts_own.get(cid, [])]
        sup = self.supers.get(cid, 0)
        res = list(own) + (self.full_layout(sup, _seen) if sup else [])
        self._layout_cache[cid] = res
        return res

    def _ref_offsets(self, cid):
        # Precompute offsets once per class, including primitive and weak fields.
        # Per-object work then touches only strong reference slots.
        if cid not in self._ref_cache:
            pos = 0
            refs = []
            for nid, t, strong in self.full_layout(cid):
                if t == 2 and strong:
                    refs.append((nid, pos))
                pos += self.id_size if t == 2 else TYPE_SIZES.get(t, 0)
            self._ref_cache[cid] = refs
        return self._ref_cache[cid]

    def _refs(self, cid: int, body: bytes):
        unpack = self._unpack_ref
        for nid, pos in self._ref_offsets(cid):
            if pos + self.id_size > len(body):
                break
            tgt = unpack(body, pos)[0]
            if tgt:
                yield nid, tgt

    # ---- pass 2: sample the dominant objects ----
    def sample(self, leaf: str) -> List[int]:
        try:
            return self._sample(leaf)
        except _TraceComplete:
            return self._sampled

    def _sample(self, leaf: str) -> List[int]:
        out: List[int] = []
        self._sampled = out
        if self.sample_cap <= 0:
            return out

        def add(oid):
            out.append(oid)
            if len(out) >= self.sample_cap:
                raise _TraceComplete

        reader, _ = _open(self.fp)
        if leaf.endswith("[]"):
            base = leaf[:-2]
            if base in _PRIM_ETYPE:
                etype = _PRIM_ETYPE[base]

                def on_pa(oid, t, n):
                    if t == etype and len(out) < self.sample_cap:
                        add(oid)
                _walk(reader, self.id_size, on_primarray=on_pa)
            else:
                elem_ids = {cid for cid, nm in self.class_name_by_id.items() if nm in (base, leaf)}

                def on_oa(oid, elem, elems):
                    if elem in elem_ids and len(out) < self.sample_cap:
                        add(oid)
                _walk(reader, self.id_size, on_objarray=on_oa)
        else:
            leaf_ids = {cid for cid, nm in self.class_name_by_id.items() if nm == leaf}
            if not leaf_ids:
                return out

            def on_inst(oid, cid):
                if cid in leaf_ids and len(out) < self.sample_cap:
                    add(oid)
            _walk(reader, self.id_size, on_instance_header=on_inst)
        return out

    def array_name(self, cid):
        name = self.class_name_by_id.get(cid, "?")
        return name if name.endswith("[]") else name + "[]"

    def trace(self, leaf: str):
        # Every frontier entry carries its own connected path. Selecting the most
        # frequent class independently at each level could fabricate a chain.
        frontier = {oid: [leaf] for oid in self.sample(leaf)}
        visited = set(frontier)
        best = None
        for level in range(self.max_levels):
            if not frontier:
                break
            for oid, chain in frontier.items():
                if oid in self.static_targets:
                    cls, field = self.static_targets[oid]
                    return chain + [f"{cls}.{field}"], ("static", cls, field)
                if oid in self.roots:
                    return chain + ["a GC root"], ("gcroot", leaf, "")
            next_frontier = {}
            terminal = None
            self.stage(f"Tracing retention: reference level {level + 1} / {self.max_levels}")

            def record(oid, target, label, cname, field):
                nonlocal terminal, best
                if oid in visited:
                    return
                chain = frontier[target] + [label]
                if best is None or len(chain) > len(best):
                    best = chain
                if terminal is None:
                    if oid in self.static_targets:
                        cls, sf = self.static_targets[oid]
                        terminal = (chain + [f"{cls}.{sf}"], ("static", cls, sf))
                    elif is_user_code(cname):
                        terminal = (chain, ("user", cname, field))
                    elif oid in self.roots:
                        terminal = (chain + ["a GC root"], ("gcroot", cname, field))
                if terminal is not None:
                    raise _TraceComplete
                if len(next_frontier) < self.sample_cap and oid not in next_frontier:
                    next_frontier[oid] = chain

            try:
                self.visit_holders(frontier, visited, record)
            except _TraceComplete:
                pass
            if terminal:
                return terminal
            visited.update(next_frontier)
            frontier = next_frontier
        return best, None

    def visit_holders(self, frontier, visited, record):
        def on_inst(oid, cid, body):
            if oid in visited:
                return
            cname = self.class_name_by_id.get(cid, "?")
            for nid, target in self._refs(cid, body):
                if target in frontier:
                    field = self.strings.get(nid, "?")
                    record(oid, target, f"{cname}.{field}", cname, field)

        def on_arr(oid, elem, elements):
            if oid in visited:
                return
            for target in elements:
                if target in frontier:
                    name = self.array_name(elem)
                    record(oid, target, name, "java.lang.Object[]", "[]")
                    break

        reader, _ = _open(self.fp)
        _walk(reader, self.id_size, on_instance=on_inst, on_objarray=on_arr,
              instance_filter=lambda oid, cid: oid not in visited and bool(self._ref_offsets(cid)),
              on_progress=lambda pos: self.stage(f"Tracing retention references: {pos:,} bytes"))


class _IndexedRoots:
    def __init__(self, db):
        self.db = db

    def __contains__(self, oid):
        return self.db.execute("SELECT 1 FROM roots WHERE oid=? LIMIT 1",
                               (hex(oid),)).fetchone() is not None


class _IndexedTracer(_Tracer):
    """Use existing incoming-edge lookups instead of rescanning the HPROF.

    Dump and field order are preserved so the same sampled chain wins. Only
    instance fields and array elements participate, just as in the stream path;
    graph metadata edges such as <class> are deliberately excluded.
    """
    def __init__(self, fp, db, **kwargs):
        super().__init__(fp, **kwargs)
        self.db = db
        self.roots = _IndexedRoots(db)

    def scan_meta(self):
        self.stage("Tracing retention: loading indexed classes")
        # LOAD_CLASS names also cover array classes without a CLASS_DUMP.
        for row in self.db.execute("""
            SELECT substr(m.key,6),COALESCE(s.value,'')
            FROM meta m LEFT JOIN strings s ON s.id=m.value
            WHERE m.key LIKE 'name:%'
        """):
            self.class_name_by_id[int(row[0], 16)] = _normalize_class_name(row[1])
        for row in self.db.execute("SELECT cid FROM classes ORDER BY rowid"):
            cid = int(row["cid"], 16)
            for edge in self.db.execute(
                "SELECT dst,field FROM edges WHERE src=? AND field LIKE 'static:%' ORDER BY rowid",
                (row["cid"],),
            ):
                self.static_targets[int(edge["dst"], 16)] = (
                    self.class_name_by_id.get(cid, "?"), edge["field"][7:])

    def sample(self, leaf):
        if self.sample_cap <= 0:
            return []
        self.stage("Tracing retention: sampling indexed objects")
        if leaf.endswith("[]") and leaf[:-2] in _PRIM_ETYPE:
            return [int(row[0], 16) for row in self.db.execute(
                "SELECT oid FROM objects WHERE class_id='0x0' AND kind=? ORDER BY rowid LIMIT ?",
                ("primitive:" + str(_PRIM_ETYPE[leaf[:-2]]), self.sample_cap),
            )]
        names = (leaf[:-2], leaf) if leaf.endswith("[]") else (leaf,)
        kind = "object_array" if leaf.endswith("[]") else "instance"
        # Limit each class before merging: the class index also orders rowids,
        # avoiding sorting millions of objects just to select the first 2000.
        samples = []
        for cid, name in self.class_name_by_id.items():
            if name in names:
                samples.extend(self.db.execute(
                    "SELECT rowid,oid FROM objects WHERE class_id=? AND kind=? ORDER BY rowid LIMIT ?",
                    (hex(cid), kind, self.sample_cap),
                ))
                samples.sort(key=lambda row: row[0])
                del samples[self.sample_cap:]
        return [int(row[1], 16) for row in samples]

    def visit_holders(self, frontier, visited, record):
        self.db.execute("CREATE TEMP TABLE IF NOT EXISTS retention_frontier(oid TEXT PRIMARY KEY)")
        self.db.execute("DELETE FROM retention_frontier")
        self.db.executemany("INSERT INTO retention_frontier VALUES(?)",
                            ((hex(oid),) for oid in frontier))
        # Force bounded frontier lookups through incoming, rather than letting
        # SQLite choose a scan over the complete edge/object tables. Sorting is
        # backed by temporary files and preserves the stream tracer's priority.
        rows = self.db.execute("""
            SELECT e.src,e.dst,e.field,o.kind,o.class_id
            FROM retention_frontier f
            CROSS JOIN edges e INDEXED BY incoming ON e.dst=f.oid
            CROSS JOIN objects o ON o.oid=e.src
            WHERE e.strength='strong'
              AND ((o.kind='instance' AND substr(e.field,1,1)!='<')
                   OR (o.kind='object_array' AND substr(e.field,1,1)='['))
            ORDER BY o.rowid,e.rowid
        """)
        previous_array = None
        for row in rows:
            oid = int(row["src"], 16)
            if oid in visited:
                continue
            cid = int(row["class_id"], 16)
            if row["kind"] == "object_array":
                if oid == previous_array:
                    continue
                previous_array = oid
                record(oid, int(row["dst"], 16), self.array_name(cid), "java.lang.Object[]", "[]")
            else:
                cname = self.class_name_by_id.get(cid, "?")
                field = row["field"].rsplit(".", 1)[-1]
                record(oid, int(row["dst"], 16), f"{cname}.{field}", cname, field)


def trace_retention(fp: BinaryIO, leaf_class: str, source=None,
                    sample_cap: int = 2000, max_levels: int = 6,
                    index_path=None, stage_callback=None, metadata=None) -> Optional[Finding]:
    """Trace what holds `leaf_class` alive and return a retention-chain Finding.

    Returns None if nothing useful was found (no holders, or the class isn't in
    the dump). Best-effort and heuristic — see the module docstring.
    """
    db = None
    try:
        options = dict(sample_cap=sample_cap, max_levels=max_levels,
                       stage_callback=stage_callback)
        if index_path is not None:
            from .heap_index import connect
            db = connect(index_path)
            tracer = _IndexedTracer(fp, db, **options)
        else:
            tracer = _Tracer(fp, **options)
        if metadata is not None and index_path is None:
            tracer.load_meta(*metadata)
        else:
            tracer.scan_meta()
        chain, terminal = tracer.trace(leaf_class)
    finally:
        if db is not None:
            db.close()
    if not chain or len(chain) < 2:
        return None

    leaf_simple = leaf_class.rsplit(".", 1)[-1]
    arrow_chain = "  ←  ".join(chain)

    locations: List[SourceLocation] = []
    severity = Severity.WARNING
    holder_label = chain[-1]

    if terminal and terminal[0] in ("static", "user"):
        kind, cls, field = terminal
        loc = SourceLocation(class_name=cls, method=field, is_user_code=is_user_code(cls))
        if source:
            info = source.find_field(cls, field)
            if info:
                loc.line = info["line"]
                loc.repo_path = info["repo_path"]
                loc.snippet = info["snippet"]
        locations.append(loc)
        severity = Severity.WARNING
        holder_desc = (
            f"the {'static ' if kind == 'static' else ''}field "
            f"`{cls.rsplit('.', 1)[-1]}.{field}`"
            + (" in your code" if is_user_code(cls) else "")
        )
    else:
        holder_desc = f"`{holder_label}`"

    return Finding(
        severity=severity,
        title=f"Retention path: `{leaf_simple}` is held by {holder_desc}",
        conclusion="observation",
        confidence="medium",
        limitations=[
            f"Samples up to {sample_cap} objects and searches up to {max_levels} reference levels.",
            "A holding field does not prove GC-root reachability or unbounded growth.",
            "Retained sizes are not computed by this trace; other owners may exist.",
        ],
        description=(
            f"Connected references from sampled `{leaf_class}` objects:\n\n    {arrow_chain}\n\n"
            "Read right-to-left. Each step refers to the preceding object. "
            "The trace stops at a holding field, a GC root, or the search budget."
        ),
        impact="These references identify an ownership lead for the sampled objects.",
        likely_cause="Check whether this owner retains objects beyond their intended lifetime.",
        evidence=[f"retention chain: {arrow_chain}"]
                 + ([f"anchor resolved to {locations[0].repo_path}:{locations[0].line}"]
                    if locations and locations[0].repo_path else []),
        remediation=(
            "Check the owner’s lifecycle and compare captures for growth. If excessive retention is confirmed, use a size/time "
            "limit (Caffeine, Guava `CacheBuilder`) or evict explicitly; if it's a registry, "
            "make sure every add has a matching remove; if it's a buffer, release it when done."
        ),
        category="memory",
        source_locations=locations,
    )
