"""Sampled reverse reference tracing with bounded frontiers and streamed arrays.

Each reported chain follows connected object IDs. A field observation is not
proof of GC-root reachability, unbounded growth, or exact retained size.
Memory scales with class/root metadata and the configured sample, not array length.
"""
from __future__ import annotations
import struct
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
          on_primarray=None) -> None:
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
                          on_instance, on_objarray, on_primarray)
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
                  on_instance, on_objarray, on_primarray) -> None:
    while reader.pos < seg_end:
        sub = reader.u1()
        if sub == HEAP_INSTANCE_DUMP:
            oid = reader.id(id_size); reader.u4(); cid = reader.id(id_size)
            nbytes = reader.u4()
            if on_instance:
                on_instance(oid, cid, reader.read(nbytes))
            else:
                reader.skip(nbytes)
        elif sub == HEAP_OBJECT_ARRAY_DUMP:
            oid = reader.id(id_size); reader.u4(); n = reader.u4(); elem = reader.id(id_size)
            if on_objarray:
                # Callbacks may stop after a match; consume the remaining payload
                # without materializing millions of array entries.
                array_end = reader.pos + n * id_size
                def elements():
                    remaining = n
                    fmt = ">Q" if id_size == 8 else ">I"
                    while remaining:
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
            oid = reader.id(id_size); reader.u4(); n = reader.u4(); t = reader.u1()
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


class _Tracer:
    def __init__(self, fp: BinaryIO, sample_cap: int = 2000, max_levels: int = 6):
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

    # ---- pass 1: tables, layouts, roots, static targets ----
    def scan_meta(self) -> None:
        reader, self.id_size = _open(self.fp)
        statics: List[Tuple[int, int, int]] = []

        def on_class(cid, sup, fields, sts):
            self.layouts_own[cid] = fields
            self.supers[cid] = sup
            statics.extend(sts)

        _walk(reader, self.id_size,
              on_utf8=lambda sid, t: self.strings.__setitem__(sid, t),
              on_load_class=lambda c, nid: self.class_name_id.__setitem__(c, nid),
              on_class=on_class,
              on_root=lambda rid: self.roots.add(rid))

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

    def _refs(self, cid: int, body: bytes):
        pos = 0
        for nid, t, strong in self.full_layout(cid):
            sz = self.id_size if t == 2 else TYPE_SIZES.get(t, 0)
            if pos + sz > len(body):
                break
            if t == 2 and strong:
                tgt = int.from_bytes(body[pos:pos + self.id_size], "big")
                if tgt:
                    yield nid, tgt
            pos += sz

    # ---- pass 2: sample the dominant objects ----
    def sample(self, leaf: str) -> List[int]:
        out: List[int] = []
        reader, _ = _open(self.fp)
        if leaf.endswith("[]"):
            base = leaf[:-2]
            if base in _PRIM_ETYPE:
                etype = _PRIM_ETYPE[base]

                def on_pa(oid, t, n):
                    if t == etype and len(out) < self.sample_cap:
                        out.append(oid)
                _walk(reader, self.id_size, on_primarray=on_pa)
            else:
                elem_ids = {cid for cid, nm in self.class_name_by_id.items() if nm in (base, leaf)}

                def on_oa(oid, elem, elems):
                    if elem in elem_ids and len(out) < self.sample_cap:
                        out.append(oid)
                _walk(reader, self.id_size, on_objarray=on_oa)
        else:
            leaf_ids = {cid for cid, nm in self.class_name_by_id.items() if nm == leaf}
            if not leaf_ids:
                return out

            def on_inst(oid, cid, body):
                if cid in leaf_ids and len(out) < self.sample_cap:
                    out.append(oid)
            _walk(reader, self.id_size, on_instance=on_inst)
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
        for _ in range(self.max_levels):
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
                if len(next_frontier) < self.sample_cap and oid not in next_frontier:
                    next_frontier[oid] = chain

            def on_inst(oid, cid, body):
                cname = self.class_name_by_id.get(cid, "?")
                for nid, target in self._refs(cid, body):
                    if target in frontier:
                        field = self.strings.get(nid, "?")
                        record(oid, target, f"{cname}.{field}", cname, field)

            def on_arr(oid, elem, elements):
                for target in elements:
                    if target in frontier:
                        name = self.array_name(elem)
                        record(oid, target, name, "java.lang.Object[]", "[]")
                        break

            reader, _ = _open(self.fp)
            _walk(reader, self.id_size, on_instance=on_inst, on_objarray=on_arr)
            if terminal:
                return terminal
            visited.update(next_frontier)
            frontier = next_frontier
        return best, None


def trace_retention(fp: BinaryIO, leaf_class: str, source=None,
                    sample_cap: int = 2000, max_levels: int = 6) -> Optional[Finding]:
    """Trace what holds `leaf_class` alive and return a retention-chain Finding.

    Returns None if nothing useful was found (no holders, or the class isn't in
    the dump). Best-effort and heuristic — see the module docstring.
    """
    tracer = _Tracer(fp, sample_cap=sample_cap, max_levels=max_levels)
    tracer.scan_meta()
    chain, terminal = tracer.trace(leaf_class)
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
