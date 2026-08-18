"""
In-process retention tracer — answers "what holds the leaking objects alive?"
without Eclipse MAT and without a full dominator tree.

Heap dumps record the object reference graph, but materializing the whole graph
(or a dominator tree) for a 25GB dump is infeasible in Python. The trick here is
to never build the full graph: to find *who holds the dominant objects*, we only
need GC roots, class field layouts, and a SAMPLE of the dominant objects. Then we
climb the graph in reverse, one level at a time:

  Pass 1   walk once → class layouts (+ superclass chain), static-field targets,
           GC roots, string + class tables.
  Pass 2   walk once → collect a bounded sample of the dominant objects.
  Pass N   for each level, walk once → find which objects reference the current
           frontier (type-level), and whether any holder is a GC root, a static
           field, or one of the user's own classes. Stop when we reach one.

Memory stays bounded (roots + layouts + a capped frontier); the cost is a handful
of streaming passes, which is why the caller gates this behind a file-size limit.
The result is a retention chain like:

    com.example.Order  ←  java.lang.Object[]  ←  com.example.OrderCache.entries

where the last link is an instance/static field in the user's code, resolved to a
file and line. This is heuristic (type-level, sampled — not exact retained size),
but it points at the holding field, which is what a developer needs to fix a leak.
"""
from __future__ import annotations
import os
from collections import Counter
from typing import BinaryIO, Dict, List, Optional, Set, Tuple

from ..schemas import Finding, Severity, SourceLocation, SourceSnippet
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
                on_objarray(oid, elem, [reader.id(id_size) for _ in range(n)])
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
        else:
            # Unknown sub-tag — can't compute the rest of the segment safely.
            reader.skip(max(0, seg_end - reader.pos))
            return


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
        self._layout_cache: Dict[int, List[Tuple[int, int]]] = {}
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

    def full_layout(self, cid: int, _seen=None) -> List[Tuple[int, int]]:
        if cid in self._layout_cache:
            return self._layout_cache[cid]
        _seen = _seen or set()
        if cid in _seen:
            return []
        _seen.add(cid)
        own = self.layouts_own.get(cid, [])
        sup = self.supers.get(cid, 0)
        res = list(own) + (self.full_layout(sup, _seen) if sup else [])
        self._layout_cache[cid] = res
        return res

    def _refs(self, cid: int, body: bytes):
        pos = 0
        for nid, t in self.full_layout(cid):
            sz = self.id_size if t == 2 else TYPE_SIZES.get(t, 0)
            if pos + sz > len(body):
                break
            if t == 2:
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
                elem_ids = {cid for cid, nm in self.class_name_by_id.items() if nm == base}

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

    # ---- level pass: who references the current frontier? ----
    def holders(self, frontier: Set[int]):
        edges: Counter = Counter()
        terminals: List[Tuple[str, str, str]] = []  # (kind, class, field)
        next_frontier: Set[int] = set()

        def on_inst(oid, cid, body):
            for nid, tgt in self._refs(cid, body):
                if tgt in frontier:
                    edges[(cid, nid)] += 1
                    cname = self.class_name_by_id.get(cid, "?")
                    fname = self.strings.get(nid, "?")
                    if oid in self.static_targets:
                        sc, sf = self.static_targets[oid]
                        terminals.append(("static", sc, sf))
                    elif is_user_code(cname):
                        terminals.append(("user", cname, fname))
                    elif oid in self.roots:
                        terminals.append(("gcroot", cname, fname))
                    elif len(next_frontier) < self.sample_cap:
                        next_frontier.add(oid)

        def on_arr(oid, elem, elems):
            ename = self.class_name_by_id.get(elem, "?") + "[]"
            for tgt in elems:
                if tgt in frontier:
                    edges[(("arr", elem), "[]")] += 1
                    if oid in self.roots:
                        terminals.append(("gcroot", ename, "[]"))
                    elif len(next_frontier) < self.sample_cap:
                        next_frontier.add(oid)
                    break  # one hit per array is enough to enqueue it

        reader, _ = _open(self.fp)
        _walk(reader, self.id_size, on_instance=on_inst, on_objarray=on_arr)
        return edges, terminals, next_frontier

    def _edge_label(self, edge) -> str:
        key, fld = edge
        if isinstance(key, tuple) and key[0] == "arr":
            return self.class_name_by_id.get(key[1], "?") + "[]"
        return f"{self.class_name_by_id.get(key, '?')}.{self.strings.get(fld, '?')}"

    @staticmethod
    def _pick_terminal(terms: List[Tuple[str, str, str]]):
        for kind in ("static", "user", "gcroot"):
            of_kind = [t for t in terms if t[0] == kind]
            if of_kind:
                return Counter(of_kind).most_common(1)[0][0]
        return None

    def trace(self, leaf: str):
        """Return (chain:list[str], terminal:(kind,class,field)|None)."""
        frontier = set(self.sample(leaf))
        if not frontier:
            return None, None
        chain = [leaf]
        terminal = None
        for _ in range(self.max_levels):
            if not frontier:
                break
            edges, terms, nf = self.holders(frontier)
            term = self._pick_terminal(terms)
            if term and term[0] in ("static", "user"):
                chain.append(f"{term[1]}.{term[2]}")
                terminal = term
                break
            if not edges:
                if term and term[0] == "gcroot":
                    chain.append(f"a GC root ({term[1]})")
                    terminal = term
                break
            best = edges.most_common(1)[0][0]
            chain.append(self._edge_label(best))
            frontier = nf
            if not frontier:
                if term and term[0] == "gcroot":
                    chain.append(f"a GC root ({term[1]})")
                    terminal = term
                break
        return chain, terminal


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
        severity = Severity.CRITICAL if kind == "user" else Severity.WARNING
        holder_desc = (
            f"the {'static ' if kind == 'static' else ''}field "
            f"`{cls.rsplit('.', 1)[-1]}.{field}` in your code"
        )
    else:
        holder_desc = f"`{holder_label}`"

    return Finding(
        severity=severity,
        title=f"Retention path: `{leaf_simple}` is held by {holder_desc}",
        description=(
            f"Tracing the heap's reference graph back from `{leaf_class}` (the top memory "
            f"consumer) shows what is keeping it alive:\n\n    {arrow_chain}\n\n"
            "Read it right-to-left: the rightmost item is the GC root or field that anchors "
            "the whole structure in memory. If that anchor keeps growing, so does the heap. "
            "(This is a sampled, type-level path — it names the holding field, not an exact "
            "retained size.)"
        ),
        impact=(
            "Everything reachable only through this path stays in memory for as long as the "
            "anchor holds it. An anchor that accumulates entries is a leak: the heap fills, "
            "GC works harder for less, and the JVM eventually throws OutOfMemoryError."
        ),
        likely_cause=(
            f"{holder_desc[0].upper() + holder_desc[1:]} is accumulating `{leaf_simple}` "
            "instances without bound — a cache/registry that's added to but never evicted, "
            "or a structure that's never cleared."
        ),
        evidence=[f"retention chain: {arrow_chain}"]
                 + ([f"anchor resolved to {locations[0].repo_path}:{locations[0].line}"]
                    if locations and locations[0].repo_path else []),
        remediation=(
            "Bound or clear the anchor field shown below. If it's a cache, give it a size/time "
            "limit (Caffeine, Guava `CacheBuilder`) or evict explicitly; if it's a registry, "
            "make sure every add has a matching remove; if it's a buffer, release it when done."
        ),
        category="memory",
        source_locations=locations,
    )
