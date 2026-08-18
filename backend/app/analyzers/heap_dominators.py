"""
Dominator tree + exact retained sizes — the core Eclipse MAT primitive, in process.

Shallow size says how big an object is; *retained* size says how much heap would be
freed if it were collected — the number a leak investigation actually needs, and the
one this tool was previously honest about not having. The classic way to get it is
MAT's dominator tree: object D dominates object O when every path from the GC roots
to O passes through D, and an object's retained set is exactly the subtree it
dominates.

This module builds the full object graph (two streaming passes over the file), runs
the Lengauer–Tarjan algorithm to compute immediate dominators, and folds shallow
sizes up the dominator tree. Within its size gate the numbers are EXACT — the same
retained sizes MAT reports — not sampled or heuristic.

The cost is memory proportional to the object count (every other analyzer in this
package is memory-bounded regardless of dump size). That is why this is gated to
dumps ≤512MB by default: raise HEAP_DOMINATOR_MAX_BYTES to opt a bigger dump in
(expect roughly 2-4x the dump size in RAM), or set HEAP_DOMINATOR=0 to disable.
Above the gate the heuristic retention tracer (heap_graph) still runs.

Three MAT-parity reports fall out of the same graph:
  * Biggest objects by retained size — the top level of the dominator tree
  * Leak suspects — a dominator retaining ≥20% of the reachable heap (and ≥1MB),
    with its accumulation point (the deepest object still holding most of it)
  * Unreachable objects — present in the dump but not reachable from any GC root
    (dumps taken without live=true keep garbage that merely hasn't been collected)
"""
from __future__ import annotations
import os
import struct
from dataclasses import dataclass, field
from typing import BinaryIO, Callable, Dict, List, Optional, Set, Tuple

from ..schemas import DominatorEntry, Finding, Severity
from .heap_dump import (
    _Reader, _normalize_class_name, TYPE_SIZES, _PRIM_ARRAY_NAMES,
    TAG_UTF8, TAG_LOAD_CLASS, TAG_HEAP_DUMP, TAG_HEAP_DUMP_SEGMENT,
    HEAP_CLASS_DUMP, HEAP_INSTANCE_DUMP, HEAP_OBJECT_ARRAY_DUMP,
    HEAP_PRIMITIVE_ARRAY_DUMP, HEAP_ROOT_UNKNOWN, HEAP_ROOT_JNI_GLOBAL,
    HEAP_ROOT_JNI_LOCAL, HEAP_ROOT_JAVA_FRAME, HEAP_ROOT_NATIVE_STACK,
    HEAP_ROOT_STICKY_CLASS, HEAP_ROOT_THREAD_BLOCK, HEAP_ROOT_MONITOR_USED,
    HEAP_ROOT_THREAD_OBJ,
)
from .heap_graph import _open
from .heap_sizing import SizeModel, size_model

# A "leak suspect" must retain at least this share of the reachable heap AND this
# many absolute bytes. The floor keeps tiny heaps (and unit-test fixtures) from
# producing alarming findings about kilobytes.
_SUSPECT_MIN_FRACTION = 0.20
_SUSPECT_MIN_BYTES = 1 << 20   # 1MB
# Descend the dominator tree while a single child still retains this share of its
# parent — the walk ends at MAT's "accumulation point".
_ACCUMULATION_FRACTION = 0.8


def dominator_max_bytes() -> int:
    """File-size ceiling for exact retained-size computation (see module docstring)."""
    if os.environ.get("HEAP_DOMINATOR", "1") in ("0", "", "false", "False"):
        return 0
    try:
        return int(os.environ.get("HEAP_DOMINATOR_MAX_BYTES", str(512 * 1024 * 1024)))
    except ValueError:
        return 512 * 1024 * 1024


@dataclass
class RetainedResult:
    entries: List[DominatorEntry] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    reachable_bytes: int = 0
    unreachable_count: int = 0
    unreachable_bytes: int = 0
    object_count: int = 0


def _walk(fp: BinaryIO,
          on_class: Optional[Callable] = None,
          on_instance: Optional[Callable] = None,
          on_objarr: Optional[Callable] = None,
          on_primarr: Optional[Callable] = None,
          on_root: Optional[Callable] = None,
          on_utf8: Optional[Callable] = None,
          on_load_class: Optional[Callable] = None) -> int:
    """One streaming pass over every record. Instance/array callbacks receive the
    reader positioned at the payload and MUST consume exactly `nbytes` (or return
    False to have it skipped). Returns id_size."""
    reader, id_size = _open(fp)
    rid = reader.u8 if id_size == 8 else reader.u4

    while True:
        tb = reader.read(1)
        if not tb:
            break
        tag = tb[0]
        try:
            reader.u4()
            length = reader.u4()
        except struct.error:
            break

        if tag == TAG_UTF8:
            if length < id_size:
                reader.skip(length)
                continue
            sid = rid()
            if on_utf8:
                on_utf8(sid, reader.read(length - id_size))
            else:
                reader.skip(length - id_size)
        elif tag == TAG_LOAD_CLASS:
            reader.u4(); cid = rid(); reader.u4(); nid = rid()
            if on_load_class:
                on_load_class(cid, nid)
        elif tag in (TAG_HEAP_DUMP, TAG_HEAP_DUMP_SEGMENT):
            end = reader.pos + length
            while reader.pos < end:
                t = reader.u1()
                if t == HEAP_CLASS_DUMP:
                    cid = rid(); reader.u4()
                    sup = rid()
                    reader.skip(5 * id_size); reader.u4()
                    for _ in range(reader.u2()):          # constant pool
                        reader.u2(); ty = reader.u1()
                        reader.skip(id_size if ty == 2 else TYPE_SIZES.get(ty, 0))
                    statics: List[int] = []
                    for _ in range(reader.u2()):          # static fields
                        reader.skip(id_size); ty = reader.u1()
                        if ty == 2:
                            v = rid()
                            if v:
                                statics.append(v)
                        else:
                            reader.skip(TYPE_SIZES.get(ty, 0))
                    ftypes: List[int] = []
                    for _ in range(reader.u2()):          # instance fields
                        reader.skip(id_size); ftypes.append(reader.u1())
                    if on_class:
                        on_class(cid, sup, ftypes, statics)
                elif t == HEAP_INSTANCE_DUMP:
                    oid = rid(); reader.u4(); cid = rid(); nb = reader.u4()
                    if not (on_instance and on_instance(oid, cid, nb, reader)):
                        reader.skip(nb)
                elif t == HEAP_OBJECT_ARRAY_DUMP:
                    oid = rid(); reader.u4(); n = reader.u4(); ecid = rid()
                    if not (on_objarr and on_objarr(oid, n, ecid, reader)):
                        reader.skip(n * id_size)
                elif t == HEAP_PRIMITIVE_ARRAY_DUMP:
                    oid = rid(); reader.u4(); n = reader.u4(); et = reader.u1()
                    if on_primarr:
                        on_primarr(oid, n, et)
                    reader.skip(n * TYPE_SIZES.get(et, 0))
                elif t in (HEAP_ROOT_UNKNOWN, HEAP_ROOT_STICKY_CLASS, HEAP_ROOT_MONITOR_USED):
                    r = rid()
                    if on_root:
                        on_root(r)
                elif t == HEAP_ROOT_JNI_GLOBAL:
                    r = rid(); rid()
                    if on_root:
                        on_root(r)
                elif t in (HEAP_ROOT_JNI_LOCAL, HEAP_ROOT_JAVA_FRAME, HEAP_ROOT_THREAD_OBJ):
                    r = rid(); reader.u4(); reader.u4()
                    if on_root:
                        on_root(r)
                elif t in (HEAP_ROOT_NATIVE_STACK, HEAP_ROOT_THREAD_BLOCK):
                    r = rid(); reader.u4()
                    if on_root:
                        on_root(r)
                else:
                    reader.skip(end - reader.pos)
                    break
        else:
            reader.skip(length)
    return id_size


def compute_retained(fp: BinaryIO, top_n: int = 25,
                     model: Optional[SizeModel] = None) -> RetainedResult:
    """Build the object graph, compute immediate dominators + retained sizes.

    `model` must be the same layout the histogram used, or the two halves of the
    report will disagree about how big the same object is."""
    # ---- Pass 1: class layouts, static refs, GC roots, name tables ----
    strings: Dict[int, str] = {}
    cls_name_id: Dict[int, int] = {}
    class_info: Dict[int, Tuple[int, List[int], List[int]]] = {}  # cid -> (super, ftypes, static refs)
    roots: Set[int] = set()

    id_size = _walk(
        fp,
        on_class=lambda cid, sup, ft, st: class_info.__setitem__(cid, (sup, ft, st)),
        on_root=roots.add,
        on_utf8=lambda sid, raw: strings.__setitem__(sid, raw.decode("utf-8", "replace")),
        on_load_class=lambda cid, nid: cls_name_id.__setitem__(cid, nid),
    )
    idfmt = ">Q" if id_size == 8 else ">I"
    if model is None:
        model = size_model(id_size, _file_size(fp))

    # Byte offsets of the object-typed instance fields, per class (own fields first,
    # then the superclass chain — the order hprof packs values in).
    offsets_cache: Dict[int, List[int]] = {}

    def obj_offsets(cid: int) -> List[int]:
        got = offsets_cache.get(cid)
        if got is not None:
            return got
        offs: List[int] = []
        off = 0
        c = cid
        seen: Set[int] = set()
        while c and c in class_info and c not in seen:
            seen.add(c)
            sup, ftypes, _ = class_info[c]
            for ty in ftypes:
                if ty == 2:
                    offs.append(off)
                    off += id_size
                else:
                    off += TYPE_SIZES.get(ty, 0)
            c = sup
        offsets_cache[cid] = offs
        return offs

    # ---- Pass 2: nodes + edges ----
    # Node 0 is a virtual super-root that points at every GC root and every class
    # (classes hold static state and are roots in the sticky-class sense).
    oid_idx: Dict[int, int] = {}
    shallow: List[int] = [0]
    kinds: List[int] = [3]      # 0 instance, 1 object array, 2 prim array, 3 class
    keys: List[int] = [0]       # class id / element class id / prim etype
    oids: List[int] = [0]

    def reg(oid: int, sh: int, kd: int, ky: int) -> int:
        i = oid_idx.get(oid)
        if i is None:
            i = len(shallow)
            oid_idx[oid] = i
            shallow.append(sh); kinds.append(kd); keys.append(ky); oids.append(oid)
        return i

    for cid in class_info:
        reg(cid, 0, 3, cid)

    e_src: List[int] = []   # raw oid pairs; resolved to indices after the pass
    e_dst: List[int] = []

    def on_instance(oid: int, cid: int, nb: int, reader: _Reader) -> bool:
        offs = obj_offsets(cid)
        reg(oid, model.instance_size(nb, len(offs), id_size), 0, cid)
        if not offs or not nb:
            return False        # let the walker skip the payload
        body = reader.read(nb)
        for off in offs:
            if off + id_size <= nb:
                (d,) = struct.unpack_from(idfmt, body, off)
                if d:
                    e_src.append(oid); e_dst.append(d)
        return True

    def on_objarr(oid: int, n: int, ecid: int, reader: _Reader) -> bool:
        reg(oid, model.object_array_size(n), 1, ecid)
        raw = reader.read(n * id_size)
        for j in range(n):
            (d,) = struct.unpack_from(idfmt, raw, j * id_size)
            if d:
                e_src.append(oid); e_dst.append(d)
        return True

    def on_primarr(oid: int, n: int, et: int) -> None:
        reg(oid, model.prim_array_size(n, TYPE_SIZES.get(et, 0)), 2, et)

    _walk(fp, on_instance=on_instance, on_objarr=on_objarr, on_primarr=on_primarr)

    # Static-field edges: class object -> referenced value.
    for cid, (_sup, _ft, statics) in class_info.items():
        for v in statics:
            e_src.append(cid); e_dst.append(v)

    # Resolve edges to node indices; drop references to objects not in the dump.
    src: List[int] = []
    dst: List[int] = []
    for s, d in zip(e_src, e_dst):
        si = oid_idx.get(s)
        di = oid_idx.get(d)
        if si is not None and di is not None:
            src.append(si); dst.append(di)
    del e_src, e_dst
    for r in roots:
        ri = oid_idx.get(r)
        if ri is not None:
            src.append(0); dst.append(ri)
    for cid in class_info:
        src.append(0); dst.append(oid_idx[cid])

    n_nodes = len(shallow)
    pre, verts, idom = _lengauer_tarjan(n_nodes, src, dst)

    # ---- Retained sizes: fold shallow sizes up the dominator tree ----
    # idom is always a proper DFS ancestor, so reverse preorder visits every child
    # before its dominator.
    retained = shallow[:]
    for i in range(len(verts) - 1, 0, -1):
        w = verts[i]
        retained[idom[w]] += retained[w]
    reachable_bytes = retained[0]

    unreachable_count = 0
    unreachable_bytes = 0
    for i in range(1, n_nodes):
        if pre[i] == -1 and kinds[i] != 3:
            unreachable_count += 1
            unreachable_bytes += shallow[i]

    # ---- Reports ----
    def cname(cid: int) -> str:
        nid = cls_name_id.get(cid)
        return (_normalize_class_name(strings.get(nid, f"<class@{cid:x}>"))
                if nid else f"<class@{cid:x}>")

    def node_name(i: int) -> str:
        kd = kinds[i]; ky = keys[i]
        if kd == 0:
            return cname(ky)
        if kd == 1:
            n = cname(ky)
            return n if n.endswith("[]") else n + "[]"
        if kd == 2:
            return _PRIM_ARRAY_NAMES.get(ky, f"<prim:{ky}>[]")
        return f"class {cname(ky)}"

    kids: Dict[int, List[int]] = {}
    for i in range(1, len(verts)):
        w = verts[i]
        kids.setdefault(idom[w], []).append(w)

    def accumulation_path(v: int) -> List[int]:
        """Descend while one child still retains most of the parent."""
        path = [v]
        cur = v
        while len(path) < 8:
            ch = kids.get(cur)
            if not ch:
                break
            best = max(ch, key=lambda c: retained[c])
            if retained[best] < _ACCUMULATION_FRACTION * retained[cur]:
                break
            cur = best
            path.append(cur)
        return path

    top_level = sorted(kids.get(0, []), key=lambda v: -retained[v])
    entries: List[DominatorEntry] = []
    for v in top_level[:top_n]:
        if retained[v] <= 0:
            break
        entries.append(DominatorEntry(
            class_name=node_name(v),
            object_id=hex(oids[v]),
            shallow_bytes=shallow[v],
            retained_bytes=retained[v],
            pct_of_reachable=round(retained[v] / reachable_bytes * 100, 1) if reachable_bytes else 0.0,
            chain=[node_name(p) for p in accumulation_path(v)[1:]][:5],
        ))

    findings: List[Finding] = []
    threshold = max(int(_SUSPECT_MIN_FRACTION * reachable_bytes), _SUSPECT_MIN_BYTES)
    for v in top_level[:3]:
        if retained[v] < threshold:
            break
        path = accumulation_path(v)
        acc = path[-1]
        pct = retained[v] / reachable_bytes * 100 if reachable_bytes else 0
        chain_txt = " → ".join(node_name(p) for p in path)
        is_class_node = kinds[v] == 3
        findings.append(Finding(
            severity=Severity.CRITICAL if pct >= 50 else Severity.WARNING,
            title=f"Leak suspect: `{node_name(v)}` retains {_fmt_bytes(retained[v])} ({pct:.0f}% of reachable heap)",
            description=(
                "Computed from the dominator tree (exact, not sampled): every path from "
                "the GC roots to those bytes passes through this "
                + ("class's static fields" if is_class_node else "object")
                + f", so collecting it would free all {_fmt_bytes(retained[v])}. "
                + (f"The accumulation point — the deepest single object still holding "
                   f"most of it — is `{node_name(acc)}`."
                   if acc != v else "")
            ),
            impact=(
                "If this retained set grows over time the heap fills and the JVM dies "
                "with OutOfMemoryError; pair with a GC log to confirm growth."
            ),
            likely_cause=(
                "A static collection without eviction" if is_class_node else
                "A long-lived object holding an ever-growing collection or buffer"
            ),
            evidence=[
                f"retained {_fmt_bytes(retained[v])} ({pct:.0f}% of {_fmt_bytes(reachable_bytes)} reachable)",
                f"shallow {_fmt_bytes(shallow[v])}",
                f"ownership: {chain_txt}",
            ],
            remediation=(
                "Inspect the accumulation point's contents (sizes and example values are "
                "in the histogram and waste reports). Bound the collection (Caffeine/"
                "maximumSize, expireAfterWrite) or release the reference when done."
            ),
            category="memory",
        ))

    if unreachable_bytes > max(reachable_bytes // 5, _SUSPECT_MIN_BYTES):
        findings.append(Finding(
            severity=Severity.INFO,
            title=f"{_fmt_bytes(unreachable_bytes)} of unreachable objects in the dump",
            description=(
                f"{unreachable_count:,} objects ({_fmt_bytes(unreachable_bytes)}) are not "
                "reachable from any GC root — garbage that hadn't been collected when the "
                "dump was taken. They inflate the file but are NOT a leak."
            ),
            remediation=(
                "Capture with `jmap -dump:live,…` or `jcmd GC.heap_dump` (which runs a "
                "full GC first) to exclude them and shrink the dump."
            ),
            category="memory",
        ))

    return RetainedResult(
        entries=entries,
        findings=findings,
        reachable_bytes=reachable_bytes,
        unreachable_count=unreachable_count,
        unreachable_bytes=unreachable_bytes,
        object_count=n_nodes - 1,
    )


def _lengauer_tarjan(n_nodes: int, src: List[int], dst: List[int]
                     ) -> Tuple[List[int], List[int], List[int]]:
    """Immediate dominators of the flowgraph rooted at node 0.

    Classic Lengauer–Tarjan with path-compression EVAL, fully iterative (object
    graphs contain million-deep chains — linked lists — that would blow Python's
    recursion limit). Returns (preorder numbers, preorder vertex list, idom).
    Unreachable nodes keep pre == -1.
    """
    m = len(src)

    # CSR forward adjacency
    out_start = [0] * (n_nodes + 1)
    for s in src:
        out_start[s + 1] += 1
    for i in range(n_nodes):
        out_start[i + 1] += out_start[i]
    succ = [0] * m
    cur = out_start[:n_nodes]
    for k in range(m):
        s = src[k]
        succ[cur[s]] = dst[k]
        cur[s] += 1

    # CSR predecessors
    in_start = [0] * (n_nodes + 1)
    for d in dst:
        in_start[d + 1] += 1
    for i in range(n_nodes):
        in_start[i + 1] += in_start[i]
    preds = [0] * m
    cur = in_start[:n_nodes]
    for k in range(m):
        d = dst[k]
        preds[cur[d]] = src[k]
        cur[d] += 1

    # Iterative DFS preorder from the virtual root
    pre = [-1] * n_nodes
    parent = [0] * n_nodes
    verts = [0]
    pre[0] = 0
    ptr = out_start[:n_nodes]
    stack = [0]
    while stack:
        v = stack[-1]
        advanced = False
        p = ptr[v]
        end = out_start[v + 1]
        while p < end:
            w = succ[p]
            p += 1
            if pre[w] == -1:
                ptr[v] = p
                pre[w] = len(verts)
                verts.append(w)
                parent[w] = v
                stack.append(w)
                advanced = True
                break
        if not advanced:
            ptr[v] = p
            stack.pop()

    semi = pre[:]                     # semidominators, as preorder numbers
    idom = [0] * n_nodes
    ancestor = [-1] * n_nodes         # EVAL forest
    label = list(range(n_nodes))
    bucket: Dict[int, List[int]] = {}

    def _eval(v: int) -> int:
        if ancestor[v] == -1:
            return v
        # path-compress: collect the chain, then relabel top-down
        path = []
        u = v
        while ancestor[ancestor[u]] != -1:
            path.append(u)
            u = ancestor[u]
        for x in reversed(path):
            a = ancestor[x]
            if semi[label[a]] < semi[label[x]]:
                label[x] = label[a]
            ancestor[x] = ancestor[a]
        return label[v]

    for i in range(len(verts) - 1, 0, -1):
        w = verts[i]
        for j in range(in_start[w], in_start[w + 1]):
            v = preds[j]
            if pre[v] == -1:
                continue      # predecessor itself unreachable
            u = _eval(v)
            if semi[u] < semi[w]:
                semi[w] = semi[u]
        bucket.setdefault(verts[semi[w]], []).append(w)
        p = parent[w]
        ancestor[w] = p               # LINK
        blist = bucket.pop(p, None)
        if blist:
            for v in blist:
                u = _eval(v)
                idom[v] = u if semi[u] < semi[v] else p
    for i in range(1, len(verts)):
        w = verts[i]
        if idom[w] != verts[semi[w]]:
            idom[w] = idom[idom[w]]
    idom[0] = 0
    return pre, verts, idom


def _file_size(fp: BinaryIO) -> int:
    try:
        cur = fp.tell()
        fp.seek(0, os.SEEK_END)
        size = fp.tell()
        fp.seek(cur, os.SEEK_SET)
        return size
    except (OSError, AttributeError):
        return 0


def _fmt_bytes(n: int) -> str:
    v = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(v) < 1024:
            return f"{v:.1f} {unit}" if unit != "B" else f"{int(v)} B"
        v /= 1024
    return f"{v:.1f} PB"
