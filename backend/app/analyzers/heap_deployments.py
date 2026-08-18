"""
Deployment (classloader) and thread attribution for heap dumps.

A heap dump already knows which *artifact* every class came from and which threads
belong to it — the information is just thrown away by a histogram-only analysis.
Two records carry it:

  CLASS_DUMP        …  classloader_id and protection_domain_id per class.
                       The loader id is the identity of a deployed WAR/EAR; the
                       protection domain leads to the CodeSource URL, i.e. the
                       literal `file:/…/myapp.war!/WEB-INF/classes/`.
  ROOT_THREAD_OBJ   …  the object id of every *live* thread, which is what
                       separates running threads from dead `Thread` objects that
                       are still on the heap awaiting collection.

The whole structural analysis rides along on the main parse pass, because HotSpot
emits every CLASS_DUMP (and every ROOT_THREAD_OBJ) *before* the first instance
record. So by the time an instance shows up we already know the full set of
classloader object ids, and a `Thread.contextClassLoader` field can be matched
against it directly — no forward reference, no second pass, no object index. We
retain the field bytes of a small allow-list of classes (ClassLoader/Thread/
ThreadGroup/ProtectionDomain/CodeSource/URL and friends): on a real dump that is
a few dozen objects out of tens of thousands.

What can *not* be done in one pass is the leaf hop `String → byte[]`: the ids of
the strings we want (thread names, the CodeSource URL) are only known once the
object referencing them has been read, and indexing every String in a 25GB heap
is not affordable. Those get `resolve_names()` — two extra skip-only passes that
early-exit once every wanted id is found, and that degrade gracefully: without
them you still get every deployment, labelled by loader class + package prefix
instead of by file path.
"""
from __future__ import annotations
import os
import posixpath
import struct
from collections import Counter, defaultdict
from typing import BinaryIO, Dict, List, Optional, Set, Tuple

from ..schemas import (
    Deployment, DuplicateClass, Finding, HeapThread, Severity, ThreadOwnership,
)
from .source import is_user_code

# Classes whose instance field bytes we keep during the main pass. Everything we
# need to attribute a thread or name a deployment hangs off one of these, and they
# are all rare (a real dump has dozens, not millions).
_RETAIN_EXACT = {
    "java.lang.ThreadGroup",
    "java.lang.Thread$FieldHolder",   # JDK 19+: group/priority/daemon/task moved here
    "java.security.ProtectionDomain",
    "java.security.CodeSource",
    "java.net.URL",
    "java.io.File",
}
# …plus every subclass of these, found via the superclass chain.
_RETAIN_SUPERS = {"java.lang.Thread", "java.lang.ClassLoader"}

# Runaway protection: a dump with a pathological number of threads/loaders should
# degrade, not exhaust memory. Well above any sane app.
_RETAIN_CAP = 200_000

# Loader classes that are the JVM's own, not a deployed artifact.
_SYSTEM_LOADERS = (
    "jdk.internal.loader.ClassLoaders$AppClassLoader",
    "jdk.internal.loader.ClassLoaders$PlatformClassLoader",
    "jdk.internal.loader.ClassLoaders$BootClassLoader",
    "sun.misc.Launcher$AppClassLoader",
    "sun.misc.Launcher$ExtClassLoader",
)
# Loader class-name fragments that mean "this is a deployed webapp".
_WEBAPP_LOADER_HINTS = ("Webapp", "WebApp", "Jasper", "Ear", "Module", "Bundle", "Plugin")

# Thread names owned by the JVM itself — never the application's fault.
_JVM_THREAD_NAMES = (
    "Reference Handler", "Finalizer", "Signal Dispatcher", "Common-Cleaner",
    "Notification Thread", "Service Thread", "Monitor Deflation Thread",
    "Sweeper thread", "VM Thread", "VM Periodic Task Thread", "Attach Listener",
    "process reaper", "GC Thread", "G1 ", "C1 CompilerThread", "C2 CompilerThread",
)


class DeploymentScan:
    """Collector filled by the main parse pass; see module docstring.

    The parser hands us three things as it streams: every CLASS_DUMP header, the
    field bytes of allow-listed instances, and every ROOT_THREAD_OBJ id. Nothing
    here allocates per-instance state for ordinary objects, so the cost on a 25GB
    dump is one set-membership test per instance.
    """

    def __init__(self, id_size: int, strings: Dict[int, str],
                 class_obj_to_name_id: Dict[int, int]) -> None:
        self.id_size = id_size
        self.strings = strings
        self.class_obj_to_name_id = class_obj_to_name_id
        self.class_meta: Dict[int, Tuple[int, int, int]] = {}      # cid -> (super, loader, pd)
        self.class_fields: Dict[int, List[Tuple[int, int]]] = {}   # cid -> [(name_id, type)]
        self.root_thread_oids: Set[int] = set()
        self.retained: Dict[int, Tuple[int, bytes]] = {}           # oid -> (cid, field bytes)
        self._retain_cids: Optional[Set[int]] = None
        self._name_cache: Dict[int, str] = {}
        self.truncated = False

    # ---- fed by the parser ----

    def note_class(self, cid: int, super_id: int, loader_id: int, pd_id: int,
                   fields: List[Tuple[int, int]]) -> None:
        self.class_meta[cid] = (super_id, loader_id, pd_id)
        self.class_fields[cid] = fields
        self._retain_cids = None   # invalidate; rebuilt lazily on the next instance

    def note_thread_root(self, oid: int) -> None:
        self.root_thread_oids.add(oid)

    def note_instance(self, oid: int, cid: int, body: bytes) -> None:
        if len(self.retained) >= _RETAIN_CAP:
            self.truncated = True
            return
        self.retained[oid] = (cid, body)

    @property
    def retain_cids(self) -> Set[int]:
        """Class ids whose instances we keep. Built once, after the CLASS_DUMPs."""
        if self._retain_cids is None:
            self._retain_cids = {cid for cid in self.class_meta if self._wants(cid)}
        return self._retain_cids

    # ---- naming ----

    def class_name(self, cid: int) -> str:
        if cid in self._name_cache:
            return self._name_cache[cid]
        name_id = self.class_obj_to_name_id.get(cid)
        raw = self.strings.get(name_id, "") if name_id else ""
        name = _normalize(raw)
        self._name_cache[cid] = name
        return name

    def _chain(self, cid: int) -> List[str]:
        out: List[str] = []
        seen: Set[int] = set()
        while cid and cid not in seen:
            seen.add(cid)
            out.append(self.class_name(cid))
            cid = self.class_meta.get(cid, (0, 0, 0))[0]
        return out

    def _wants(self, cid: int) -> bool:
        chain = self._chain(cid)
        if not chain:
            return False
        if chain[0] in _RETAIN_EXACT:
            return True
        return any(c in _RETAIN_SUPERS for c in chain)

    def is_thread_class(self, cid: int) -> bool:
        return "java.lang.Thread" in self._chain(cid)

    def is_loader_class(self, cid: int) -> bool:
        return "java.lang.ClassLoader" in self._chain(cid)

    # ---- field decoding ----

    def layout(self, cid: int) -> List[Tuple[str, int]]:
        """Instance-field layout: a class's own declared fields, then its
        superclass's, recursively — the order hprof writes the values in."""
        out: List[Tuple[str, int]] = []
        seen: Set[int] = set()
        while cid and cid not in seen:
            seen.add(cid)
            for name_id, ftype in self.class_fields.get(cid, []):
                out.append((self.strings.get(name_id, "?"), ftype))
            cid = self.class_meta.get(cid, (0, 0, 0))[0]
        return out

    def fields(self, oid: int) -> Dict[str, object]:
        """Decode a retained instance's fields to {name: value}. Object-typed
        fields decode to the referenced object id."""
        entry = self.retained.get(oid)
        if not entry:
            return {}
        cid, raw = entry
        vals: Dict[str, object] = {}
        off = 0
        idfmt = ">Q" if self.id_size == 8 else ">I"
        for fname, ftype in self.layout(cid):
            size = self.id_size if ftype == 2 else _TYPE_SIZES.get(ftype, 0)
            if off + size > len(raw):
                break
            chunk = raw[off:off + size]
            if ftype == 2:
                vals[fname] = struct.unpack(idfmt, chunk)[0]
            elif ftype == 4:
                vals[fname] = bool(chunk[0])
            elif ftype == 10:
                vals[fname] = struct.unpack(">i", chunk)[0]
            elif ftype == 11:
                vals[fname] = struct.unpack(">q", chunk)[0]
            off += size
        return vals


_TYPE_SIZES = {2: 0, 4: 1, 5: 2, 6: 4, 7: 8, 8: 1, 9: 2, 10: 4, 11: 8}


def _normalize(name: str) -> str:
    if not name:
        return ""
    dims = 0
    while name.startswith("["):
        dims += 1
        name = name[1:]
    if name.startswith("L") and name.endswith(";"):
        name = name[1:-1]
    return name.replace("/", ".") + ("[]" * dims)


# --------------------------------------------------------------------------
# Name resolution (the two extra skip-only passes)
# --------------------------------------------------------------------------

def resolve_enabled() -> bool:
    return os.environ.get("HEAP_DEPLOY_RESOLVE", "1") not in ("0", "", "false", "False")


class _Names:
    """Resolved leaves: String oid -> text, and object oid -> class name."""

    def __init__(self) -> None:
        self.text: Dict[int, str] = {}
        self.klass: Dict[int, str] = {}

    def string(self, oid: Optional[int]) -> Optional[str]:
        return self.text.get(oid) if oid else None


def resolve_names(fp: BinaryIO, scan: DeploymentScan,
                  want_strings: Set[int], want_classes: Set[int]) -> _Names:
    """Resolve String oids to text and arbitrary oids to their class name.

    Pass A walks instance headers: for a wanted class-of oid we only need the
    header (class id, no payload); for a wanted String we read the body to learn
    its backing array. Pass B picks up those arrays. Both skip everything else and
    stop the moment nothing is outstanding.
    """
    from .heap_dump import (
        _Reader, TAG_UTF8, TAG_LOAD_CLASS, TAG_HEAP_DUMP, TAG_HEAP_DUMP_SEGMENT,
        HEAP_CLASS_DUMP, HEAP_INSTANCE_DUMP, HEAP_OBJECT_ARRAY_DUMP,
        HEAP_PRIMITIVE_ARRAY_DUMP, HEAP_ROOT_UNKNOWN, HEAP_ROOT_JNI_GLOBAL,
        HEAP_ROOT_JNI_LOCAL, HEAP_ROOT_JAVA_FRAME, HEAP_ROOT_NATIVE_STACK,
        HEAP_ROOT_STICKY_CLASS, HEAP_ROOT_THREAD_BLOCK, HEAP_ROOT_MONITOR_USED,
        HEAP_ROOT_THREAD_OBJ,
    )
    names = _Names()
    if not want_strings and not want_classes:
        return names

    id_size = scan.id_size
    # String bodies are tiny; decode them with String's own layout.
    string_cids = {cid for cid in scan.class_meta
                   if scan.class_name(cid) == "java.lang.String"}

    # -- Pass A: instance headers/bodies --
    string_bodies: Dict[int, bytes] = {}
    outstanding = set(want_strings) | set(want_classes)

    def walk(on_instance, on_prim_array) -> None:
        """Stream every heap sub-record, handing instances/arrays to the callbacks.
        Callbacks return True to request an early stop."""
        fp.seek(0)
        r = _Reader(fp)
        while True:                       # header
            b = r.read(1)
            if not b or b == b"\x00":
                break
        r.u4(); r.u4(); r.u4()
        rid = r.u8 if id_size == 8 else r.u4
        while True:
            tb = r.read(1)
            if not tb:
                return
            tag = tb[0]
            try:
                r.u4()
                length = r.u4()
            except struct.error:
                return
            if tag not in (TAG_HEAP_DUMP, TAG_HEAP_DUMP_SEGMENT):
                r.skip(length)
                continue
            end = r.pos + length
            while r.pos < end:
                t = r.u1()
                if t == HEAP_INSTANCE_DUMP:
                    oid = rid(); r.u4(); cid = rid(); nbytes = r.u4()
                    if on_instance(oid, cid, r, nbytes):
                        return
                elif t == HEAP_PRIMITIVE_ARRAY_DUMP:
                    oid = rid(); r.u4(); n = r.u4(); etype = r.u1()
                    nbytes = n * _TYPE_SIZES.get(etype, 0)
                    if on_prim_array(oid, etype, r, nbytes):
                        return
                elif t == HEAP_OBJECT_ARRAY_DUMP:
                    rid(); r.u4(); n = r.u4(); rid()
                    r.skip(n * id_size)
                elif t == HEAP_CLASS_DUMP:
                    _skip_class_dump(r, id_size)
                elif t in (HEAP_ROOT_UNKNOWN, HEAP_ROOT_STICKY_CLASS, HEAP_ROOT_MONITOR_USED):
                    r.skip(id_size)
                elif t == HEAP_ROOT_JNI_GLOBAL:
                    r.skip(2 * id_size)
                elif t in (HEAP_ROOT_JNI_LOCAL, HEAP_ROOT_JAVA_FRAME, HEAP_ROOT_THREAD_OBJ):
                    r.skip(id_size + 8)
                elif t in (HEAP_ROOT_NATIVE_STACK, HEAP_ROOT_THREAD_BLOCK):
                    r.skip(id_size + 4)
                else:
                    r.skip(end - r.pos)
                    break

    def on_instance_a(oid, cid, r, nbytes):
        if oid in outstanding:
            if oid in want_classes:
                names.klass[oid] = scan.class_name(cid)
                outstanding.discard(oid)
            if oid in want_strings and cid in string_cids:
                string_bodies[oid] = r.read(nbytes)
                outstanding.discard(oid)
                return not outstanding
            outstanding.discard(oid)
            if not outstanding:
                return True
        r.skip(nbytes)
        return False

    def skip_array(oid, etype, r, nbytes):
        r.skip(nbytes)
        return False

    walk(on_instance_a, skip_array)

    # -- Pass B: the backing arrays of the strings we found --
    want_arrays: Dict[int, Tuple[int, Optional[int]]] = {}   # array oid -> (string oid, coder)
    for soid, body in string_bodies.items():
        cid = next(iter(string_cids), None)
        # Decode against String's layout: `value` (byte[]/char[]) and `coder` (JDK 9+).
        vals = _decode_body(scan, cid, body)
        value_oid = vals.get("value")
        if isinstance(value_oid, int) and value_oid:
            want_arrays[value_oid] = (soid, vals.get("coder"))
    if not want_arrays:
        return names

    pending = set(want_arrays)

    def on_prim_array_b(oid, etype, r, nbytes):
        if oid in pending:
            data = r.read(nbytes)
            soid, coder = want_arrays[oid]
            names.text[soid] = _decode_java_string(data, etype, coder)
            pending.discard(oid)
            return not pending
        r.skip(nbytes)
        return False

    def skip_instance(oid, cid, r, nbytes):
        r.skip(nbytes)
        return False

    walk(skip_instance, on_prim_array_b)
    return names


def _decode_body(scan: DeploymentScan, cid: Optional[int], body: bytes) -> Dict[str, object]:
    if cid is None:
        return {}
    saved = scan.retained.get(-1)
    scan.retained[-1] = (cid, body)
    try:
        return scan.fields(-1)
    finally:
        if saved is None:
            scan.retained.pop(-1, None)
        else:
            scan.retained[-1] = saved


def _decode_java_string(data: bytes, etype: int, coder: Optional[object]) -> str:
    # JDK 8: char[] (UTF-16BE). JDK 9+: byte[] with coder 0=LATIN1, 1=UTF16.
    if etype == 5:
        return data.decode("utf-16-be", "replace")
    if coder == 1:
        return data.decode("utf-16-be", "replace")
    return data.decode("latin-1", "replace")


def _skip_class_dump(r, id_size: int) -> None:
    r.skip(id_size); r.u4()
    r.skip(6 * id_size); r.u4()
    for _ in range(r.u2()):                       # constant pool
        r.u2(); t = r.u1()
        r.skip(id_size if t == 2 else _TYPE_SIZES.get(t, 0))
    for _ in range(r.u2()):                       # static fields
        r.skip(id_size); t = r.u1()
        r.skip(id_size if t == 2 else _TYPE_SIZES.get(t, 0))
    n = r.u2()                                    # instance fields
    r.skip(n * (id_size + 1))


# --------------------------------------------------------------------------
# Analysis
# --------------------------------------------------------------------------

def _artifact_of(code_source: Optional[str]) -> Optional[str]:
    """'file:/opt/tomcat/webapps/billing.war!/WEB-INF/classes/' -> 'billing.war'."""
    if not code_source:
        return None
    path = code_source.split("!", 1)[0]
    for scheme in ("jar:file:", "file:", "jar:"):
        if path.startswith(scheme):
            path = path[len(scheme):]
            break
    path = path.rstrip("/")
    base = posixpath.basename(path)
    if base.endswith((".war", ".ear", ".jar")):
        return base
    return None


def _common_packages(class_names: List[str], limit: int = 3) -> List[str]:
    """The dominant package prefixes a loader loaded — the human label for a
    deployment when no file path resolves."""
    counts: Counter = Counter()
    for name in class_names:
        parts = name.split(".")
        if len(parts) >= 3:
            counts[".".join(parts[:3])] += 1
        elif len(parts) >= 2:
            counts[".".join(parts[:2])] += 1
    return [pkg for pkg, _ in counts.most_common(limit)]


def analyze_deployments(
    scan: DeploymentScan,
    instance_count: Dict[int, int],
    instance_size: Dict[int, int],
    fp: Optional[BinaryIO] = None,
    resolve: bool = True,
) -> Tuple[List[Deployment], ThreadOwnership, List[Finding]]:
    """Turn the raw main-pass capture into deployments, thread ownership, findings."""
    loader_oids = {loader for (_s, loader, _p) in scan.class_meta.values() if loader}
    thread_oids = [oid for oid, (cid, _b) in scan.retained.items()
                   if scan.is_thread_class(cid)]

    # --- what needs resolving from the file (strings, and classes of thread targets)
    want_strings: Set[int] = set()
    want_classes: Set[int] = set()

    # per-class protection domain -> code source URL -> location string
    loader_pd: Dict[int, int] = {}
    for cid, (_s, loader, pd) in scan.class_meta.items():
        if loader and pd and loader not in loader_pd:
            loader_pd[loader] = pd

    loader_location_str: Dict[int, int] = {}
    for loader, pd in loader_pd.items():
        cs = scan.fields(pd).get("codesource")
        if not isinstance(cs, int) or not cs:
            continue
        url = scan.fields(cs).get("location")
        if not isinstance(url, int) or not url:
            continue
        uf = scan.fields(url)
        sid = uf.get("file") or uf.get("path")
        if isinstance(sid, int) and sid:
            loader_location_str[loader] = sid
            want_strings.add(sid)

    # a loader's own context/name field, when it has one (Tomcat & friends)
    loader_name_str: Dict[int, int] = {}
    for loader in loader_oids:
        lf = scan.fields(loader)
        for key in ("contextName", "contextPath", "name"):
            sid = lf.get(key)
            if isinstance(sid, int) and sid:
                loader_name_str[loader] = sid
                want_strings.add(sid)
                break

    # thread name + the Runnable it wraps
    thread_raw: Dict[int, dict] = {}
    for toid in thread_oids:
        cid, _ = scan.retained[toid]
        f = scan.fields(toid)
        holder = f.get("holder")
        hf = scan.fields(holder) if isinstance(holder, int) and holder else {}
        # JDK 19+ moved group/priority/daemon/task into Thread$FieldHolder
        daemon = hf.get("daemon", f.get("daemon"))
        priority = hf.get("priority", f.get("priority"))
        target = hf.get("task", f.get("target"))
        name_sid = f.get("name")
        if isinstance(name_sid, int) and name_sid:
            want_strings.add(name_sid)
        if isinstance(target, int) and target:
            want_classes.add(target)
        thread_raw[toid] = {
            "cid": cid,
            "name_sid": name_sid if isinstance(name_sid, int) else None,
            "daemon": daemon if isinstance(daemon, bool) else None,
            "priority": priority if isinstance(priority, int) else None,
            "target": target if isinstance(target, int) and target else None,
            "tccl": f.get("contextClassLoader"),
        }

    names = _Names()
    if resolve and fp is not None and resolve_enabled():
        try:
            names = resolve_names(fp, scan, want_strings, want_classes)
        except Exception:
            names = _Names()   # best effort — structure still stands

    # --- build deployments
    classes_by_loader: Dict[int, List[int]] = defaultdict(list)
    for cid, (_s, loader, _p) in scan.class_meta.items():
        if loader:
            classes_by_loader[loader].append(cid)

    deployments: List[Deployment] = []
    dep_by_oid: Dict[int, Deployment] = {}
    for loader in sorted(loader_oids):
        cids = classes_by_loader.get(loader, [])
        loader_cls = scan.class_name(scan.retained[loader][0]) if loader in scan.retained else "<unknown>"
        code_source = names.string(loader_location_str.get(loader))
        artifact = _artifact_of(code_source)
        ctx = names.string(loader_name_str.get(loader))
        class_names = [scan.class_name(c) for c in cids]
        is_webapp = (
            any(h in loader_cls for h in _WEBAPP_LOADER_HINTS)
            or bool(artifact and artifact.endswith((".war", ".ear")))
            or bool(code_source and "WEB-INF" in code_source)
        )
        dep = Deployment(
            id=hex(loader),
            loader_class=loader_cls,
            name=ctx or artifact or (class_names and _common_packages(class_names, 1)[:1] or [None])[0],
            code_source=code_source,
            artifact=artifact,
            is_webapp=is_webapp and loader_cls not in _SYSTEM_LOADERS,
            class_count=len(cids),
            instance_count=sum(instance_count.get(c, 0) for c in cids),
            shallow_size_bytes=sum(instance_size.get(c, 0) for c in cids),
            packages=_common_packages(class_names),
        )
        deployments.append(dep)
        dep_by_oid[loader] = dep

    # A deployment is stale when another loader serves the same artifact under the
    # same context name — i.e. a redeploy left the old loader behind.
    groups: Dict[Tuple[Optional[str], Optional[str]], List[Deployment]] = defaultdict(list)
    for dep in deployments:
        if dep.artifact or dep.code_source:
            groups[(dep.artifact or dep.code_source, dep.name)].append(dep)
    for group in groups.values():
        if len(group) > 1:
            for dep in group:
                dep.stale = True

    # Every thread in the JVM inherits the system classloader as its context
    # classloader by default, so a TCCL pointing at one carries no information —
    # it would sweep `main` and the JVM's own threads into a "deployment". TCCL is
    # only a signal when it has been *deliberately* set to a custom loader, which
    # is exactly what a servlet container does per webapp.
    system_loaders = {oid for oid, dep in dep_by_oid.items()
                      if dep.loader_class in _SYSTEM_LOADERS}

    # --- attribute threads
    threads: List[HeapThread] = []
    for toid, raw in thread_raw.items():
        cid = raw["cid"]
        cls = scan.class_name(cid)
        tname = names.string(raw["name_sid"])
        target_cls = names.klass.get(raw["target"]) if raw["target"] else None

        own_loader = scan.class_meta.get(cid, (0, 0, 0))[1]
        tccl = raw["tccl"] if isinstance(raw["tccl"], int) else 0

        dep_id = None
        attribution = "unattributed"
        if own_loader in dep_by_oid:
            dep_id = dep_by_oid[own_loader].id
            attribution = "own-class"
        elif target_cls and is_user_code(target_cls):
            # the Runnable is application code — find the loader that loaded it
            for cid2, (_s, loader2, _p) in scan.class_meta.items():
                if loader2 in dep_by_oid and scan.class_name(cid2) == target_cls:
                    dep_id = dep_by_oid[loader2].id
                    attribution = "target"
                    break
        if dep_id is None and tccl in dep_by_oid and tccl not in system_loaders:
            dep_id = dep_by_oid[tccl].id
            attribution = "context-classloader"

        threads.append(HeapThread(
            name=tname,
            class_name=cls,
            live=toid in scan.root_thread_oids,
            daemon=raw["daemon"],
            priority=raw["priority"],
            deployment_id=dep_id,
            attribution=attribution,
            target_class=target_cls,
            is_user_code=is_user_code(cls) or bool(target_cls and is_user_code(target_cls)),
        ))

    for t in threads:
        if t.deployment_id and t.deployment_id in {d.id for d in deployments}:
            dep = next(d for d in deployments if d.id == t.deployment_id)
            dep.thread_count += 1
            if t.live:
                dep.live_thread_count += 1

    def _is_jvm_thread(t: HeapThread) -> bool:
        name = t.name or ""
        if any(name.startswith(p) for p in _JVM_THREAD_NAMES):
            return True   # the JVM's own, regardless of what it got attributed to
        return not (t.deployment_id or t.is_user_code)

    # The jvm/application split is over *live* threads: a dead Thread object still
    # on the heap was not "created by" anyone in any sense the user cares about.
    live = [t for t in threads if t.live]
    ownership = ThreadOwnership(
        total_threads=len(threads),
        live_threads=len(live),
        jvm_internal=sum(1 for t in live if _is_jvm_thread(t)),
        application=sum(1 for t in live if not _is_jvm_thread(t)),
        by_deployment={d.id: d.live_thread_count for d in deployments if d.live_thread_count},
        threads=sorted(threads, key=lambda t: (not t.live, t.name or "~")),
    )

    findings = _build_findings(deployments, ownership, scan)
    deployments.sort(key=lambda d: (not d.is_webapp, -d.shallow_size_bytes))
    return deployments, ownership, findings


def find_duplicate_classes(scan: DeploymentScan,
                           deployments: List[Deployment]) -> List[DuplicateClass]:
    """MAT's 'Duplicate Classes' query: the same class name loaded by more than one
    classloader. One or two duplicates are normal in containers (shared APIs);
    a whole application's worth is the redeploy-leak fingerprint."""
    by_name: Dict[str, Set[int]] = defaultdict(set)
    for cid, (_sup, loader, _pd) in scan.class_meta.items():
        name = scan.class_name(cid)
        # Lambdas/proxies/hidden classes get per-loader synthetic names; skip noise.
        if not name or "$$Lambda" in name or "$Proxy" in name or "/0x" in name:
            continue
        by_name[name].add(loader)

    label = {}
    for d in deployments:
        try:
            label[int(d.id, 16)] = d.name or d.id
        except ValueError:
            pass

    out: List[DuplicateClass] = []
    for name, loaders in by_name.items():
        if len(loaders) < 2:
            continue
        out.append(DuplicateClass(
            class_name=name,
            loader_count=len(loaders),
            loaders=[str(label.get(l, "bootstrap" if not l else hex(l)))
                     for l in sorted(loaders)],
        ))
    out.sort(key=lambda d: (-d.loader_count, d.class_name))
    return out[:50]


def _build_findings(deployments: List[Deployment], ownership: ThreadOwnership,
                    scan: DeploymentScan) -> List[Finding]:
    findings: List[Finding] = []
    webapps = [d for d in deployments if d.is_webapp]

    # 1. Stale classloader still pinned by running threads — the redeploy leak.
    stale_with_threads = [d for d in webapps if d.stale and d.live_thread_count]
    for dep in stale_with_threads:
        findings.append(Finding(
            severity=Severity.CRITICAL,
            title=f"Stale classloader for `{dep.artifact or dep.name}` is pinned by {dep.live_thread_count} running thread(s)",
            description=(
                f"More than one live classloader serves `{dep.artifact or dep.name}`, which means a "
                "redeploy left the previous one behind. It cannot be collected because threads it "
                "started are still running — a thread is a GC root, and it keeps its whole "
                "classloader (and every class and static field in that WAR) alive forever."
            ),
            impact=(
                "Every redeploy leaks another full copy of the application's classes and statics. "
                "The heap (and Metaspace) grows with each deploy until the JVM dies — classically "
                "'it OOMs after the third redeploy'."
            ),
            likely_cause=(
                "The webapp starts threads (an ExecutorService, a scheduler, a custom Thread) and "
                "never stops them on shutdown, so they outlive the context that created them."
            ),
            evidence=(
                [f"classloader {dep.id} ({dep.loader_class})",
                 f"{dep.live_thread_count} live thread(s) still attributed to it",
                 f"{dep.class_count} classes, ≈{_fmt_bytes(dep.shallow_size_bytes)} retained"]
                + [f"thread `{t.name}`" for t in ownership.threads
                   if t.deployment_id == dep.id and t.live][:5]
            ),
            remediation=(
                "Stop every thread the webapp starts. Register a `ServletContextListener` (or "
                "`@PreDestroy`) that calls `ExecutorService.shutdownNow()` and joins any custom "
                "threads in `contextDestroyed()`. Threads created with the webapp's classloader as "
                "their context classloader will pin it until they exit."
            ),
            category="classloader-leak",
        ))

    # 2. Several live loaders for one artifact, even without threads pinning them.
    for artifact in {d.artifact for d in webapps if d.stale and d.artifact}:
        group = [d for d in webapps if d.artifact == artifact]
        if any(d.live_thread_count for d in group):
            continue   # already reported above, with the stronger evidence
        findings.append(Finding(
            severity=Severity.WARNING,
            title=f"{len(group)} live classloaders for `{artifact}`",
            description=(
                f"`{artifact}` is loaded by {len(group)} distinct classloaders that are all still "
                "reachable. Only one should be live; the others are leftovers from a redeploy that "
                "something is still holding a reference to."
            ),
            impact="Each leftover loader keeps a full duplicate of the WAR's classes and static state on the heap.",
            likely_cause=(
                "A reference from outside the webapp into it — a ThreadLocal, a JDBC driver "
                "registration, a JMX/MBean listener, a shared static cache holding webapp objects."
            ),
            evidence=[f"{d.id}: {d.class_count} classes, ≈{_fmt_bytes(d.shallow_size_bytes)}" for d in group],
            remediation=(
                "Take a second dump after another redeploy — if the loader count grows, it is a leak. "
                "Common culprits: unremoved ThreadLocals, `DriverManager` registrations, and MBeans "
                "not deregistered in `contextDestroyed()`."
            ),
            category="classloader-leak",
        ))

    # 3. Thread ownership roll-up — the plain answer to "who created these threads".
    if webapps:
        owned = [d for d in webapps if d.live_thread_count]
        if owned:
            findings.append(Finding(
                severity=Severity.INFO,
                title=f"{sum(d.live_thread_count for d in owned)} live thread(s) belong to deployed applications",
                description=(
                    "Threads attributed to a deployment, by the classloader that loaded either the "
                    "thread's own class, the Runnable it wraps, or its context classloader."
                ),
                evidence=[
                    f"{d.name or d.id}: {d.live_thread_count} live thread(s)"
                    + (f" — {d.artifact}" if d.artifact else "")
                    for d in sorted(owned, key=lambda d: -d.live_thread_count)
                ],
                remediation=(
                    "Each of these must be shut down when its application stops, or it will pin the "
                    "classloader on redeploy."
                ),
                category="threads",
            ))

    if scan.truncated:
        findings.append(Finding(
            severity=Severity.INFO,
            title="Deployment analysis was truncated",
            description=(
                f"This dump has more than {_RETAIN_CAP:,} classloader/thread-related objects, so "
                "attribution stopped early to bound memory. Counts below are a lower bound."
            ),
            category="parse",
        ))
    return findings


def _fmt_bytes(n: int) -> str:
    v = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(v) < 1024:
            return f"{v:.1f} {unit}" if unit != "B" else f"{int(v)} B"
        v /= 1024
    return f"{v:.1f} PB"
