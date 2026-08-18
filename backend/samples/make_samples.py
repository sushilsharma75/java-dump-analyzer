#!/usr/bin/env python3
"""
Generate ready-to-upload sample data for a manual end-to-end walkthrough.

Produces, next to this script:
  - order-leak.hprof   a realistic leak: com.example.Order is the single biggest
                       consumer of heap, retained through a real HashMap (Node[]
                       table -> Node.value) held by the *instance* field
                       OrderCache.entries, where the OrderCache is kept alive by a
                       live worker thread (a GC root) rather than a static field.
                       That makes the retention tracer climb to OrderCache.entries
                       and report it as a user-code anchor. A second, distinct leak
                       shape — a *static* cache via SessionRegistry.SESSIONS — is
                       there to exercise the static-field finder.
  - baseline.hprof     a healthy-looking dump (no dominant class, no static caches)
                       to show the "no obvious red flags" path for contrast.
  - order-leak-src.zip the com.example mini-app source (zip of ./src) to attach so
                       findings resolve to file:line.

Run:  python make_samples.py
"""
import sys
import struct
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "tests"))  # reuse the test hprof builder
from hprof_builder import HprofBuilder, INT, LONG, OBJECT, BYTE  # noqa: E402


def _node_body(b: HprofBuilder, hashval: int, key: int, value: int, nxt: int = 0) -> bytes:
    """Body for a HashMap.Node-like layout: int hash, then 3 object refs."""
    return struct.pack(">i", hashval) + b._id(key) + b._id(value) + b._id(nxt)


def _map_with_entries(b, map_cls, node_cls, value_field, entry_values):
    """Build a HashMap-like structure holding entry_values; return the map object id.

    map layout: (int size, object table); node layout: (int hash, object key,
    object <value_field>, object next). Mirrors real JDK internals closely enough
    that the retention tracer climbs value -> Node -> Node[] -> map.table -> map.
    """
    long_cls = b.load_class("java.lang.Long")
    nodes = []
    for k, val in enumerate(entry_values):
        key = b.instance(long_cls, body=struct.pack(">q", k))
        nodes.append(b.instance(node_cls, body=_node_body(b, k, key, val)))
    table = b.object_array(node_cls, nodes)
    return b.instance(map_cls, body=struct.pack(">i", len(entry_values)) + b._id(table))


def build_order_leak(n_orders: int = 3000, n_sessions: int = 120) -> bytes:
    b = HprofBuilder()

    order = b.load_class("com.example.Order")
    ocache = b.load_class("com.example.OrderCache")
    sreg = b.load_class("com.example.SessionRegistry")
    session = b.load_class("com.example.Session")
    hashmap = b.load_class("java.util.HashMap")
    hnode = b.load_class("java.util.HashMap$Node")
    chm = b.load_class("java.util.concurrent.ConcurrentHashMap")
    cnode = b.load_class("java.util.concurrent.ConcurrentHashMap$Node")
    string = b.load_class("java.lang.String")
    b.load_class("java.lang.Long")

    # A realistically chunky Order (4 longs + 4 object refs = 64-byte body, ~80B
    # shallow). Bigger than its own HashMap$Node entries, so the Order *instances*
    # — not the map internals or any byte[] — are the single largest line item.
    b.class_dump(order, instance_fields=[
        ("id", LONG), ("customerId", LONG), ("amountCents", LONG), ("createdAt", LONG),
        ("customer", OBJECT), ("status", OBJECT), ("shipTo", OBJECT), ("items", OBJECT),
    ])
    b.class_dump(session, instance_fields=[("id", OBJECT), ("payload", OBJECT)])
    b.class_dump(string, instance_fields=[("value", OBJECT), ("hash", INT)])
    b.class_dump(b._class_id["java/lang/Long"], instance_fields=[("value", LONG)])
    b.class_dump(hnode, instance_fields=[("hash", INT), ("key", OBJECT),
                                         ("value", OBJECT), ("next", OBJECT)])
    b.class_dump(cnode, instance_fields=[("hash", INT), ("key", OBJECT),
                                         ("val", OBJECT), ("next", OBJECT)])
    b.class_dump(hashmap, instance_fields=[("size", INT), ("table", OBJECT)])
    b.class_dump(chm, instance_fields=[("sizeCtl", INT), ("table", OBJECT)])
    b.class_dump(ocache, instance_fields=[("entries", OBJECT)])

    # The leak: many Orders, retained through a HashMap held by OrderCache.entries.
    def order_body(i: int) -> bytes:
        longs = struct.pack(">qqqq", i, i % 1000, (i * 99) % 100_000, 1_700_000_000_000 + i)
        return longs + b._id(0) * 4   # customer/status/shipTo/items left null

    orders = [b.instance(order, body=order_body(i)) for i in range(n_orders)]
    orders_map = _map_with_entries(b, hashmap, hnode, "value", orders)
    cache = b.instance(ocache, refs=[orders_map])  # OrderCache.entries -> map

    # The static cache leak: Sessions retained through a ConcurrentHashMap held by
    # the static field SessionRegistry.SESSIONS.
    sessions = []
    for _ in range(n_sessions):
        payload = b.primitive_array(BYTE, 64)
        sessions.append(b.instance(session, body=b._id(0) + b._id(payload)))
    sessions_map = _map_with_entries(b, chm, cnode, "val", sessions)
    b.class_dump(sreg, static_object_fields=[("SESSIONS", sessions_map)])

    # GC roots, like a real dump. The OrderCache is anchored by a live worker
    # thread (NOT a static field), so the tracer climbs to the instance field
    # OrderCache.entries instead of collapsing the path onto a static holder —
    # keeping it distinct from the SessionRegistry.SESSIONS static leak below.
    b.gc_root(cache, "thread_obj")
    b.gc_root(sessions_map, "sticky_class")
    return b.build()


def build_baseline(per_class: int = 300) -> bytes:
    """A balanced dump: several classes, none dominant, no static caches."""
    b = HprofBuilder()
    classes = {
        "com.example.Order": [("id", LONG), ("customer", OBJECT)],
        "com.example.Session": [("id", OBJECT), ("payload", OBJECT)],
        "com.example.Row": [("id", LONG)],
        "java.lang.Long": [("value", LONG)],
    }
    for name, fields in classes.items():
        cid = b.load_class(name)
        b.class_dump(cid, instance_fields=fields)
    for name, fields in classes.items():
        cid = b._class_id[name.replace(".", "/")]
        width = sum(8 for _ in fields)
        for _ in range(per_class):
            b.instance(cid, body=b"\x00" * width)
    return b.build()


def build_gc_log(n: int = 48, heap_mb: int = 2048) -> str:
    """A G1 unified-logging GC log matching the order-leak story: the post-GC live
    set ratchets upward (Orders accumulating in OrderCache.entries), pauses grow as
    the heap fills, and it ends in mixed + Full GCs — the run-up to OutOfMemoryError.
    Deterministic so the sample is reproducible."""
    lines: List[str] = []
    after = 80.0
    t = 2.0
    dt = 240.0 / n
    for i in range(n):
        before = min(after + 190, heap_mb - 8)
        after = min(after + 34, heap_mb * 0.95)        # the climbing floor = the leak
        pause = 6.0 + (after / heap_mb) * 40.0          # pauses worsen as heap fills
        phase = "Pause Young (Mixed)" if i and i % 12 == 0 else "Pause Young (Normal)"
        cause = "G1 Evacuation Pause"
        lines.append(f"[{t:.3f}s][info][gc] GC({i}) {phase} ({cause}) "
                     f"{int(before)}M->{int(after)}M({heap_mb}M) {pause:.1f}ms")
        t += dt
    # The collector loses the race: a couple of back-to-back Full GCs that barely help.
    for j in range(2):
        lines.append(f"[{t:.3f}s][info][gc] GC({n + j}) Pause Full (G1 Compaction Pause) "
                     f"(G1 Evacuation Pause) {heap_mb - 12}M->{heap_mb - 60}M({heap_mb}M) 1180.0ms")
        t += dt
    return "\n".join(lines) + "\n"


def zip_source(out: Path) -> None:
    src = HERE / "src"
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(src.rglob("*")):
            if p.is_file():
                z.write(p, p.relative_to(src).as_posix())


def main() -> None:
    (HERE / "order-leak.hprof").write_bytes(build_order_leak())
    (HERE / "baseline.hprof").write_bytes(build_baseline())
    (HERE / "order-leak-gc.log").write_text(build_gc_log())
    zip_source(HERE / "order-leak-src.zip")
    for f in ("order-leak.hprof", "baseline.hprof", "order-leak-gc.log", "order-leak-src.zip"):
        size = (HERE / f).stat().st_size
        print(f"  wrote {f:24s} {size/1024:8.1f} KB")
    print("Done. See samples/README.md for the walkthrough.")


if __name__ == "__main__":
    main()
