#!/usr/bin/env python3
"""
gen_hprof.py - Write a synthetic Java heap dump (HPROF "JAVA PROFILE 1.0.2") of any size,
with planted memory problems and a ground-truth JSON. No JVM required.

    python3 gen_hprof.py --size-gb 6 --out big-heap.hprof

Planted problems (mirrors a real app layout):
  1. Unbounded cache   : HeapDumpGenerator.SESSION_CACHE (HashMap) -> Session -> byte[] payload + ArrayList<Order>
  2. ThreadLocal leak  : worker threads -> ThreadLocalMap -> Entry.value -> large byte[]
  3. Listener leak     : HeapDumpGenerator.LISTENERS (ArrayList) -> lambda -> captured byte[]
  4. Duplicate strings : HeapDumpGenerator.DUP_STRINGS (ArrayList) -> N copies of "ACTIVE"
"""
import argparse
import json
import struct
import time

ID_SIZE = 8
OBJ, BOOL, CHAR, FLOAT, DOUBLE, BYTE, SHORT, INT, LONG = 2, 4, 5, 6, 7, 8, 9, 10, 11
SIZE = {OBJ: 8, BOOL: 1, CHAR: 2, FLOAT: 4, DOUBLE: 8, BYTE: 1, SHORT: 2, INT: 4, LONG: 8}
FMT = {OBJ: 'Q', BOOL: 'B', CHAR: 'H', FLOAT: 'f', DOUBLE: 'd', BYTE: 'b', SHORT: 'h', INT: 'i', LONG: 'q'}

# top-level record tags
TAG_STRING, TAG_LOAD_CLASS, TAG_STACK_TRACE = 0x01, 0x02, 0x05
TAG_HEAP_DUMP_SEGMENT, TAG_HEAP_DUMP_END = 0x1C, 0x2C
# heap-dump sub-record tags
ROOT_STICKY_CLASS, ROOT_THREAD_OBJ = 0x05, 0x08
CLASS_DUMP, INSTANCE_DUMP, OBJ_ARRAY_DUMP, PRIM_ARRAY_DUMP = 0x20, 0x21, 0x22, 0x23

TRACE = 1  # dummy stack-trace serial used for every object, as HotSpot does


class Cls:
    def __init__(self, name, fields=(), sup=None, statics=()):
        self.name, self.fields, self.sup, self.statics = name, list(fields), sup, list(statics)
        self.id = None
        chain, c = [], self
        while c:                      # instance data = own fields, then superclass fields
            chain += c.fields
            c = c.sup
        self.data_len = sum(SIZE[t] for _, t in chain)
        self.inst = struct.Struct('>BQIQI' + ''.join(FMT[t] for _, t in chain))


class HprofWriter:
    def __init__(self, path, segment_bytes=1 << 30):
        self.f = open(path, 'wb', buffering=8 << 20)
        self.seg_limit, self.seg_pos, self.seg_len = segment_bytes, None, 0
        self.strings, self.next_str, self.next_obj = {}, 1, 1 << 36
        self.f.write(b'JAVA PROFILE 1.0.2\x00' + struct.pack('>IQ', ID_SIZE, int(time.time() * 1000)))

    def new_id(self):
        self.next_obj += 16
        return self.next_obj

    def record(self, tag, body):
        assert self.seg_pos is None, 'top-level record inside heap segment'
        self.f.write(struct.pack('>BII', tag, 0, len(body)) + body)

    def string(self, s):
        if s not in self.strings:
            self.strings[s] = self.next_str
            self.record(TAG_STRING, struct.pack('>Q', self.next_str) + s.encode())
            self.next_str += 1
        return self.strings[s]

    # --- heap dump segments (length is back-patched, so nothing big is buffered in memory) ---
    def _open(self):
        self.f.write(struct.pack('>BII', TAG_HEAP_DUMP_SEGMENT, 0, 0))
        self.seg_pos, self.seg_len = self.f.tell() - 4, 0

    def _close(self):
        end = self.f.tell()
        self.f.seek(self.seg_pos)
        self.f.write(struct.pack('>I', self.seg_len))
        self.f.seek(end)
        self.seg_pos = None

    def sub(self, *parts):
        n = sum(len(p) for p in parts)
        if self.seg_pos is None:
            self._open()
        elif self.seg_len + n > self.seg_limit:
            self._close()
            self._open()
        for p in parts:
            self.f.write(p)
        self.seg_len += n

    # --- records ---
    def load_class(self, serial, c):
        self.record(TAG_LOAD_CLASS, struct.pack('>IQIQ', serial, c.id, TRACE, self.strings[c.name]))

    def class_dump(self, c, static_vals=()):
        b = bytearray(struct.pack('>BQIQQQQQQIH', CLASS_DUMP, c.id, TRACE, c.sup.id if c.sup else 0,
                                  0, 0, 0, 0, 0, 16 + c.data_len, 0))
        b += struct.pack('>H', len(c.statics))
        for (name, t), v in zip(c.statics, static_vals):
            b += struct.pack('>QB' + FMT[t], self.strings[name], t, v)
        b += struct.pack('>H', len(c.fields))
        for name, t in c.fields:
            b += struct.pack('>QB', self.strings[name], t)
        self.sub(b)

    def instance(self, c, *vals, oid=None):
        oid = oid or self.new_id()
        self.sub(c.inst.pack(INSTANCE_DUMP, oid, TRACE, c.id, c.data_len, *vals))
        return oid

    def byte_array(self, data, oid=None):
        oid = oid or self.new_id()
        self.sub(struct.pack('>BQIIB', PRIM_ARRAY_DUMP, oid, TRACE, len(data), BYTE), data)
        return oid

    def obj_array(self, arr_cls, ids_bytes, oid=None):
        oid = oid or self.new_id()
        self.sub(struct.pack('>BQIIQ', OBJ_ARRAY_DUMP, oid, TRACE, len(ids_bytes) // 8, arr_cls.id), ids_bytes)
        return oid

    def close(self):
        if self.seg_pos is not None:
            self._close()
        self.record(TAG_HEAP_DUMP_END, b'')
        size = self.f.tell()
        self.f.close()
        return size


def main():
    ap = argparse.ArgumentParser(description='Generate a synthetic HPROF heap dump with planted leaks.')
    ap.add_argument('--size-gb', type=float, default=6, help='target file size (default 6)')
    ap.add_argument('--out', default='big-heap.hprof')
    ap.add_argument('--payload-kb', type=int, default=256, help='byte[] per cached Session')
    ap.add_argument('--orders', type=int, default=50, help='Orders per Session')
    ap.add_argument('--threads', type=int, default=16, help='worker threads with ThreadLocal leak')
    ap.add_argument('--tl-mb', type=int, default=64, help='ThreadLocal buffer per thread')
    ap.add_argument('--listeners', type=int, default=500)
    ap.add_argument('--listener-kb', type=int, default=1024)
    ap.add_argument('--dup-strings', type=int, default=5_000_000)
    a = ap.parse_args()
    target = int(a.size_gb * (1 << 30))
    t0 = time.time()

    # ---------- class model ----------
    Object = Cls('java/lang/Object')
    Class_ = Cls('java/lang/Class', sup=Object)
    B_ARR = Cls('[B', sup=Object)
    OBJ_ARR = Cls('[Ljava/lang/Object;', sup=Object)
    String = Cls('java/lang/String', [('value', OBJ), ('coder', BYTE), ('hash', INT), ('hashIsZero', BOOL)], Object)
    Reference = Cls('java/lang/ref/Reference', [('referent', OBJ)], Object)
    WeakRef = Cls('java/lang/ref/WeakReference', [], Reference)
    Entry = Cls('java/lang/ThreadLocal$ThreadLocalMap$Entry', [('value', OBJ)], WeakRef)
    ENTRY_ARR = Cls('[Ljava/lang/ThreadLocal$ThreadLocalMap$Entry;', sup=Object)
    TLMap = Cls('java/lang/ThreadLocal$ThreadLocalMap', [('table', OBJ), ('size', INT), ('threshold', INT)], Object)
    ThreadLocal = Cls('java/lang/ThreadLocal', [('threadLocalHashCode', INT)], Object)
    Thread = Cls('java/lang/Thread', [('name', OBJ), ('tid', LONG), ('daemon', BOOL), ('threadLocals', OBJ)], Object)
    Node = Cls('java/util/HashMap$Node', [('hash', INT), ('key', OBJ), ('value', OBJ), ('next', OBJ)], Object)
    NODE_ARR = Cls('[Ljava/util/HashMap$Node;', sup=Object)
    HashMap = Cls('java/util/HashMap', [('table', OBJ), ('size', INT), ('modCount', INT),
                                        ('threshold', INT), ('loadFactor', FLOAT)], Object)
    ArrayList = Cls('java/util/ArrayList', [('elementData', OBJ), ('size', INT)], Object)
    Order = Cls('com/example/Order', [('id', LONG), ('status', OBJ), ('amount', DOUBLE)], Object)
    Session = Cls('com/example/Session', [('id', OBJ), ('user', OBJ), ('payload', OBJ), ('orders', OBJ)], Object)
    Lambda = Cls('com/example/HeapDumpGenerator$$Lambda$14', [('arg$1', OBJ)], Object)
    Gen = Cls('com/example/HeapDumpGenerator', sup=Object,
              statics=[('SESSION_CACHE', OBJ), ('BUFFER', OBJ), ('LISTENERS', OBJ), ('DUP_STRINGS', OBJ)])
    classes = [Object, Class_, B_ARR, OBJ_ARR, String, Reference, WeakRef, Entry, ENTRY_ARR, TLMap,
               ThreadLocal, Thread, Node, NODE_ARR, HashMap, ArrayList, Order, Session, Lambda, Gen]

    w = HprofWriter(a.out)

    # ---------- top-level records (must precede heap segments) ----------
    for c in classes:
        c.id = w.new_id()
        w.string(c.name)
        for n, _ in c.fields + c.statics:
            w.string(n)
    for i, c in enumerate(classes, 1):
        w.load_class(i, c)
    w.record(TAG_STACK_TRACE, struct.pack('>III', TRACE, 0, 0))
    for t in range(1 + a.threads):  # main + workers: trace serial TRACE+1+t, thread serial 1+t
        w.record(TAG_STACK_TRACE, struct.pack('>III', TRACE + 1 + t, 1 + t, 0))

    cache_id, tl_id, listeners_id, dups_id = (w.new_id() for _ in range(4))

    # ---------- heap: classes + roots ----------
    for c in classes:
        w.class_dump(c, [cache_id, tl_id, listeners_id, dups_id] if c is Gen else [])
        w.sub(struct.pack('>BQ', ROOT_STICKY_CLASS, c.id))

    def jstr(s):
        return w.instance(String, w.byte_array(s.encode('latin-1')), 0, 0, 0)

    def arraylist(ids, oid=None):
        arr = w.obj_array(OBJ_ARR, struct.pack(f'>{len(ids)}Q', *ids))
        return w.instance(ArrayList, arr, len(ids), oid=oid)

    # ---------- 2. ThreadLocal leak ----------
    tl_hash = 0x61C88647
    w.instance(ThreadLocal, tl_hash, oid=tl_id)
    main_t = w.instance(Thread, jstr('main'), 1, 0, 0)
    w.sub(struct.pack('>BQII', ROOT_THREAD_OBJ, main_t, 1, TRACE + 1))
    tl_buf = bytes(a.tl_mb << 20)
    for i in range(a.threads):
        entry = w.instance(Entry, w.byte_array(tl_buf), tl_id)   # value, then inherited referent
        table = bytearray(16 * 8)
        slot = tl_hash & 15
        table[slot * 8:slot * 8 + 8] = struct.pack('>Q', entry)
        tlmap = w.instance(TLMap, w.obj_array(ENTRY_ARR, bytes(table)), 1, 10)
        t = w.instance(Thread, jstr(f'worker-{i + 1}'), 20 + i, 0, tlmap)
        w.sub(struct.pack('>BQII', ROOT_THREAD_OBJ, t, 2 + i, TRACE + 2 + i))

    # ---------- 3. Listener leak ----------
    l_buf = bytes(a.listener_kb << 10)
    arraylist([w.instance(Lambda, w.byte_array(l_buf)) for _ in range(a.listeners)], oid=listeners_id)

    # ---------- 4. Duplicate strings ----------
    dup_ids = bytearray()
    for _ in range(a.dup_strings):
        dup_ids += struct.pack('>Q', w.instance(String, w.byte_array(b'ACTIVE'), 0, 0, 0))
    w.instance(ArrayList, w.obj_array(OBJ_ARR, bytes(dup_ids)), a.dup_strings, oid=dups_id)
    del dup_ids
    print(f'fixed leaks written: {w.f.tell() / (1 << 30):.2f} GB in {time.time() - t0:.0f}s')

    # ---------- 1. Unbounded session cache (fills up to target size) ----------
    status = [jstr('OPEN'), jstr('CLOSED')]
    users = {}  # user-0..user-999, created on first use so no garbage is left behind
    payload = bytes(a.payload_kb << 10)
    nodes = bytearray()
    n = 0
    while w.f.tell() < target:
        orders = arraylist([w.instance(Order, n * a.orders + j, status[j % 2], j * 1.5) for j in range(a.orders)])
        sid = jstr(f'sess-{n}')
        if n % 1000 not in users:
            users[n % 1000] = jstr(f'user-{n % 1000}')
        s = w.instance(Session, sid, users[n % 1000], w.byte_array(payload), orders)
        nodes += struct.pack('>Q', w.instance(Node, n, sid, s, 0))
        n += 1
        if n % 2000 == 0:
            print(f'  {n} sessions, {w.f.tell() / (1 << 30):.2f} GB')
    cap = 16
    while cap * 0.75 < n:
        cap *= 2
    table = w.obj_array(NODE_ARR, bytes(nodes) + bytes((cap - n) * 8))  # node i sits in slot i
    w.instance(HashMap, table, n, n, int(cap * 0.75), 0.75, oid=cache_id)

    size = w.close()
    truth = {
        'file': a.out,
        'file_bytes': size,
        'leak_1_session_cache': {
            'path': 'com.example.HeapDumpGenerator.SESSION_CACHE -> java.util.HashMap',
            'sessions': n, 'orders': n * a.orders,
            'payload_bytes_each': len(payload), 'payload_bytes_total': n * len(payload),
            'expected': 'top leak suspect / biggest dominator'},
        'leak_2_threadlocal': {
            'path': 'Thread worker-N -> threadLocals -> Entry.value -> byte[]',
            'threads': a.threads, 'bytes_each': len(tl_buf), 'bytes_total': a.threads * len(tl_buf)},
        'leak_3_listeners': {
            'path': 'com.example.HeapDumpGenerator.LISTENERS -> ArrayList -> $$Lambda$14.arg$1 -> byte[]',
            'count': a.listeners, 'bytes_each': len(l_buf), 'bytes_total': a.listeners * len(l_buf)},
        'waste_4_duplicate_strings': {
            'path': 'com.example.HeapDumpGenerator.DUP_STRINGS', 'value': 'ACTIVE', 'count': a.dup_strings},
        'thread_count': 1 + a.threads,
        'class_count': len(classes),
    }
    with open(a.out + '.truth.json', 'w') as f:
        json.dump(truth, f, indent=2)
    print(f'done: {a.out} ({size / (1 << 30):.2f} GB, {n} sessions) in {time.time() - t0:.0f}s')
    print(f'ground truth: {a.out}.truth.json')


if __name__ == '__main__':
    main()
