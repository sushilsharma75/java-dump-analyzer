"""
Programmatic builder for small, *valid* HotSpot .hprof files — the test-suite
companion to `generate_big_hprof.py` (which is for scale, this is for precision).

It lets a test construct an exact object graph — classes with field layouts and
superclass chains, instances whose fields reference other objects, object and
primitive arrays, static fields, and GC roots — then emit bytes the real parser
in `app.analyzers.heap_dump` can read. That's what makes it possible to unit-test
the histogram, the static-field leak finder, and the retention tracer against
known-correct expected output.

Wire format reference: openjdk hprof.h (the same records the parser consumes).
Only 8-byte identifiers are emitted (the common 64-bit case).

Example:
    b = HprofBuilder()
    leaf = b.load_class("com.example.Leaf")
    holder = b.load_class("com.example.Holder")
    b.class_dump(leaf)
    b.class_dump(holder, instance_fields=[("leaves", b.OBJECT)])
    leaves = [b.instance(leaf) for _ in range(50)]
    arr = b.object_array(leaf, leaves)
    h = b.instance(holder, refs=[arr])      # Holder.leaves -> arr
    b.gc_root(h)
    data = b.build()
"""
from __future__ import annotations
import struct
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple, Union

# hprof type codes (subset we need)
OBJECT = 2
BOOLEAN = 4
CHAR = 5
FLOAT = 6
DOUBLE = 7
BYTE = 8
SHORT = 9
INT = 10
LONG = 11

_PRIM_SIZE = {BOOLEAN: 1, CHAR: 2, FLOAT: 4, DOUBLE: 8, BYTE: 1, SHORT: 2, INT: 4, LONG: 8}

# Top-level record tags
_TAG_UTF8 = 0x01
_TAG_LOAD_CLASS = 0x02
_TAG_HEAP_DUMP_SEGMENT = 0x1C

# Heap sub-record tags
_SUB_ROOT_UNKNOWN = 0xFF
_SUB_ROOT_JNI_GLOBAL = 0x01
_SUB_ROOT_THREAD_OBJ = 0x08
_SUB_ROOT_STICKY_CLASS = 0x05
_SUB_CLASS_DUMP = 0x20
_SUB_INSTANCE_DUMP = 0x21
_SUB_OBJECT_ARRAY_DUMP = 0x22
_SUB_PRIMITIVE_ARRAY_DUMP = 0x23


class HprofBuilder:
    """Builds an in-memory .hprof byte string for tests. Convenience constants are
    exposed as attributes (`b.OBJECT`, `b.BYTE`, …) so callers needn't import them."""

    OBJECT, BOOLEAN, CHAR, FLOAT, DOUBLE, BYTE, SHORT, INT, LONG = (
        OBJECT, BOOLEAN, CHAR, FLOAT, DOUBLE, BYTE, SHORT, INT, LONG)

    def __init__(self) -> None:
        self.id_size = 8
        self._strings: Dict[str, int] = {}
        self._next_str = 1000
        self._class_id: Dict[str, int] = {}     # FQCN (slashed) -> class object id
        self._next_class = 0x100
        self._next_oid = 0x100000
        self._top = bytearray()                 # UTF8 + LOAD_CLASS records
        self._seg = bytearray()                 # heap-dump segment sub-records

    # ---- low-level packers ----
    def _id(self, v: int) -> bytes:
        return struct.pack(">Q", v)

    def _str_id(self, text: str) -> int:
        if text in self._strings:
            return self._strings[text]
        sid = self._next_str
        self._next_str += 1
        self._strings[text] = sid
        self._top += bytes([_TAG_UTF8]) + struct.pack(">II", 0, 8 + len(text.encode()))
        self._top += self._id(sid) + text.encode()
        return sid

    # ---- classes ----
    def load_class(self, fqcn: str, fresh: bool = False) -> int:
        """Register a class by dotted FQCN; emit its UTF8 name + LOAD_CLASS. Returns class id.
        `fresh=True` mints a new class id even if the name was seen before — that's
        how the same class loaded by two classloaders looks in a real dump."""
        slashed = fqcn.replace(".", "/")
        if slashed in self._class_id and not fresh:
            return self._class_id[slashed]
        cid = self._next_class
        self._next_class += 1
        self._class_id[slashed] = cid
        name_id = self._str_id(slashed)
        serial = len(self._class_id)
        self._top += bytes([_TAG_LOAD_CLASS]) + struct.pack(">II", 0, 4 + 8 + 4 + 8)
        self._top += struct.pack(">I", serial) + self._id(cid) + struct.pack(">I", 0) + self._id(name_id)
        return cid

    def class_dump(self, class_id: int, super_id: int = 0,
                   instance_fields: Sequence[Tuple[str, int]] = (),
                   static_object_fields: Sequence[Tuple[str, int]] = (),
                   loader_id: int = 0, protection_domain_id: int = 0) -> None:
        """Emit a CLASS_DUMP. `instance_fields` are (name, type_code) in layout order;
        `static_object_fields` are (name, value_object_id) — always object-typed.
        `loader_id` / `protection_domain_id` are the object ids of the class's
        classloader and protection domain — the deployment-attribution inputs."""
        b = bytearray()
        b += self._id(class_id) + struct.pack(">I", 0) + self._id(super_id)
        b += self._id(loader_id) + self._id(0) + self._id(protection_domain_id)
        b += self._id(0) * 2            # reserved1, reserved2
        b += struct.pack(">I", 0)       # instance size (unused by our parser paths)
        b += struct.pack(">H", 0)       # constant pool count
        b += struct.pack(">H", len(static_object_fields))
        for name, value_oid in static_object_fields:
            b += self._id(self._str_id(name)) + bytes([OBJECT]) + self._id(value_oid)
        b += struct.pack(">H", len(instance_fields))
        for name, type_code in instance_fields:
            b += self._id(self._str_id(name)) + bytes([type_code])
        self._seg += bytes([_SUB_CLASS_DUMP]) + b

    # ---- objects ----
    def _new_oid(self, oid: Optional[int]) -> int:
        if oid is not None:
            return oid
        oid = self._next_oid
        self._next_oid += 1
        return oid

    def instance(self, class_id: int, refs: Optional[Sequence[int]] = None,
                 body: bytes = b"", oid: Optional[int] = None) -> int:
        """Create an INSTANCE_DUMP. Either pass `refs` (an object id per object-typed
        field, in layout order — packed for you) or raw `body` bytes. Returns the oid."""
        oid = self._new_oid(oid)
        if refs is not None:
            body = b"".join(self._id(r) for r in refs)
        self._seg += (bytes([_SUB_INSTANCE_DUMP]) + self._id(oid) + struct.pack(">I", 0)
                      + self._id(class_id) + struct.pack(">I", len(body)) + body)
        return oid

    def pack_fields(self, values: Sequence[Tuple[int, object]]) -> bytes:
        """Pack (type_code, value) pairs into an instance body in layout order.
        Object values are object ids; primitives are packed by type. This is what
        you need for a class with mixed field types (e.g. java.lang.Thread)."""
        out = bytearray()
        for tcode, val in values:
            if tcode == OBJECT:
                out += self._id(int(val))
            elif tcode == BOOLEAN:
                out += bytes([1 if val else 0])
            elif tcode == INT:
                out += struct.pack(">i", int(val))
            elif tcode == LONG:
                out += struct.pack(">q", int(val))
            elif tcode == CHAR:
                out += struct.pack(">H", int(val))
            elif tcode == SHORT:
                out += struct.pack(">h", int(val))
            elif tcode == FLOAT:
                out += struct.pack(">f", float(val))
            elif tcode == DOUBLE:
                out += struct.pack(">d", float(val))
            else:  # BYTE
                out += struct.pack(">b", int(val))
        return bytes(out)

    def java_string(self, text: str, string_class_id: int, oid: Optional[int] = None,
                    coder: int = 0) -> int:
        """Build a JDK 9+ java.lang.String (byte[] `value` + byte `coder`).
        `string_class_id` must be a class whose layout is [('value',OBJECT),('coder',BYTE)].
        LATIN1 (coder 0) is used for ASCII text."""
        data = text.encode("latin-1", "replace") if coder == 0 else text.encode("utf-16-be")
        arr = self.primitive_array(BYTE, len(data), data=data)
        return self.instance(string_class_id,
                             body=self.pack_fields([(OBJECT, arr), (BYTE, coder)]),
                             oid=oid)

    def object_array(self, element_class_id: int, elements: Sequence[int],
                     oid: Optional[int] = None) -> int:
        oid = self._new_oid(oid)
        self._seg += (bytes([_SUB_OBJECT_ARRAY_DUMP]) + self._id(oid) + struct.pack(">I", 0)
                      + struct.pack(">I", len(elements)) + self._id(element_class_id)
                      + b"".join(self._id(e) for e in elements))
        return oid

    def primitive_array(self, element_type: int, count: int, oid: Optional[int] = None,
                        data: Optional[bytes] = None) -> int:
        """Emit a PRIMITIVE_ARRAY_DUMP. Pass `data` to set exact element bytes
        (length must be count*element_size); otherwise the array is zero-filled."""
        oid = self._new_oid(oid)
        size = _PRIM_SIZE[element_type]
        payload = data if data is not None else b"\x00" * (count * size)
        self._seg += (bytes([_SUB_PRIMITIVE_ARRAY_DUMP]) + self._id(oid) + struct.pack(">I", 0)
                      + struct.pack(">I", count) + bytes([element_type]) + payload)
        return oid

    # ---- GC roots ----
    def gc_root(self, oid: int, kind: str = "unknown") -> None:
        if kind == "jni_global":
            self._seg += bytes([_SUB_ROOT_JNI_GLOBAL]) + self._id(oid) + self._id(0)
        elif kind == "thread_obj":
            self._seg += bytes([_SUB_ROOT_THREAD_OBJ]) + self._id(oid) + struct.pack(">II", 0, 0)
        elif kind == "sticky_class":
            self._seg += bytes([_SUB_ROOT_STICKY_CLASS]) + self._id(oid)
        else:
            self._seg += bytes([_SUB_ROOT_UNKNOWN]) + self._id(oid)

    # ---- assembly ----
    def build(self) -> bytes:
        out = bytearray()
        out += b"JAVA PROFILE 1.0.2\x00"
        out += struct.pack(">I", self.id_size)
        out += struct.pack(">II", 0, 0)        # timestamp hi/lo
        out += self._top
        out += bytes([_TAG_HEAP_DUMP_SEGMENT]) + struct.pack(">II", 0, len(self._seg)) + self._seg
        return bytes(out)

    def write(self, path: Union[str, Path]) -> str:
        path = str(path)
        Path(path).write_bytes(self.build())
        return path
