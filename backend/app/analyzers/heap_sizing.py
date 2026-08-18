"""Shallow-size model — how many bytes an object actually occupies in the JVM.

hprof does not record object headers or alignment. An INSTANCE_DUMP carries only
the packed field values, and every object reference inside them is written at the
dump's *identifier size* (8 bytes on any 64-bit JVM) regardless of how wide that
reference is in the running heap. A shallow size read straight off the record is
therefore wrong twice over: it misses the header, and — whenever compressed oops
are in play — it over-counts every reference field by 4 bytes.

This module reconstructs what HotSpot actually allocated:

    instance       align(object_header + payload - (id_size - oop) * n_refs)
    object array   align(array_header  + n * oop)
    prim array     align(array_header  + n * element_size)

Compressed oops (12-byte object header, 16-byte array header, 4-byte references)
are the default on every 64-bit HotSpot up to a 32GB max heap, so a dump below
that size is assumed compressed and anything above it falls back to the 16/24/8
layout. A 4-byte identifier size means a 32-bit JVM (8/12/4).

The assumption is never silent: `SizeModel.name` is reported on the analysis so
the reader knows which layout produced the numbers, and `HEAP_OOPS` overrides it
(`compressed` | `uncompressed` | `auto`, the default).
"""
from __future__ import annotations

import os
from dataclasses import dataclass

# HotSpot disables compressed oops once the max heap passes ~32GB. A dump file
# bigger than that cannot have come from a smaller heap, so it is the one signal
# the format actually gives us.
COMPRESSED_OOPS_HEAP_LIMIT = 32 * 1024 * 1024 * 1024


@dataclass(frozen=True)
class SizeModel:
    """One JVM object layout. All sizes in bytes."""

    name: str            # "compressed oops" | "64-bit (no compressed oops)" | "32-bit"
    oop_size: int        # width of an object reference in the live heap
    object_header: int
    array_header: int    # includes the 4-byte array length
    alignment: int = 8

    def align(self, n: int) -> int:
        a = self.alignment
        return (n + a - 1) // a * a

    def instance_size(self, payload_bytes: int, n_refs: int, id_size: int) -> int:
        """Shallow size of one instance.

        `payload_bytes` is the INSTANCE_DUMP field-value length and `n_refs` the
        number of object-typed fields in the class *and its superclasses* — hprof
        writes each of those at `id_size`, so the excess over the live oop width
        has to come back off.
        """
        adjusted = payload_bytes - (id_size - self.oop_size) * n_refs
        if adjusted < 0:
            adjusted = 0
        return self.align(self.object_header + adjusted)

    def object_array_size(self, n_elements: int) -> int:
        return self.align(self.array_header + n_elements * self.oop_size)

    def prim_array_size(self, n_elements: int, element_size: int) -> int:
        return self.align(self.array_header + n_elements * element_size)


COMPRESSED = SizeModel("compressed oops", oop_size=4, object_header=12, array_header=16)
UNCOMPRESSED = SizeModel("64-bit (no compressed oops)", oop_size=8, object_header=16, array_header=24)
THIRTY_TWO_BIT = SizeModel("32-bit", oop_size=4, object_header=8, array_header=12)


def size_model(id_size: int = 8, heap_bytes: int = 0) -> SizeModel:
    """Pick the layout this dump was produced under.

    Args:
        id_size: identifier size from the hprof header (4 or 8).
        heap_bytes: dump file size, used as the proxy for max heap.
    """
    override = (os.environ.get("HEAP_OOPS") or "auto").strip().lower()
    if override in ("compressed", "compressed_oops", "on"):
        return COMPRESSED
    if override in ("uncompressed", "off", "none"):
        return UNCOMPRESSED

    if id_size == 4:
        return THIRTY_TWO_BIT
    if heap_bytes and heap_bytes > COMPRESSED_OOPS_HEAP_LIMIT:
        return UNCOMPRESSED
    return COMPRESSED
