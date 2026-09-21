"""Assumed shallow-size layouts shared by histogram and retention analysis.

HPROF IDs are not the JVM reference width. Headers, field padding, alignment and
compressed-reference settings are not fully recoverable from dump file size.
The default for 8-byte IDs is a compressed-reference assumption; HEAP_OOPS can
override it. This is not a universal exact JVM object-size model.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

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
        heap_bytes: retained for API compatibility; never used to infer JVM layout.
    """
    override = (os.environ.get("HEAP_OOPS") or "auto").strip().lower()
    if override in ("compressed", "compressed_oops", "on"):
        return COMPRESSED
    if override in ("uncompressed", "off", "none"):
        return UNCOMPRESSED

    if id_size == 4:
        return THIRTY_TWO_BIT
    return COMPRESSED
