#!/usr/bin/env python3
"""
Generate a large, realistic synthetic .hprof file for scale-testing the parser.

Layout mirrors real JVM dumps:
  - header "JAVA PROFILE 1.0.2", 8-byte IDs
  - a few hundred UTF8 + LOAD_CLASS records (class names)
  - many HEAP_DUMP_SEGMENT records (~512MB each), each packed with millions of
    INSTANCE_DUMP and PRIMITIVE_ARRAY_DUMP sub-records across those classes

Usage: python generate_big_hprof.py <output_path> <size_gb>
"""
import struct
import sys
import random

CLASS_NAMES = [
    "java/lang/String", "java/util/HashMap$Node", "java/lang/Object",
    "java/util/concurrent/ConcurrentHashMap$Node", "java/lang/Integer",
    "java/lang/Long", "java/util/ArrayList", "java/util/HashMap",
    "com/acme/order/Order", "com/acme/order/OrderLine", "com/acme/user/Session",
    "com/acme/cache/CacheEntry", "com/acme/event/AuditEvent",
    "org/hibernate/engine/spi/EntityEntry", "java/lang/ThreadLocal$ThreadLocalMap$Entry",
] + [f"com/acme/generated/Bean{i:03d}" for i in range(185)]  # 200 classes total


def main(path: str, size_gb: float):
    target = int(size_gb * 1024**3)
    out = open(path, "wb", buffering=8 * 1024 * 1024)

    # --- Header ---
    out.write(b"JAVA PROFILE 1.0.2\x00")
    out.write(struct.pack(">I", 8))          # id size
    out.write(struct.pack(">II", 0, 0))      # timestamp

    def record(tag: int, body: bytes):
        out.write(bytes([tag]) + struct.pack(">II", 0, len(body)) + body)

    # --- Strings + classes ---
    for i, name in enumerate(CLASS_NAMES):
        sid = 1000 + i
        record(0x01, struct.pack(">Q", sid) + name.encode())
        # LOAD_CLASS: serial, class_obj_id, stacktrace serial, name string id
        record(0x02, struct.pack(">I", i + 1) + struct.pack(">Q", 5000 + i)
               + struct.pack(">I", 0) + struct.pack(">Q", sid))

    # --- Build a reusable block of sub-records (~8MB), weighted realistically ---
    rng = random.Random(42)
    block_parts = []
    block_size = 0
    while block_size < 8 * 1024 * 1024:
        cls_idx = min(int(rng.expovariate(1 / 12.0)), 199)  # skew toward first classes
        class_obj_id = 5000 + cls_idx
        if rng.random() < 0.25:
            # PRIMITIVE_ARRAY_DUMP: tag 0x23, id, u4 stacktrace, u4 nelems, u1 elemtype, payload
            n = rng.choice((16, 64, 256))
            sub = (bytes([0x23]) + struct.pack(">Q", rng.getrandbits(63))
                   + struct.pack(">I", 0) + struct.pack(">I", n) + bytes([8])  # byte[]
                   + b"\x00" * n)
        else:
            # INSTANCE_DUMP: tag 0x21, obj id, u4 stacktrace, class id, u4 nbytes, payload
            nbytes = rng.choice((16, 24, 32, 48))
            sub = (bytes([0x21]) + struct.pack(">Q", rng.getrandbits(63))
                   + struct.pack(">I", 0) + struct.pack(">Q", class_obj_id)
                   + struct.pack(">I", nbytes) + b"\x00" * nbytes)
        block_parts.append(sub)
        block_size += len(sub)
    block = b"".join(block_parts)

    # --- Write HEAP_DUMP_SEGMENTs (~512MB each) of repeated blocks ---
    seg_target = 512 * 1024 * 1024
    blocks_per_seg = seg_target // len(block)
    seg_len = blocks_per_seg * len(block)

    written = out.tell()
    while written < target:
        this_len = min(seg_len, ((target - written) // len(block) or 1) * len(block))
        if this_len <= 0:
            break
        out.write(bytes([0x1C]) + struct.pack(">II", 0, this_len))
        n_blocks = this_len // len(block)
        for _ in range(n_blocks):
            out.write(block)
        written = out.tell()
        print(f"  written {written / 1024**3:.2f} GB", flush=True)

    out.close()
    print(f"Done: {written / 1024**3:.2f} GB at {path}")


if __name__ == "__main__":
    main(sys.argv[1], float(sys.argv[2]))
