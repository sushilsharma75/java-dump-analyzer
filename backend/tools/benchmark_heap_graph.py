"""Reproducible native graph benchmark; no production-data speed claim.

Run from the repo root:
  backend/.venv/bin/python backend/tools/benchmark_heap_graph.py --objects 1000000
Writes a streamed HPROF with a long chain, shared references and unreachable
objects. Verifies the exact expected retained total, then removes its temp files.
"""
import argparse
import json
from pathlib import Path
import struct
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tests.hprof_builder import HprofBuilder
from app.analyzers.heap_index import build_index, retained


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--objects', type=int, default=100000)
    args = parser.parse_args()
    if args.objects < 10:
        parser.error('--objects must be at least 10')
    with tempfile.TemporaryDirectory(prefix='heap-benchmark-') as temp:
        dump = Path(temp) / 'graph.hprof'
        db = Path(temp) / 'graph.sqlite'
        b = HprofBuilder()
        cls = b.load_class('benchmark.Node')
        b.class_dump(cls, instance_fields=[('next', b.OBJECT), ('shared', b.OBJECT)])
        base = 0x100000
        b.gc_root(base)
        live = args.objects - args.objects // 10
        with dump.open('wb') as fp:
            fp.write(b.build())
            for first in range(0, args.objects, 10000):
                block = bytearray()
                for i in range(first, min(first + 10000, args.objects)):
                    nxt = base + i + 1 if i + 1 < live else 0
                    shared = base + live - 1 if i < live - 1 else 0
                    block.extend(struct.pack('>BQI QI QQ', 0x21, base+i, 0, cls, 16, nxt, shared))
                fp.write(bytes([0x1c]) + struct.pack('>II', 0, len(block)) + block)
        started = time.monotonic()
        with dump.open('rb') as fp:
            build_index(fp, db)
        indexed = time.monotonic()
        result = retained(db)
        finished = time.monotonic()
        assert result['reachable_bytes'] == live * 24, result
        assert result['unreachable_count'] == args.objects - live, result
        metrics = dict(objects=args.objects, dump_bytes=dump.stat().st_size,
                       index_bytes=db.stat().st_size, index_seconds=round(indexed-started, 3),
                       dominator_seconds=round(finished-indexed, 3),
                       retained_bytes=result['reachable_bytes'], algorithm=result['algorithm'])
        try:
            import resource
            metrics['peak_rss_platform_units'] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        except ImportError:
            pass
        print(json.dumps(metrics, indent=2))


if __name__ == '__main__':
    main()
