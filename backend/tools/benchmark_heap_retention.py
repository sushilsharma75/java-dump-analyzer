"""Benchmark retention tracing on a reproducible graph, without production data.

Run from the repo root:
  backend/.venv/bin/python backend/tools/benchmark_heap_retention.py --objects 1000000

Reports indexing separately: reuse only helps when that index already exists.
Checks that indexed and streaming findings are identical. The generated dump
contains a sampled leaf -> array -> library holder -> application owner chain,
followed by unrelated instances. File generation and indexing stay bounded.
"""
import argparse
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import time
import types

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tests.hprof_builder import HprofBuilder
from app.analyzers.heap_graph import trace_retention
from app.analyzers.heap_index import build_index


class CountingFile:
    def __init__(self, fp):
        self.fp = fp
        self.bytes_read = 0

    def read(self, n=-1):
        data = self.fp.read(n)
        self.bytes_read += len(data)
        return data

    def seek(self, *args):
        return self.fp.seek(*args)

    def tell(self):
        return self.fp.tell()


def make_dump(path, objects):
    b = HprofBuilder()
    leaf = b.load_class('benchmark.Leaf')
    library = b.load_class('java.util.Holder')
    owner = b.load_class('benchmark.Owner')
    unused = b.load_class('java.util.Unrelated')
    b.class_dump(leaf)
    b.class_dump(library, instance_fields=[('items', b.OBJECT)])
    b.class_dump(owner, instance_fields=[('holder', b.OBJECT)])
    b.class_dump(unused, instance_fields=[('next', b.OBJECT)])
    leaves = [b.instance(leaf) for _ in range(2000)]
    array = b.object_array(leaf, leaves)
    holder = b.instance(library, refs=[array])
    root = b.instance(owner, refs=[holder])
    b.gc_root(root)
    with path.open('wb') as fp:
        fp.write(b.build())
        for first in range(0, objects, 10000):
            block = bytearray()
            for i in range(first, min(first + 10000, objects)):
                block.extend(struct.pack('>BQI QI Q', 0x21, 0x200000 + i, 0, unused, 8, 0))
            fp.write(struct.pack('>BII', 0x1c, 0, len(block)))
            fp.write(block)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--objects', type=int, default=1000000,
                        help='number of unrelated tail instances')
    parser.add_argument('--baseline-revision',
                        help='optional Git revision to compare the previous streaming tracer')
    args = parser.parse_args()
    if args.objects < 0:
        parser.error('--objects must be nonnegative')
    with tempfile.TemporaryDirectory(prefix='retention-benchmark-') as temp:
        path = Path(temp) / 'heap.hprof'
        index = Path(temp) / 'heap.sqlite'
        make_dump(path, args.objects)
        baseline_metrics = {}
        with path.open('rb') as fp:
            stream = CountingFile(fp)
            if args.baseline_revision:
                source = subprocess.check_output([
                    'git', 'show', args.baseline_revision + ':backend/app/analyzers/heap_graph.py',
                ], cwd=Path(__file__).resolve().parents[2], text=True)
                baseline = types.ModuleType('app.analyzers._retention_baseline')
                baseline.__package__ = 'app.analyzers'
                exec(compile(source, '<baseline heap_graph>', 'exec'), baseline.__dict__)
                start = time.monotonic()
                old = baseline.trace_retention(stream, 'benchmark.Leaf')
                baseline_metrics = dict(
                    baseline_revision=args.baseline_revision,
                    baseline_retention_seconds=round(time.monotonic() - start, 3),
                    baseline_bytes_read=stream.bytes_read,
                )
                stream.bytes_read = 0
            start = time.monotonic()
            expected = trace_retention(stream, 'benchmark.Leaf')
            if args.baseline_revision:
                assert old == expected
            stream_seconds = time.monotonic() - start
            stream_bytes = stream.bytes_read
            start = time.monotonic()
            build_index(fp, index)
            index_seconds = time.monotonic() - start
            stream.bytes_read = 0
            start = time.monotonic()
            actual = trace_retention(stream, 'benchmark.Leaf', index_path=index)
            indexed_seconds = time.monotonic() - start
        assert actual == expected and actual is not None
        assert 'benchmark.Owner.holder' in ' '.join(actual.evidence)
        assert stream.bytes_read == 0
        print(json.dumps(dict(
            unrelated_objects=args.objects, dump_bytes=path.stat().st_size,
            index_seconds=round(index_seconds, 3),
            streaming_retention_seconds=round(stream_seconds, 3),
            indexed_retention_seconds=round(indexed_seconds, 3),
            streaming_bytes_read=stream_bytes, indexed_bytes_read=stream.bytes_read,
            identical_findings=True,
            **baseline_metrics,
        ), indent=2))


if __name__ == '__main__':
    main()
