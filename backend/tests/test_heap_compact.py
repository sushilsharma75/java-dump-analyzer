"""Independent dominator checks, cancellation and traversal query scaling."""
import io
import random
import sqlite3

import pytest

from app.analyzers.heap_index import build_index, retained, connect
from app.analyzers.heap_compact import compute_dominators
from app.analyzers.heap_control import cancel_requested
from app.heap_jobs import HeapCancelled
from tests.hprof_builder import HprofBuilder


def fixture(tmp_path, n=40, seed=0):
    rng = random.Random(seed)
    b = HprofBuilder()
    cls = b.load_class('test.Node')
    b.class_dump(cls, instance_fields=[('a', b.OBJECT), ('b', b.OBJECT), ('c', b.OBJECT)])
    base = 0xf000000000000000  # exercises unsigned IDs beyond SQLite int64
    links = [[rng.randrange(n) if rng.random() < .8 else None for _ in range(3)] for _ in range(n)]
    for i, targets in enumerate(links):
        b.instance(cls, refs=[base + j if j is not None else 0 for j in targets], oid=base+i)
    b.gc_root(base)
    b.gc_root(base+1)
    path = tmp_path / f'{seed}.sqlite'
    build_index(io.BytesIO(b.build()), path)
    return path, base, links


@pytest.mark.parametrize('seed', range(30))
def test_every_immediate_dominator_matches_removal_oracle(tmp_path, seed):
    path, base, links = fixture(tmp_path, seed=seed)
    roots = {0, 1}

    def reachable(exclude=None):
        work = list(roots - {exclude})
        seen = set()
        while work:
            node = work.pop()
            if node in seen or node == exclude:
                continue
            seen.add(node)
            work.extend(v for v in links[node] if v is not None and v != exclude)
        return seen

    live = reachable()
    dominated = {i: live - reachable(i) for i in live}
    retained(path)
    with sqlite3.connect(path) as db:
        rows = {oid: (parent, size) for oid, parent, size in db.execute('SELECT oid,parent,retained FROM dom')}
    for i in live:
        strict = [d for d in live if d != i and i in dominated[d]]
        closest = min(strict, key=lambda d: len(dominated[d])) if strict else None
        expected = hex(base + closest) if closest is not None else '0x0'
        assert rows[hex(base+i)] == (expected, len(dominated[i]) * 24)


def test_traversal_uses_constant_number_of_selects(tmp_path):
    path, _, _ = fixture(tmp_path, n=500)
    with connect(path) as db:
        db.executescript("""
            CREATE TABLE dom(oid TEXT PRIMARY KEY, rank INTEGER, parent TEXT, retained INTEGER);
            INSERT INTO objects VALUES('0x0','0x0','virtual',0,0,0,'{}');
            INSERT INTO edges SELECT '0x0',oid,'<root>','strong' FROM roots;
        """)
        selects = []
        db.set_trace_callback(lambda sql: selects.append(sql) if sql.lstrip().upper().startswith('SELECT') else None)
        compute_dominators(db, tmp_path)
        assert len(selects) <= 6
        assert db.execute('SELECT count(*) FROM dom').fetchone()[0] > 100


def test_cancel_cleans_mappings_and_never_marks_dom_complete(tmp_path):
    path, _, _ = fixture(tmp_path)
    stopped = False
    def stage(message):
        nonlocal stopped
        if message == 'Traversing compact strong-reference graph':
            stopped = True
    token = cancel_requested.set(lambda: stopped)
    try:
        with pytest.raises(HeapCancelled):
            retained(path, stage_callback=stage)
    finally:
        cancel_requested.reset(token)
    assert not list(tmp_path.glob('.heap-dom-*'))
    with connect(path) as db:
        assert not db.execute("SELECT 1 FROM meta WHERE key='dominators_complete'").fetchone()
    assert retained(path)['reachable_bytes'] > 0  # retry succeeds


def test_disk_preflight_reports_needed_capacity(tmp_path, monkeypatch):
    from collections import namedtuple
    path, _, _ = fixture(tmp_path)
    usage = namedtuple('usage', 'total used free')
    monkeypatch.setattr('app.analyzers.heap_compact.shutil.disk_usage', lambda _: usage(1, 1, 0))
    with pytest.raises(OSError, match='free bytes'):
        retained(path)
    assert not list(tmp_path.glob('.heap-dom-*'))
