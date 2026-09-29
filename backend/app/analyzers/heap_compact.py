"""Compact, disk-backed Lengauer–Tarjan dominators, independent of MAT.

SQLite is scanned to resolve IDs once; traversal performs no SQL per object or
edge. Arrays use temporary memory-mapped files so the OS can reclaim their pages.
This bounds Python object overhead, not total RSS or the disk needed for indexes.
Algorithm: Lengauer & Tarjan (1979), simple LINK/EVAL with path compression.
https://doi.org/10.1145/357062.357071
"""
from contextlib import ExitStack
import mmap
from pathlib import Path
import tempfile
import shutil

from .heap_control import cancel_requested


def compute_dominators(db, directory, stage_callback=None):
    """Publish dom only after graph traversal and retained sums finish.

    Node numbers are SQLite rowids; address zero is the synthetic GC root.
    Missing targets and non-strong references do not enter the graph.
    """
    stage = stage_callback or (lambda message: None)
    cancelled = cancel_requested.get()

    def progress(message):
        if cancelled and cancelled():
            from ..heap_jobs import HeapCancelled
            raise HeapCancelled()
        stage(message)

    progress("Preparing compact reference graph")
    n = db.execute("SELECT COALESCE(max(rowid),0) FROM objects").fetchone()[0]
    if n >= 2**32 - 1:
        raise ValueError("Compact graph supports fewer than 4,294,967,295 object slots")
    root = db.execute("SELECT rowid FROM objects WHERE oid='0x0'").fetchone()[0]
    edge_capacity = db.execute("SELECT count(*) FROM edges WHERE strength='strong'").fetchone()[0]
    # Include scratch arrays and headroom for persisted rows/indexes. This is a
    # conservative preflight, not a reservation against concurrent disk writers.
    required = (n + 2) * 256 + edge_capacity * 16 + 64 * 1024**2
    available = shutil.disk_usage(directory).free
    if available < required:
        raise OSError(f"Compact dominators need approximately {required:,} free bytes "
                      f"including output headroom; only {available:,} are available")
    # All scratch storage is next to the index, not on a possibly small /tmp.
    with tempfile.TemporaryDirectory(prefix='.heap-dom-', dir=directory) as temp, ExitStack() as files:
        serial = 0
        allocations = {}

        def array(code, count):
            nonlocal serial
            serial += 1
            fp = files.enter_context(open(Path(temp) / str(serial), 'w+b'))
            fp.truncate(max(1, count) * (8 if code == 'Q' else 4))
            region = mmap.mmap(fp.fileno(), 0)
            files.callback(region.close)
            view = memoryview(region).cast(code)
            files.callback(view.release)
            allocations[id(view)] = (region, fp)
            return view

        def discard(view):
            region, fp = allocations.pop(id(view))
            view.release()
            region.close()
            name = fp.name
            fp.close()
            Path(name).unlink()

        addresses = array('Q', n + 1)
        sizes = array('Q', n + 1)
        for row in db.execute('SELECT rowid,oid,shallow FROM objects'):
            node, oid, shallow = row
            addresses[node] = int(oid, 16)
            sizes[node] = shallow
            if node % 10000 == 0:
                progress(f"Preparing compact objects: {node:,} / {n:,}")
        outgoing = array('Q', n + 2)
        incoming = array('Q', n + 2)
        pairs = array('I', edge_capacity * 2)
        edge_count = 0
        for row in db.execute("""
            SELECT s.rowid,d.rowid FROM edges e
            JOIN objects s ON s.oid=e.src JOIN objects d ON d.oid=e.dst
            WHERE e.strength='strong'
        """):
            src, dst = row
            pairs[2 * edge_count] = src
            pairs[2 * edge_count + 1] = dst
            outgoing[src + 1] += 1
            incoming[dst + 1] += 1
            edge_count += 1
            if edge_count % 10000 == 0:
                progress(f"Resolving compact references: {edge_count:,}")
        for node in range(1, n + 2):
            outgoing[node] += outgoing[node - 1]
            incoming[node] += incoming[node - 1]
            if node % 10000 == 0:
                progress(f"Building compact offsets: {node:,} / {n:,}")
        successors = array('I', edge_count)
        predecessors = array('I', edge_count)
        # Reuse cursors as DFS edge positions and the retained-size algorithm's
        # working stack after the compact adjacency arrays have been filled.
        out_cursor = array('Q', n + 1)
        in_cursor = array('Q', n + 1)
        for i in range(edge_count):
            src, dst = pairs[2*i], pairs[2*i+1]
            successors[outgoing[src] + out_cursor[src]] = dst
            predecessors[incoming[dst] + in_cursor[dst]] = src
            out_cursor[src] += 1
            in_cursor[dst] += 1
            if i % 10000 == 0:
                progress(f"Building compact adjacency: {i:,} / {edge_count:,}")
        # Retire scratch mappings as soon as their last scan ends.
        discard(pairs)

        semi = array('I', n + 1)
        parent = array('I', n + 1)
        vertex = array('I', n + 1)
        label = array('I', n + 1)
        ancestor = array('I', n + 1)
        dom = array('I', n + 1)
        bucket_head = array('I', n + 1)
        bucket_next = array('I', n + 1)
        stack = in_cursor
        progress("Traversing compact strong-reference graph")
        count = 1
        vertex[1] = root
        semi[root] = 1
        label[root] = root
        stack[0] = root
        out_cursor[root] = outgoing[root]
        depth = 1
        steps = 0
        while depth:
            node = stack[depth - 1]
            at = out_cursor[node]
            if at >= outgoing[node + 1]:
                depth -= 1
                continue
            out_cursor[node] = at + 1
            child = successors[at]
            if not semi[child]:
                count += 1
                semi[child] = count
                vertex[count] = child
                label[child] = child
                parent[child] = node
                out_cursor[child] = outgoing[child]
                stack[depth] = child
                depth += 1
            steps += 1
            if steps % 10000 == 0:
                progress(f"Traversing compact graph: {count:,} reachable objects")

        discard(successors)
        discard(outgoing)
        discard(out_cursor)

        def evaluate(node):
            if not ancestor[node]:
                return label[node]
            depth = 0
            cursor = node
            while ancestor[ancestor[cursor]]:
                stack[depth] = cursor
                depth += 1
                cursor = ancestor[cursor]
                if depth % 10000 == 0:
                    progress("Compressing dominator ancestor paths")
            while depth:
                depth -= 1
                cursor = stack[depth]
                a = ancestor[cursor]
                if semi[label[a]] < semi[label[cursor]]:
                    label[cursor] = label[a]
                ancestor[cursor] = ancestor[a]
            return label[node]

        progress("Computing compact dominators")
        for i in range(count, 1, -1):
            node = vertex[i]
            for j in range(incoming[node], incoming[node + 1]):
                pred = predecessors[j]
                if semi[pred]:
                    candidate = evaluate(pred)
                    if semi[candidate] < semi[node]:
                        semi[node] = semi[candidate]
                steps += 1
                if steps % 10000 == 0:
                    progress(f"Computing compact dominators: {count - i:,} / {count:,}")
            owner = vertex[semi[node]]
            bucket_next[node] = bucket_head[owner]
            bucket_head[owner] = node
            p = parent[node]
            ancestor[node] = p
            member = bucket_head[p]
            bucket_head[p] = 0
            while member:
                candidate = evaluate(member)
                dom[member] = candidate if semi[candidate] < semi[member] else p
                member = bucket_next[member]
                steps += 1
                if steps % 10000 == 0:
                    progress(f"Resolving dominator buckets: {count - i:,} / {count:,}")
        dom[root] = root
        for i in range(2, count + 1):
            node = vertex[i]
            if dom[node] != vertex[semi[node]]:
                dom[node] = dom[dom[node]]
            if i % 10000 == 0:
                progress(f"Resolving immediate dominators: {i:,} / {count:,}")
        for i in range(count, 1, -1):
            node = vertex[i]
            sizes[dom[node]] += sizes[node]
            if i % 10000 == 0:
                progress(f"Summing retained sizes: {count - i:,} / {count:,}")

        progress("Saving compact dominator results")
        # Batch inserts keep the compatibility table for existing object browser
        # queries. No graph traversal or per-node SELECT/UPDATE remains in SQL.
        def rows():
            for i in range(1, count + 1):
                node = vertex[i]
                if i % 10000 == 0:
                    progress(f"Saving dominator results: {i:,} / {count:,}")
                yield hex(addresses[node]), i - 1, hex(addresses[dom[node]]), sizes[node]
        db.executemany('INSERT INTO dom VALUES(?,?,?,?)', rows())
        return {'reachable_objects': count, 'edges': edge_count, 'algorithm': 'lengauer-tarjan'}
