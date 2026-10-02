# Heap analysis performance regression

## 138-million-object retention fix (2026-10-02)

The latest screenshot shows 138,273,967 objects, 100% parsed, and retention still
running after 131 minutes. The actual dump is unavailable locally, so the exact
production bottleneck is not measured. Code inspection found repeated full scans
per retention level and unrestricted SQLite indexing before retention.

The report pipeline now reuses histogram metadata for retention, decodes common
record headers directly from the read buffer, and skips instance bodies with no
strong reference fields. A complete histogram containing no byte/char arrays also
avoids the duplicate-array pass. Connected-path and weak-reference semantics are
unchanged.

Automatic SQLite indexing and exact dominators now default to 2,000,000 objects.
Larger inputs keep the full histogram and sampled retention tracing. Both limits
can be raised explicitly. Optional stages share a 900-second budget measured from
parse start; deep mode cannot bypass it. Timeout checks cover buffered scans,
SQLite queries and compact graph checkpoints. Reports label unfinished work as
partial, remove incomplete catalogs, preserve structural deployment data, and
finish the background job. The histogram is never truncated by this budget.
Set `HEAP_ANALYSIS_MAX_SECONDS=0` for explicitly unlimited optional work.

Measured locally with Python 3.13 on Linux:

| Synthetic report measurement | Result |
| --- | ---: |
| Heap objects | 138,273,967 |
| HPROF bytes | 11,200,220,482 (10.43 GiB) |
| End-to-end analysis, excluding fixture generation | 324.406 seconds (5m 24s) |
| Bytes returned by the file wrapper | 22,404,635,268 |
| Complete histogram | Yes |
| Sampled retaining owner found | Yes, owner at end of file |
| Exact dominators / object index | Skipped by object-count limits |

Raw results: [benchmark JSON](benchmarks/heap-138m-2026-10-02.json).

Reproduce from the repository root:

```sh
backend/.venv/bin/python backend/tools/benchmark_heap_retention.py \
  --objects 138271963 --payload-bytes 56 --tail-owner --report-only
```

The fixture contains ordinary instance records, not sparse giant arrays. Most
objects have one null reference and six primitive longs. The dominant class's
owner is at the end, forcing one full reference pass; it does not represent a
dense production graph needing six reverse passes. It has no byte/char arrays to
hash. This establishes a measured result at the screenshot's object count, not a
10–15 minute guarantee for the user's Windows machine or exact retained sizes.
Blocked I/O, decompression and histogram parsing may exceed the budget.

The one-million-object standalone tracer comparison returned identical findings:
5.354 seconds for the committed tracer and 4.377 seconds for the updated tracer.
This excludes histogram-metadata reuse. Existing indexed tracing remains available
when an index has already been built; constructing that index took 19.767 seconds
in the same run.

Validation: 327 backend tests passed. One unrelated MySQL test,
`test_i1_mysql_uses_full_scan_selectivity`, fails with `orders` versus
`public.orders`; it also fails on a clean archive of the unchanged HEAD revision.
All 68 focused heap/evidence tests passed, as did 26 frontend tests and the
production frontend build. API tests require execution outside this environment's
sandbox because its local asyncio test client stalls during startup inside it.

Restart the backend and rerun the analysis to use the changes. A job already
running the old code cannot acquire them. Rebuild the frontend for updated scan
option text. Earlier measurements and implementation history follow.

The reported 3.1 GB dump reached 100% parsing with 38,381,746 instances but did
not return a report after more than an hour. The screenshots alone cannot identify
the exact running statement; the following regressions were confirmed in code.

## Causes

- Full API analyses unconditionally built a persistent SQLite object/edge graph
  before returning results. This adds work proportional to every object and edge,
  although the streaming histogram is already complete.
- During the indexer's second pass, every object offset change discarded the
  reader's 4 MiB buffer. Small adjacent objects therefore caused overlapping reads
  repeatedly, instead of a sequential second pass.
- Static field names were resolved with an unindexed full edges-table update for
  each distinct static field name.
- Having a persistent index bypassed the 512 MiB dominator limit by default.
  SQL-backed iterative dominators bound Python RAM use but perform many queries
  per object and can require multiple convergence iterations.
- Progress measured only initial parsing. Its zero-second ETA did not account for
  source matching, indexing, duplicate scans, dominators or saving the report.

SQLite supports the saved object explorer, incoming/outgoing references, GC-root
paths, array hashes and retained-size traversal. The main report is saved as JSON.
The `.sqlite-journal` file is transaction bookkeeping, not a second heap dump.
Changing database engines alone would not remove the repeated reads or the cost
of building and traversing tens of millions of graph nodes.

## Changes

The indexer now visits payloads in explicit insertion/dump order, retaining the
read buffer across forward gaps. Static field names resolve in a single table
scan, and catalog transactions commit every 10,000 heap subrecords even inside a
single large HPROF segment.

Replacing SQL-per-object dominator traversal previously removed the automatic
cutoffs. The latest policy above restores object-count limits because building
the SQLite graph is still expensive at hundreds of millions of objects. Indexing
runs after the saved histogram checkpoint when within those limits. No prefix-only
quick mode is silently substituted.

Sampled retention tracing now runs at every dump size by default. An explicit
`HEAP_GRAPH_MAX_BYTES` still sets an operator ceiling; `HEAP_GRAPH_TRACE=0`
disables it. The extended-scans option (`deep=true`) overrides a positive configured
tracing ceiling and enables duplicate-array scans above their default 2 GB limit.
Object-index and dominator budgets remain separate.

The tracer streams object-array entries in small chunks, follows a connected path
for each sampled object, excludes `Reference.referent` weak/soft/phantom edges,
and detects static fields directly holding arrays. The chosen target is the
largest shallow consumer. Previously, even a tiny application class in the top
ten could displace a dominant primitive array. Findings describe observations,
with explicit sampling and depth limits, rather than asserting a confirmed leak.

Exact retained sizes now use compact numeric adjacency arrays and the simple
Lengauer–Tarjan algorithm with iterative path compression. SQLite resolves object
IDs in a streaming join; graph traversal then performs no SQL queries per node.
Results are batch-inserted into the existing object browser's dominator table.
Temporary arrays are memory-mapped in the index directory. Their pages can be
reclaimed by the OS, but mapping is not a strict RSS cap. The engine checks free
disk space before allocating scratch arrays, reports capacity failures, checks
cancellation during traversal and cleans its scratch files on exit. An indexing
failure does not trigger a second full index build for dominators.

This remains an independent native engine, with no MAT dependency. Representative
root paths still have search budgets; exact retained totals use the documented
strong-reference and assumed object-layout model. Production-scale runtime on the
user's 138-million-object dump remains unmeasured.

Jobs now expose the active stage. The UI labels ETA as parse ETA and suppresses
it after parsing finishes, while showing the ongoing analysis stage.

## Earlier parser regression measurements

`backend/tests/test_heap_scaling.py` checks input read amplification rather than a
machine-dependent time threshold, full-report preservation across each budget,
explicitly increased limits, and post-parse progress semantics. Existing graph
correctness tests compare dominators to an independent reachability oracle.

A local before/after experiment used the previous committed `build_index` and the
working-tree implementation on the same synthetic dump (20,000 instances with one
integer field). Input was instrumented with `CountingStream`:

| Measurement | Before | After |
| --- | ---: | ---: |
| Dump bytes | 580,212 | 580,212 |
| Bytes returned by the input stream | 5,800,550,212 | 1,160,196 |
| Local elapsed seconds | 0.528 | 0.405 |

This is approximately 5,000 times less input read amplification, **not** a
5,000-times end-to-end speedup or a measurement of physical disk reads. BytesIO,
OS caches and filesystem performance all affect wall time.

A separate sparse HPROF of 3,328,600,266 bytes verified that a file above 3 GiB
returns a complete histogram without creating a SQLite index. This checks size
boundaries and stage policy; its few large arrays do not represent the runtime of
a real dump with millions of small objects.

Validation completed: 196 backend tests passed, 8 frontend tests passed, and the
production frontend build succeeded. FastAPI TestClient stalled at startup inside
the execution sandbox; the complete backend suite passed outside the sandbox.

The user's actual dump, source repository and Windows runtime were not available
for testing. A restored 10 GB / 15-minute runtime has not been established. Rebuild
the frontend and restart/redeploy the backend to use these changes; an already
running old analysis will not acquire them.

## Progressive reports and background cancellation

Asynchronous heap jobs now save the histogram before source matching and optional
scans. Each completed stage updates that saved report. The browser opens the report
while tracing continues and downloads another revision only when findings change.
Server-sent progress events include the stage, scan pass, file position and elapsed
time; polling is the fallback when a proxy prevents streaming.

Cancellation is cooperative at buffered input reads/seeks, SQLite instruction
boundaries and compact graph traversal checkpoints. It preserves completed checkpoints and leaves unfinished stages marked
cancelled. It does not preserve a half-computed retention chain. Restarting the
backend keeps saved reports and job metadata, but unfinished scans are reported as
interrupted and must be rerun. These changes make the histogram available earlier;
they do not establish faster tracing of a 138-million-object production heap.

`test_heap_background.py` holds retention tracing open while querying the saved
histogram, edits notes during the scan, and checks completion, cancellation,
failure, restart metadata, scan progress, and terminal streaming events. Frontend
tests cover revision-based fetching, stale-response suppression, cancellation
copy, and recovery through polling.

## Automatic tracing regression checks (2026-09-29)

A 10.5 GiB sparse HPROF with three large byte arrays and one application owner
completed a full histogram and identified `example.Cache.payload` with default
tracing settings. The experiment used about 63 MiB peak process RSS. The fixture
contains only four objects and skips sparse primitive payloads: it validates large
file offsets and stage routing, not throughput on a 138-million-object heap.

Additional tests cover a million-element object array with less than 20 MiB of
traced Python allocation, early-exit array consumption, inherited weak references,
static array owners, real array class names, and disjoint reference branches.

## Native dominator benchmark

`backend/tools/benchmark_heap_graph.py` streams a synthetic HPROF containing a
long chain, shared references and 10% unreachable objects. It verifies the exact
retained total and removes its temporary dump/index afterward. Run from the repo
root with `backend/.venv/bin/python backend/tools/benchmark_heap_graph.py --objects 1000000`.

The one-million-object run (41,001,146-byte HPROF) took 24.925 seconds to index and
13.674 seconds for dominators/report extraction. Peak process RSS was 199,424 KiB;
the resulting SQLite file was 381,833,216 bytes. Expected and computed reachable
memory were both 21,600,000 bytes. These are local synthetic measurements, not
production throughput guarantees. Index size can greatly exceed dump size.

`test_heap_compact.py` checks every immediate dominator against an independent
object-removal oracle on 30 random graphs, high unsigned object IDs, a constant
number of traversal SELECT queries, cancellation cleanup/retry and disk preflight.
Existing tests cover cycles, shared descendants, weak references and source paths.

The five-million-object run (205,004,746-byte HPROF) took 125.673 seconds to index
and 68.729 seconds for dominators/report extraction. Peak process RSS was 673,412
KiB, and the completed SQLite index occupied 1,935,228,928 bytes. Computed retained
memory matched the expected 108,000,000 bytes. Scratch mappings are now closed and
deleted as each phase finishes, reducing the storage and resident pages carried
into later phases.

A subsequent 100,000-object run took 2.420 seconds for indexing and 1.350 seconds
for dominators. The previous SQL implementation did not finish that graph during
the comparison window and was interrupted inside its ancestor intersection loop;
no completed baseline speed ratio is claimed.

A separate full native analysis of the sparse 10.5 GiB fixture computed the exact
expected 3,758,096,416 reachable bytes and two unreachable arrays, in 13.665 seconds
with 64,088 KiB peak process RSS. Again, this contains only four objects and is a
large-payload/offset check, not a production-scale graph benchmark.

Latest validation: 286 backend tests and 22 frontend tests passed; the frontend
production build succeeded. The actual production dump and Windows runtime have
not been tested. Restart the backend and rebuild the frontend before reanalysis;
existing jobs and previously saved skipped stages do not acquire the new engine.
