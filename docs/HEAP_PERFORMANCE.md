# Heap analysis performance regression

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

Automatic persistent indexing defaults to at most 512 MiB and 1,000,000 objects.
Exact retained-size computation separately enforces both limits, even for an
existing index or an internally created temporary index. Explicit byte/object
settings can raise these limits; the old `HEAP_DISK_DOMINATORS` flag cannot silently
bypass them. See the README configuration table.

Large dumps still receive a complete streaming histogram, source references,
static-field findings and deployment attribution. Stages above their limits are
reported as skipped. Object browsing and exact retained sizes are unavailable for
those reports; this change does not claim scalable exhaustive graph analysis of a
38-million-object heap. No prefix-only quick mode is silently substituted.

Jobs now expose the active stage. The UI labels ETA as parse ETA and suppresses
it after parsing finishes, while showing the ongoing analysis stage.

## Reproduction and validation

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
