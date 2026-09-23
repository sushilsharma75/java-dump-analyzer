# Stack Analyser

**Deep insights into JVM and database performance**

A self-hosted workbench for investigating HotSpot JVM thread dumps, binary HPROF
heap dumps, GC logs, matching application source, and DBDoctor snapshots from
PostgreSQL, MySQL and MariaDB. Formerly POSTMORTEM. It reports observations,
ranked hypotheses, source context, and the evidence needed to verify a diagnosis.

**A dump snapshot does not prove a memory leak or identify an allocation site.**
A large histogram entry, a repeated thread stack, or rising GC occupancy is an
investigation lead. The workbench distinguishes executing frames, retaining fields,
and source references, and exposes incomplete analysis instead of calling it healthy.

## Start locally

Use 64-bit Python 3.13 and Node.js 22.

### Linux / macOS

```bash
cd backend
python -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/uvicorn app.main:app --reload --port 8000
```

In a second terminal:

```bash
cd frontend
npm install
npm run dev
```

The React/webpack frontend serves on port 5173 and proxies `/api` to port 8000.
`npm run build` creates the production frontend. A local
JDK 17+ with `java` and `javac` enables Java AST indexing and the real-JVM integration
test. Without a compiler, source indexing falls back to explicitly labelled lexical
scopes. No application code or annotation processors are executed by source indexing.

### Windows (PowerShell)

From the repository directory, start the backend:

```powershell
cd backend
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

In a second PowerShell terminal, from the repository directory:

```powershell
cd frontend
npm.cmd ci
npm.cmd run dev
```

Open `http://localhost:5173`. These commands do not require virtual-environment
activation or a change to PowerShell's execution policy. `npm.cmd` avoids a blocked
`npm.ps1` shim. Install a JDK 17+ and put `java.exe` and `javac.exe` on `PATH` for
Java AST source matching; Git for Windows is optional for repository clone fallback.
No WSL, Docker, or separately installed SQLite server is required.

By default, uploads use the operating system's temporary directory plus
`postmortem`, and saved analyses use its `analyses` subdirectory. On Windows this
normally resolves under `%TEMP%`; on Linux it is normally `/tmp`. To choose other
storage locations, set these variables **before starting the backend**:

```powershell
$env:DUMP_TMP_DIR = 'D:\StackAnalyser\uploads'
$env:ANALYSIS_DIR = 'D:\StackAnalyser\analyses'
```

Use existing drives with writable space for your dumps. The application creates
the directories. Heap limits and stage reporting are identical on both platforms;
see the configuration table below. After updating the application, restart the
backend and frontend. For a deployed frontend, rebuild with `npm.cmd run build`
and serve the updated `frontend/dist` output through your existing web server.

To run the checks on Windows:

```powershell
# From the repository directory
.\backend\.venv\Scripts\python.exe -m pytest backend/tests
cd frontend
npm.cmd test
npm.cmd run build
```

The [CI workflow](.github/workflows/tests.yml) runs backend tests (including a real
HotSpot heap and Java source indexing), frontend tests and the production build on
both Windows and Linux. Windows-specific regressions cover file sharing, paths
with spaces/non-ASCII characters, CRLF source files and upload cleanup.

This is a single-user, trusted-host application. Source and dump path endpoints read
server-side files. There is no authentication or multi-tenant isolation.

## Database analysis (DBDoctor)

Choose **Database Analyser** from the top menu, then upload a normalized DBDoctor
JSON file using **Database Snapshot**. Choose **JVM Analyser** for thread dumps,
heap dumps, GC logs and source attachment. Try `backend/samples/database/pg_full.json` or `mysql_full.json` first. The
integration runs locally with the existing backend dependencies; no separate
DBDoctor service or database connection is needed.

1. Download the PostgreSQL or MySQL/MariaDB Python collector from the upload panel.
   Run it inside your database environment with a read-only account and the driver
   it requires (`psycopg[binary]` or `PyMySQL`). Use `--help` for its connection/output
   flags. Download `delta.py` alongside it if using `--delta-of`.
2. Review the resulting snapshot before sharing it. Collector normalization handles
   common SQL literals; SQL comments and other sensitive content may remain.
3. Upload the current snapshot (maximum 10 MiB), optionally with an older cumulative
   snapshot from the same engine, database alias and server version. Timezones and
   increasing capture timestamps are required for comparison.
4. Inspect coverage, query/index/operations/configuration/maintenance findings,
   measured evidence and confidence. The score ranks observed findings; even 100
   does not certify database health when evidence is absent.
5. Export HTML or the complete JSON. Database analyses use the same persistent
   saved-history list as JVM analyses and survive restarts.
6. For JVM/database leads, analyze or reopen a thread dump, save its capture time,
   then open the database report. Confirm that the JVM connects to this database
   in the same incident. Captures more than five minutes apart are rejected.
   Driver/pool stacks provide investigation context, not proof of SQL causality.

Stored procedure/function analysis is available for the existing PostgreSQL,
MySQL and MariaDB engines. Run the collector with `--include-procedures`, then
upload its JSON normally. This option captures original routine bodies and column
types; **routine literals and comments are retained**, so review source for secrets.
Older snapshots still work but show missing procedure/column coverage.
Try [the procedure sample](backend/samples/database/mysql_procedures.json).

The `procedures` findings category includes:

- Parameter/local-variable and column datatype differences in simple comparisons,
  including length, numeric precision/scale and MySQL signedness.
- Temporary-column differences in joins and explicit-column `INSERT … SELECT`.
- Temporary tables used in joins/filters/sorts without an explicit index.
- Cursor/loop processing, `SELECT *`, dynamic SQL requiring separate review, and
  functions applied to predicate columns.

Each finding includes source line evidence, confidence and a suggested action.
These are static review candidates: validate plans, representative row counts and
runtime before changing SQL or adding indexes. This does not compile procedures,
prove invalid variable definitions, infer all temporary-table types, analyse dynamic
SQL strings, resolve quoted identifiers/CTEs/nested scopes, or detect parameter
sniffing, collation effects and runtime blocking. Unsupported languages and missing
bodies show partial coverage; catalog permissions can also hide entire routines.

For manually prepared snapshots, add `procedures` (schema_name, name, definition,
optional language/identity/parameters) and `columns` (schema_name, table, name,
data_type). Definitions must be routine **bodies**, excluding CREATE wrappers;
parameters use `{ "name": "p_id", "data_type": "bigint" }`. The sample demonstrates
this contract. PostgreSQL parameter typmods may be absent in catalog metadata;
local declarations and column definitions retain captured precision/length.
Collector catalog references: [PostgreSQL pg_proc](https://www.postgresql.org/docs/16/catalog-pg-proc.html)
and [MySQL ROUTINES](https://dev.mysql.com/doc/refman/8.4/en/information-schema-routines-table.html).

Database snapshots retain collector-supplied text in `ANALYSIS_DIR`. No database
credentials are requested by the workbench. No recommendations are automatically
executed. Baseline rates may be uncertain after resets or digest eviction, and
query time percentages cover captured statements only.

```text
POST /api/analyze/database             multipart file, optional baseline
GET  /api/database/collectors/{name}   pg_collect.py, mysql_collect.py, delta.py
POST /api/correlate/database           database_id, thread_id, same_incident_confirmed
```

The original DBDoctor repository was downloaded to `integrations/dbdoctor/`.
Runtime code is embedded under `backend/app/vendor/dbdoctor/` at revision
`59160ccb1878c8c3f3d355ed64abda2335dc4aa9`, with diagnostic corrections.
See [the DBDoctor review](docs/DBDOCTOR_REVIEW.md) for findings, implemented fixes,
maintenance guidance and remaining evidence boundaries. Its hosted billing/auth
service is not part of this trusted-host integration. Existing `postmortem` storage
paths, source manifests and browser keys remain compatible with earlier analyses.

## Investigation workflow

1. Attach the source used to build the deployed application: ZIP, local directory,
   or Git repository. Include the source manifest described below when available.
2. Analyze a thread dump, heap dump, and optional GC log from the same incident.
   Full heap analysis creates a persistent object index within the configured
   byte/object limits and reports skipped stages above them. Quick mode reads only
   a prefix and deliberately cannot support a complete diagnosis.
3. In **Evidence and investigation**, enter process identity, process start time,
   capture time, and build ID. Process identity should include the host/container
   identity as well as PID. Use ISO timestamps with timezones.
4. Read stage coverage and source provenance before interpreting findings. Each
   finding carries an evidence ID, confidence, observation/hypothesis classification,
   limitations, and verification guidance.
5. For a thread stall, inspect the lock owner and both stacks. For memory retention,
   open a dominator object, expand references, and follow a field-labelled path to
   a GC root. Attached source can resolve retaining fields to declarations.
6. Pin a baseline and compare a later capture under comparable load. Missing capture
   provenance is reported; explicit process/build/layout conflicts prevent numerical
   comparison. Partial histograms never imply that an omitted class has zero objects.
7. Generate an optional detailed AI report after checking the evidence. Save HTML
   for presentation and the complete analysis JSON for structured details.

Saved analyses can be reopened or deleted from the landing page. JSON and SQLite
indexes survive backend restarts in `ANALYSIS_DIR`; source sessions and running jobs
remain process-local. Reattach source after a restart. Saved artifacts are retained
until explicitly deleted. Treat that directory as sensitive diagnostic data.

## Implemented capabilities and boundaries

| Area | What is implemented | Interpretation / boundary |
|---|---|---|
| Thread parsing | HotSpot text headers, module/classloader-prefixed frames, monitors and ownable synchronizers; adjacent thread blocks | Rejected frame counts/examples are exposed. Zero recognized threads yields `invalid`; incomplete stacks cannot silently yield a healthy verdict |
| Lock analysis | Monitor/synchronizer owner relationships, reconstructed acquisition cycles, JVM-reported deadlocks, waiter and owner source locations | Condition/Object.wait waits are not treated as monitor acquisition; timed acquisition can resolve a sampled cycle |
| Thread comparison | Unique thread identities, full-stack/state persistence, CPU and lifetime deltas when present, idle-worker exclusion | Repeated stacks are observations, not proof of no progress. Ambiguous duplicate identities are excluded |
| Heap histogram | Complete class histogram plus display-oriented top lists | Sizes use the declared layout model, not measured JVM allocation sizes |
| Object exploration | Persistent SQLite graph; paginated object search, incoming/outgoing references and primitive fields | Object IDs are local to one capture. Primitive arrays show a bounded value preview |
| GC-root paths | Field-labelled, representative reverse paths for any indexed object; optional reference-referent edges | Search budgets and partial results are explicit; absence of a path within budget is not proof of unreachability |
| Retention | Disk-backed immediate dominators, top owners, accumulation chains, unreachable-object accounting | Exact graph sums under the selected size model, **not a claim of MAT/JVM byte-for-byte parity** |
| Classloaders | Class, superclass, defining-loader and loaded-class relationships; deployment attribution and duplicate classes | Multiple loaders for one artifact need lifecycle evidence before declaring a stale deployment |
| Heap threads | HPROF FRAME/TRACE records, thread roots, Java/JNI local root associations | Reports `not recorded` when the dump lacks stacks; heap snapshots do not record general allocation history |
| Collections | Observed size, backing-array capacity/fill ratio, occupied slots and map collision-entry lower bound | Only recognized field layouts; not a complete semantic adapter for every collection implementation |
| Duplicate arrays | Streaming content hashes in the persistent index; typed groups and potential duplicate bytes | Mutable arrays may require separate storage. Savings are potential, not guaranteed reclaimable bytes |
| Source | Java AST declarations/method/field scopes when javac is present; conservative import binding, nested types, source content fingerprint | No project-classpath type checking or interprocedural proof. Ambiguous symbols stay unresolved; Kotlin/Scala use lexical support |
| Comparison | Complete-histogram deltas; partial legacy results compare only intersecting classes | Growth may reflect load, lifecycle, or caches; it does not itself prove unbounded retention |
| Correlation | Heap class/source-reference overlap with executing threads; GC pressure context | Explicit capture conflicts and large timestamp gaps block correlation; global GC trends do not identify the leaking class |
| Reports | Findings with evidence IDs, expandable method context, summary/detailed AI modes, HTML export and complete JSON | AI receives selected structured evidence and source context, not unrestricted repository access |

## Heap graph and size semantics

Full API analyses always stream the complete dump for the histogram (unless quick
mode is selected). Automatic object/edge indexing is limited to 512 MiB and one
million objects by default. Above either limit, the report still includes the full
histogram, source references, static-field findings and deployment attribution;
object browsing is explicitly marked skipped. Object bodies and large arrays
within the indexed workflow are processed in bounded chunks. SQLite holds incoming/outgoing indexes, roots,
class metadata, thread records, and the dominator traversal state. Retention uses an
iterative reverse-postorder algorithm; the graph does not need to fit in Python RAM.

Only recorded GC roots connect to the virtual root. Classes are **not all assumed
to be roots**. Instances reference their classes; class/loader relationships and
static fields participate in ownership. `java.lang.ref.Reference.referent` edges are
excluded from the default strong-reference graph. The object browser can include
these edges for investigation; this is not a full simulation of collector policy for
soft, weak, final, and phantom references.

Object layout is an assumption. `HEAP_OOPS` selects compressed or uncompressed
references; auto uses compressed references for 8-byte identifiers, independent of
dump file size. The model uses fixed headers and eight-byte alignment. It does not
recover every JVM's field padding, compact headers, alignment flags, or class-object
shallow overhead. Retained totals are exact for the constructed graph and modeled
shallow sizes; they must not be advertised as universally equal to MAT results.

Exact retained-size analysis respects `HEAP_DOMINATOR_MAX_BYTES` (512 MiB) and
`HEAP_DOMINATOR_MAX_OBJECTS` (one million), including when an index exists. The old
`HEAP_DISK_DOMINATORS` switch no longer bypasses these limits. Administrators can
explicitly raise the byte and object limits after benchmarking their hardware;
disk-backed storage bounds RAM usage, not execution time. Skipped retained sizes
are unavailable, not zero. The bounded heuristic tracer is a separate optional
stage, not a replacement for an exhaustive GC-root search.

Large-dump support means the parser/index accepts files up to the API's 50 GiB limit;
it is **not a measured throughput or disk-space guarantee at 25–50 GiB**. SQLite
indexes can substantially exceed dump size, and convergence time depends on graph
shape. Use a dedicated volume, benchmark representative dumps, and inspect stage
status. Upload progress covers transfer; parse byte progress is not an ETA for the
subsequent graph and dominator stages. The progress screen reports the active
stage and hides parse ETA once parsing finishes.

Every stage reports `completed`, `partial`, `skipped`, or `failed`. Failed graph,
duplicate, or attribution stages remain visible alongside usable histogram results.
An unknown heap subrecord marks histogram coverage partial; malformed record lengths
are rejected. Quick mode's counts describe only the parsed prefix.

## Attaching the matching source build

At build/package time, generate a manifest for the source being distributed:

```bash
cd backend
.venv/bin/python tools/source_manifest.py /path/to/source release-2026-09-21
```

This writes `postmortem-source.json` into that source tree with a build ID and
content fingerprint. Upload it with the source; enter the same deployed build ID
in the analysis's capture metadata. A build match requires both an intact source
fingerprint and a matching declared capture build ID. Changing the source invalidates
the manifest. Git commit and dirty-worktree information are also recorded where
available. **The capture's build ID is supplied by the operator; the application
does not independently extract or authenticate it from the running JVM.**

Source resolution never picks an arbitrary duplicate FQCN. Qualified names do not
fall back to unrelated same-named files. Constructor/field references are filtered
by imports and package, and method scopes come from the Java syntax tree where
available. Missing dependencies, wildcard imports, generated names, language-specific
lowering, and overload binding can leave references unresolved. A source match
identifies context; only a recorded object edge establishes a retaining relationship.

Attach or change source after analysis, then use **Refresh source locations**.
The object path viewer resolves field declarations against the currently attached
source, and **Source method context** expands beyond the original small snippet.

## Capture examples

```bash
jcmd <pid> Thread.print -l > thread-dump.txt
jcmd <pid> GC.heap_dump /path/to/heap.hprof
# Automatic heap dump on OOM:
# -XX:+HeapDumpOnOutOfMemoryError -XX:HeapDumpPath=/var/log/
# GC logging:
# -Xlog:gc*:file=gc.log:time,uptime,level,tags
```

For intermittent stalls, capture several thread dumps seconds apart. For memory
growth, compare compatible heaps over a representative workload and inspect owners.
A heap dump and source alone cannot reconstruct allocation history; use an allocation
recording/profiler when the allocation site is the missing evidence.

## API

Existing upload and analysis endpoints remain available:

```text
GET    /api/health
POST   /api/analyze/thread              file, optional source_session
POST   /api/analyze/gc                  GC log file
POST   /api/analyze/heap                file, quick, source_session (≤200 MiB)
POST   /api/analyze/heap/async           upload then background analysis
POST   /api/analyze/heap/path            server-side path, quick, source_session
GET    /api/jobs/{job_id}
DELETE /api/jobs/{job_id}
POST   /api/source/upload               source ZIP
POST   /api/source/path                 source directory
POST   /api/source/git                  Git URL
GET    /api/source/{session}/lookup     class_name, line
GET    /api/source/{session}/context    class_name, method, line
DELETE /api/source/{session}
POST   /api/correlate                   heap, thread, optional gc/source_session
POST   /api/compare/heap                before, after, optional source_session
POST   /api/compare/threads             before, after
POST   /api/llm/summarize                analysis, kind, api_key, model,
                                       detail: summary|detailed, source_session
```

Persistent analysis and investigation endpoints:

```text
GET    /api/analyses                    latest 100 saved analyses
GET    /api/analyses/{id}               kind + complete analysis JSON
DELETE /api/analyses/{id}               remove saved report and SQLite index
POST   /api/analyses/{id}/capture       process_id, process_start, captured_at, build_id
POST   /api/analyses/{id}/source/{session}
GET    /api/heap/{id}/objects           class_name, offset, limit (1–200)
GET    /api/heap/{id}/objects/{oid}     paginated incoming/outgoing references
GET    /api/heap/{id}/objects/{oid}/roots
                                       include_weak, max_nodes (≤100000),
                                       max_depth (≤100), source_session
GET    /api/heap/{id}/threads           recorded stacks and local root associations
```

Use the returned `analysis_id`/`object_index_id`; never infer IDs from filenames.
Indexes unavailable because of quick mode or a failed stage return HTTP 409.
The async upload endpoint returns a job after the upload completes, not before the
browser has transferred the file. Deleting a saved analysis is separate from
cleaning up its transient job record.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `DUMP_TMP_DIR` | OS temp directory + `postmortem` | Uploaded dump staging |
| `ANALYSIS_DIR` | OS temp directory + `postmortem/analyses` | Persisted JSON and SQLite indexes; configure a durable volume |
| `HEAP_INDEX_MAX_BYTES` | `536870912` | Automatic persistent object-index size ceiling; `0` disables it |
| `HEAP_INDEX_MAX_OBJECTS` | `1000000` | Automatic index object-count ceiling |
| `HEAP_DOMINATOR` | `1` | `0` disables dominator computation |
| `HEAP_DOMINATOR_MAX_BYTES` | `536870912` | Retained-size analysis ceiling in bytes, also enforced with a persistent index |
| `HEAP_DOMINATOR_MAX_OBJECTS` | `1000000` | Retained-size analysis object-count ceiling, including temporary indexes |
| `HEAP_GRAPH_TRACE` | `1` | Bounded heuristic retention tracer |
| `HEAP_GRAPH_MAX_BYTES` | `2147483648` | Heuristic tracer gate, in bytes |
| `HEAP_WASTE_TRACE` | `1` | Duplicate-array analysis |
| `HEAP_WASTE_MAX_BYTES` | `2147483648` | Legacy non-indexed duplicate scan gate, in bytes |
| `HEAP_OOPS` | `auto` | `compressed`, `uncompressed`, or documented default assumption |
| `ANTHROPIC_MODEL` | backend default | Override the model for optional AI reports; UI also accepts a model selection |

AI calls send selected findings, stacks, and source context to Anthropic using a
per-request key. The backend does not persist that key. Browser key remembrance is
optional. Detailed mode asks for ranked hypotheses, counter-evidence, coverage,
ownership/blocking chains, source context, and measurable verification steps. Input
selection prioritizes affected threads; budget reduction drops whole records and
reports omissions instead of cutting JSON mid-record.

## Validation

```bash
cd backend
.venv/bin/python -m pytest
cd ../frontend
npm test
npm run build
```

Tests include module-prefixed frames, acquisition cycles without a JVM deadlock
section, idle workers, duplicate names, partial comparisons, capture conflicts,
source ambiguity, comments and method boundaries, manifest mismatch, stage failures,
collection capacity, typed references, persistence, pagination, and API deletion.

Dominator tests use an independent removal/reachability oracle over randomized
graphs. A local-JDK integration test compiles a small application, asks its HotSpot
MXBean to produce a real HPROF, indexes it, resolves an application static-field root
path, reads heap threads, and computes retention. That test skips if the JDK is absent.
This is correctness coverage, not a production-scale benchmark or external MAT parity
certification.

## Architecture and explicit limits

`backend/app/analyzers/heap_index.py` owns the SQLite graph and queries;
`heap_dominators.py` produces retention findings; `source_symbols.py` and
`java/SourceSymbols.java` provide source scopes. `evidence.py` defines evidence IDs
and compatibility checks. `artifacts.py` persists reports. Existing streaming
histogram, thread, GC, deployment, and comparison analyzers remain separate stages.
The React workbench exposes these through its evidence/investigation panel.

Not supported: IBM PHD/javacore, arbitrary OQL, live monitoring, allocation-history
reconstruction, full compiler semantic analysis across a project's dependencies,
all virtual-thread dump formats, or every JVM/collector object-layout variation.
Kotlin/Scala source support is conservative and does not replace language compilers.
The system reports these evidence limits; it cannot guarantee a root cause from
artifacts that do not contain the necessary evidence.

## License

MIT — see [LICENSE](LICENSE).

## Server logs and combined JVM investigations

Upload **server.log** (plain UTF-8 text or JSON-lines, up to **5 GiB /
5,368,709,120 bytes**) in **Server log · combined investigation**. The browser
streams the file as a raw body; the backend writes bounded chunks to temporary
storage and scans it in a background job. Upload and scan progress are separate.
Cancel stops an upload or cooperatively stops the indexer and removes partial
files. One server-log index runs at a time; other log jobs queue.

1. Attach the matching source tree using the existing Source attachment panel.
2. Upload or reopen the incident's heap and/or thread dump. GC logs are optional.
3. Upload the server log. For timestamps without an offset, supply its UTC offset
   (for example `+05:30`); leave it blank if unknown. An offset is fixed for this
   file; split logs spanning a daylight-saving change or use offset-bearing logs.
4. Set process identity, capture time and build ID in the dump and log capture
   controls where known. Use timezone-bearing ISO timestamps. Explicit process or
   build conflicts block combined analysis. Missing identity remains unverified.
5. Click **Analyze all attached evidence**. Inspect the selected artifact IDs;
   detach inputs belonging to another incident. The report joins exact logged
   classes/methods and thread names to dump evidence, including recorded retaining
   edges. Source-reference candidates are labelled separately from recorded edges.
6. Search log events by severity, excerpt text, exact thread, request/trace ID,
   or time range. Open an event to resolve its stack to source and method context.
   Combined reports can be exported as HTML or JSON and reopened from history.
   Optional AI diagnosis receives selected structured log/dump evidence, never the
   complete raw multi-GB log; its existing API-key consent flow still applies.

The scanner recognizes common ISO-date Logback/Log4j/Spring/WildFly-style headers,
Java exception continuations (`Caused by`, suppressed exceptions, frames), and
JSON-lines keys such as `message`, `level`, `@timestamp`, `thread_name`,
`logger_name`, `stack_trace`, `traceId`, and `requestId`. Abbreviated logger names,
custom timestamp formats, and missing stack lines may remain unresolved. Gzip,
archives and binary logs must be converted to uncompressed UTF-8 first.

The **entire file is scanned**, but retained excerpts are bounded: a physical line
prefix is at most 64 KiB, an event excerpt at most 32,768 characters, and an event
has at most 128 indexed frames and 256 physical lines. Longer continuation groups
are split and marked truncated. Coverage includes oversized lines, omitted frames,
unrecognized events and timestamps that could not be aligned. Text search searches
retained excerpts. All indexed events remain pageable on disk; summary and combined
reports select bounded samples and report omissions. Combined matching searches
up to 500 candidate classes and 200 thread names, prioritizes errors/warnings, and
includes at most 100 matches. Its default time window is ±5 minutes when every
attached dump has an aligned capture time; otherwise alignment stays explicit.

Reports and SQLite event indexes persist in `ANALYSIS_DIR`; raw uploads in
`DUMP_TMP_DIR` are removed after analysis. Deleting the saved log analysis removes
its event index. Saved combined reports contain their selected evidence snapshot,
so deleting the original log does not remove those exported/saved snapshots.
Reserve space for both the upload and SQLite index during scanning; index size
can exceed raw input size. Run a single backend process, as with existing job and
source sessions. Interrupted jobs do not resume after a process restart; abandoned log uploads and
unpublished log indexes are removed at startup.

If deployed behind a reverse proxy, configure its body-size limit to at least
5 GiB, permit long upload connections, and disable request buffering for this raw
upload route where supported. The application cannot override a proxy's lower
limit. This capacity is independent of heap object-index limits: attaching a log
does not create an object graph for a heap whose indexing was skipped.

Additional endpoints:

```text
POST   /api/analyze/server-log                  raw body; filename, timezone_offset
GET    /api/jobs/{job_id}                       upload returns a job after transfer
DELETE /api/jobs/{job_id}                       cancel log scan / remove job
GET    /api/server-logs/{id}/events             after, limit, level, query, thread,
                                               trace_id, request_id, since, until
GET    /api/server-logs/{id}/events/{event_id}   optional source_session
POST   /api/analyze/incident                   saved server_log_id, heap_id and/or
                                               thread_id, optional gc_id,
                                               source_session, window_seconds
```

Run the reproducible capacity check with
`backend/.venv/bin/python backend/tools/benchmark_server_log.py --gib 5`.
It exercises the production upload/index functions with streamed synthetic data,
writes real temporary files, verifies byte/event counts and final-event queries,
then removes its files. It is a synthetic capacity check, not a production
throughput guarantee or a reverse-proxy/browser transport benchmark.
