# POSTMORTEM — Java Dump Analyzer

**v0.2.0** — a self-hosted web app for analyzing JVM **thread dumps** and **heap dumps** (up to 25GB+). Drop a file, get a structured diagnosis with concrete remediation steps. Attach your source repo and findings point straight to the line of code responsible.

```
┌─────────────────┐   ┌──────────────────────┐   ┌──────────────────┐
│  jstack /.hprof │ → │  streaming analyzers │ → │  React workbench │
│  (up to 25GB+)  │   │  + source indexer    │   │  + source view   │
└─────────────────┘   └──────────┬───────────┘   └──────────────────┘
                                 │
                                 └── (optional) Anthropic API
                                     for AI-powered diagnosis
```

## What it analyzes

**Thread dumps (jstack output)**
- Parses HotSpot/OpenJDK output (Java 8 through current)
- Detects JVM-reported deadlocks and reconstructs cycles
- Identifies lock contention (many threads BLOCKED on same monitor)
- Builds blocking chains (`A waits on lock held by B who waits on C…`)
- Clusters threads by identical top-of-stack (find hot code paths)
- Pattern recognition: HikariCP / JDBC pool exhaustion, HTTP client exhaustion, Tomcat saturation, ThreadLocal leak signatures

**Heap dumps (.hprof binary, up to 50GB)**
- Buffered streaming parser — no full-file load
- Async job model with live upload + parse progress, ETA, instances/sec
- Class histogram by instance count and shallow size — sized the way the JVM actually
  allocates (object header + 8-byte alignment, references at their live width), not the raw
  hprof payload length. The assumed layout is reported as `sizing_model`; override with `HEAP_OOPS`
- Detects classic leak signatures
- **Dominator tree with exact retained sizes** (dumps ≤512MB by default) — the
  Eclipse MAT core primitive: biggest objects by *retained* size, a MAT-style **leak
  suspects report** with the accumulation point, **unreachable-object** accounting,
  and a **duplicate classes** report (same class, multiple loaders)
- **Static-field leak finder** — mines `CLASS_DUMP` static fields (GC roots) and, with source attached, points an unbounded `static` cache/registry at the exact declaration line
- **Wasteful-memory detector** — a bounded extra pass hashes `byte[]`/`char[]` contents to find duplicate strings/buffers and reports the *actual reclaimable bytes* with example values (done in-process — no "go run MAT" hand-off)
- **Deployment (WAR/classloader) attribution** — reads the `classloader` + `protection domain` every `CLASS_DUMP` already carries and groups the heap *by deployed artifact*: which `.war`/`.ear` each class came from (resolved to the `file:/…/app.war!/WEB-INF/classes/` CodeSource), how much heap it holds, and its class count. Rides along on the main parse pass (HotSpot emits every class before the first instance), so it's free even on a 25GB dump
- **Thread → deployment attribution** — every live thread (`ROOT_THREAD_OBJ`) is tied to the application that created it, via the classloader of the thread's own class, the Runnable it wraps, or a *deliberately-set* context classloader (the default system loader is ignored, so `main` and JVM threads aren't miscounted). Answers "how many threads did this WAR create, and which of my classes are they?" — with a jvm-internal vs application split
- **Classloader-leak detection** — the classic redeploy leak: when two live classloaders serve the same `.war` and running threads pin the old one, that's a `CRITICAL` finding (a thread is a GC root, so it keeps the whole stale WAR — every class and static — alive forever, and the heap grows with each redeploy)
- Server-side path option — skip multi-GB uploads when the file is local
- "Quick mode" samples the first 256MB for huge dumps — and *says so*: the result carries
  `truncated` / `analyzed_bytes`, the summary is prefixed `PARTIAL:`, and the UI leads with a
  coverage banner. Any heavyweight stage that was gated out (dominator tree, retention tracing,
  duplicate scan) is listed in `skipped_analyses` with the reason and how to enable it, so a
  partial analysis can never be mistaken for a complete one
- **Exportable report** — every analysis view has an *export report* button that writes one
  self-contained HTML file: verdict, coverage, findings with source snippets, the top-10 tables,
  and the AI diagnosis if one was generated

**Source code repository integration (NEW)**
- Upload a `.zip` of your source tree, or point at a server-side directory
- Builds a class-name → file index from Java / Kotlin / Scala `package` declarations
- Each finding is enriched with the exact source location of the relevant frame
- Snippet of ±4 lines around the guilty line shown inline in finding cards
- Heuristic distinguishes user code from JDK/framework frames
- For heap dumps: when a class tops the histogram, finds where *your* code constructs/holds it (file, method, line)

**GC logs (`-Xlog:gc*` unified, or legacy `PrintGCDetails`) (NEW)**
- Streaming, dependency-free parser; detects the collector (G1 / Parallel / CMS / Serial / ZGC / Shenandoah)
- Computes throughput %, pause P50/P95/P99/max, allocation rate, and Full-GC / allocation-stall counts
- **Leak signal** — the linear-regression slope of post-GC heap occupancy: a rising floor that never resets is the over-time proof a single heap snapshot can't give
- Findings for leak trend, Full-GC thrash / pre-OOM, low throughput, long pauses, and allocation churn

**Dump comparison / delta (NEW)**
- Compare two heap dumps → ranks the classes that **grew** between captures; the biggest grower is the prime leak suspect (the classic two-snapshot leak workflow). With source attached, the top user-class grower resolves to where your code constructs it
- Compare two thread dumps → finds threads **stuck at the same stack frame in both** captures (a real hang, not a transient blip); BLOCKED ones are flagged critical
- Stateless over the serialized analyses, so any two prior analyses in the session can be diffed

**Cross-dump correlation (NEW)**
- Analyze a thread dump, a heap dump, *and* a GC log in one session and the workbench cross-references them
- A user class that both dominates the heap **and** is live on a thread stack is a double-confirmed pinpoint
- Heap dumps have no stack traces — so the heap-dominant class is bridged to the thread frame that *constructs or holds* it (via the source reference index), giving a real `file:line`
- **Three-pillar marriage** — when a GC log is present, its over-time trend confirms whether the heap's dominant class is a genuine leak (heap snapshot says *what's big*, GC log says *it's still growing*, thread dump says *where it's allocated*) → one high-confidence "confirmed memory leak" finding

**Optional AI diagnosis**
- Bring your own Anthropic API key — sent per-request, never stored on the server
- Produces a prescriptive, plain-English write-up
- When a thread dump + heap dump (+ source) are all present, the cross-dump panel offers a **unified diagnosis**: a single Problem → Evidence → Exact location (`file:line`) → Fix (with a code sketch) → Confidence write-up aimed at an entry-level developer

## Quick start

### Backend (FastAPI)

```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

### Frontend (React + webpack)

```bash
cd frontend
npm install
npm run dev      # webpack-dev-server on :5173, proxies /api/* to :8000
npm run build    # production build to dist/
```

The frontend uses a standard webpack + Babel + plain CSS stack — no Vite, no PostCSS, no Tailwind. All styling lives in `src/styles.css` with CSS custom properties for the design tokens.

### Tests (backend)

```bash
cd backend
pip install -r requirements-dev.txt   # adds pytest
pytest                                 # ~40 tests, runs in well under a second
```

`tests/hprof_builder.py` programmatically constructs valid `.hprof` byte streams
(classes, instances, object/primitive arrays, static + instance-field references,
GC roots), and `tests/fixtures/src/` is a small Java/Kotlin repo — together they let
the suite assert exact, known-correct output for the histogram, the static-field
leak finder, the retention tracer, and the thread × heap correlation. `tests/*.txt`
are real-world sample dumps; `tests/generate_big_hprof.py` makes multi-GB dumps for
scale testing.

## How to generate dumps

```bash
# Thread dump
jstack <pid> > thread-dump.txt
# or:  kill -3 <pid>
# or:  jcmd <pid> Thread.print > thread-dump.txt

# Heap dump
jmap -dump:format=b,file=heap.hprof <pid>
# or:  jcmd <pid> GC.heap_dump /path/to/heap.hprof
# or auto on OOM:  -XX:+HeapDumpOnOutOfMemoryError -XX:HeapDumpPath=/var/log/
```

## API endpoints

```
GET  /api/health                        liveness + active session count
POST /api/analyze/thread                jstack upload (form: file, optional source_session)
POST /api/analyze/gc                     GC log upload (-Xlog:gc* or legacy), synchronous
POST /api/analyze/heap                  small heap upload (<200MB, synchronous)
POST /api/analyze/heap/async            big heap upload → returns job_id immediately
POST /api/analyze/heap/path             parse a .hprof already on the server
GET  /api/jobs/{job_id}                 poll job progress; includes result when done
DELETE /api/jobs/{job_id}               clean up a job + its temp file
POST /api/source/upload                 zip of source code → session_id
POST /api/source/path                   index a server-side source directory
POST /api/source/git                    fetch + index source from a GitHub/Bitbucket/GitLab URL
GET  /api/source/{session}/lookup       resolve class+line → file & code snippet
DELETE /api/source/{session}            release a source session
POST /api/correlate                     cross-reference heap + thread (+ optional gc, source) → findings
POST /api/compare/heap                   diff two heap analyses → class growth / leak suspects
POST /api/compare/threads                diff two thread dumps → persistently-stuck threads
POST /api/llm/summarize                 optional Claude diagnosis (BYO API key)
```

## Architecture

```
backend/
  app/
    main.py                    FastAPI routes, CORS, upload chunking, async jobs
    schemas.py                 Pydantic models (incl. SourceLocation, JobStatus)
    sessions.py                In-memory source-session + job stores
    analyzers/
      thread_dump.py           Regex-based jstack parser
      diagnostics.py           Findings engine, stack clustering, chains,
                               + source-location enrichment
      heap_dump.py             Streaming .hprof parser with buffered reader,
                               progress callback (≈50x speedup), + static-field
                               leak finder (GC-root → source line)
      source.py                Repo indexer: package decl → FQCN → file path,
                               handles inner classes, lambdas, anonymous classes;
                               static-field + reference resolution
      heap_graph.py            In-process retention tracer — reverse-path from the
                               top consumer to the holding field (no MAT, bounded)
      gc_log.py                Streaming GC-log parser — throughput, pauses, and the
                               post-GC occupancy trend (the leak signal)
      correlate.py             Thread × heap × GC × source cross-referencing engine
      compare.py               Delta engine — heap growers + persistently-stuck threads
      heap_waste.py            Duplicate byte[]/char[] detector — quantified reclaimable bytes
      heap_deployments.py      WAR/classloader + thread attribution — groups the heap by
                               deployed artifact; classloader-leak (redeploy) detection
      heap_dominators.py       Dominator tree (Lengauer–Tarjan) — exact retained sizes,
                               leak suspects, unreachable objects (gated by dump size)
      llm.py                   Pluggable Anthropic API caller
  tests/sample_thread_dump.txt Example dump with deadlock + contention

frontend/
  src/
    App.jsx                    View routing + async-job polling loop
    api.js                     Fetch + XHR (upload progress) wrappers
    components/
      Hero.jsx                 Landing + drag-and-drop + server-path option
      SourceUpload.jsx         Zip-upload OR server-side path for source repo
      HeapProgress.jsx         Two-phase progress: upload → parse, with ETA
      SourceSnippet.jsx        File path + numbered lines, guilty line highlighted
      Findings.jsx             Severity-coded findings with inline source snippets
      ThreadAnalysis.jsx       Threads table, deadlock cycles, blocked chains
      HeapAnalysis.jsx         Histograms by instance count / shallow size
      CorrelationPanel.jsx     Thread × heap cross-dump diagnosis (auto-shown when both exist)
      LLMPanel.jsx             Optional AI diagnosis panel
```

## Design notes — handling 25GB+ heap dumps

The parser is genuinely streaming: it walks records sequentially, never holds the whole dump in memory, and aggregates only small Counter-style histograms keyed by class id. The bottleneck on big files is the rate of small reads — `.hprof` records can be 1-8 bytes — so we use a 4MB read buffer. That alone gives roughly a 50x speedup compared to a naive reader.

For the async pipeline:

1. Client uploads via `POST /api/analyze/heap/async`; chunks are streamed to a temp file in `DUMP_TMP_DIR` (override via env var to point at a big-disk volume).
2. The endpoint returns a `JobStatus` immediately with `job_id`.
3. A background asyncio task runs the parser inside `asyncio.to_thread` (keeps the event loop responsive).
4. The parser fires a progress callback every ~5K records (top-level and mid-segment), updating an in-memory job state.
5. Client polls `GET /api/jobs/{job_id}` every ~500ms; UI shows bytes processed, instances counted, elapsed, and ETA.
6. When `status == "done"`, the result is included in the poll response.

For setups where the dump already lives on the same host as the server (self-hosted, common case), `POST /api/analyze/heap/path` skips the upload entirely. Bear the security implication in mind: the server reads whatever path you point at, so don't expose this endpoint publicly without authentication.

## Design notes — source code integration

The `SourceIndex` walks a directory, finds `.java` / `.kt` / `.scala` files, parses the `package` declaration from the first ~50 lines, and combines it with the filename to form a fully-qualified class name. Inner classes, lambdas, and anonymous classes (`Foo$Bar`, `Foo$$Lambda$1/...`) all collapse to the outer file via a simple `$`-strip.

When diagnostics run with a source index attached, each finding gets enriched: for the threads it affects, the analyzer walks the stack and picks the most relevant frame — the one holding the lock for deadlocks/contention, or the first user-code frame otherwise. "User code" is anything not starting with `java.`, `jdk.`, `org.springframework.`, `io.netty.`, and similar known prefixes. The result is a `SourceLocation` with `class_name`, `method`, `line`, an `is_user_code` flag, and (when resolved) a `repo_path` plus a `SourceSnippet` of ±4 surrounding lines.

The UI shows these inline in each finding card with the guilty line highlighted and prefixed `▸`. When source isn't attached, only the class/method/line tuple is shown.

## Coverage vs Eclipse MAT / IBM HeapAnalyzer / VisualVM

| Capability | MAT | IBM HA | VisualVM | POSTMORTEM |
|---|---|---|---|---|
| Class histogram (count / shallow size) | ✓ | ✓ | ✓ | ✓ |
| **Dominator tree / exact retained sizes** | ✓ | ✓ | ✓ | ✓ dumps ≤512MB by default (`HEAP_DOMINATOR_MAX_BYTES` to raise); heuristic retention path above the gate |
| Leak suspects report (with accumulation point) | ✓ | ✓ | — | ✓ |
| Unreachable-object accounting | ✓ | ✓ | — | ✓ |
| Duplicate classes / classloader explorer | ✓ | — | — | ✓ (deployments panel + duplicate-classes report) |
| Thread analysis from the heap | ✓ + stacks & locals | — | ✓ + stacks | partial — live threads, daemon flags and thread→WAR attribution (which MAT doesn't do), but **no stack traces**: the hprof `TRACE`/`FRAME` records are skipped, so a jstack is still needed for stacks |
| Duplicate strings/arrays with reclaimable bytes | ✓ | — | — | ✓ |
| Two-snapshot comparison / delta | ✓ | ✓ | ✓ | ✓ |
| Path to GC roots | ✓ any object | ✓ | ✓ | partial — top consumer only (`heap_graph`), plus dominator ownership chains |
| OQL / arbitrary queries | ✓ | — | ✓ | ✗ |
| Interactive object browsing (expand any object) | ✓ | ✓ | ✓ | ✗ |
| IBM J9 dumps (PHD / javacore) | via DTFJ | ✓ | — | ✗ HotSpot hprof only |
| Collection queries (fill ratio, collisions, empty collections) | ✓ | — | — | ✗ — the waste scan hashes `byte[]`/`char[]` content only |
| Histogram grouped by package / superclass | ✓ | partial | — | ✗ — grouping by classloader exists (deployments), by package does not |
| System properties / JVM args recovered from the heap | ✓ | partial | partial | ✗ |
| Coverage honesty — states which stages ran on this dump | — | — | — | ✓ `truncated`, `analyzed_bytes`, `skipped_analyses` |
| Shareable report file | ✓ HTML, headless | partial | — | ✓ HTML, includes the AI diagnosis |
| Live JVM monitoring / profiling | — | — | ✓ | ✗ out of scope (dump analysis only) |
| **Source-repo integration → finding at `file:line`** | ✗ | ✗ | ✗ | ✓ |
| **Heap + GC-log + thread-dump correlation** | ✗ | ✗ | ✗ | ✓ |
| Headless / self-hosted / shareable analysis | ✗ | ✗ | ✗ | ✓ |

The honest summary: within the dominator-tree size gate the retained numbers are
**exact — the same numbers MAT reports**. What remains MAT-only is the interactive
workflow (browse any object, OQL, arbitrary GC-root paths) and very large dumps'
retained sizes, where our answer degrades to the bounded heuristic tracer. The
right-hand rows are the other direction: things none of the three desktop tools do.

## Environment variables

| Variable | Default | Effect |
|---|---|---|
| `ANTHROPIC_MODEL` | `claude-opus-5` | Model used for the AI diagnosis. Set this if your organisation doesn't have access to the default — the UI also has a per-request model picker. The API key itself is never read from the environment; it is supplied per request and discarded |
| `HEAP_DOMINATOR_MAX_BYTES` | `512MB` | Ceiling for exact retained sizes; `HEAP_DOMINATOR=0` disables |
| `HEAP_GRAPH_MAX_BYTES` | `2GB` | Ceiling for the heuristic retention tracer; `HEAP_GRAPH_TRACE=0` disables |
| `HEAP_WASTE_MAX_BYTES` | `2GB` | Ceiling for the duplicate-array scan; `HEAP_WASTE_TRACE=0` disables |
| `HEAP_OOPS` | `auto` | Object layout for shallow sizes: `compressed`, `uncompressed`, or `auto` (compressed below a 32GB dump, which is where HotSpot switches). The choice is reported as `sizing_model` on every analysis |
| `DUMP_TMP_DIR` | `/tmp/postmortem` | Where uploaded dumps are staged — point at a big-disk volume |

Whenever a stage is gated out by one of the ceilings above, it is listed in the
analysis's `skipped_analyses` with the reason and the variable that would enable it,
and the UI shows it in the coverage banner. A gated analysis never looks like a
complete one.

## Limitations

This is an MVP. Things it explicitly **does not** do (yet):
- Compute exact retained sizes on very large dumps. The full dominator tree (exact
  retained sizes, leak suspects, unreachable objects) auto-runs on dumps ≤512MB —
  raise `HEAP_DOMINATOR_MAX_BYTES` if you have the RAM (expect ~2-4x the dump size),
  or `HEAP_DOMINATOR=0` to disable. Above the gate you get the heuristic, sampled
  **retention path** from the top consumer to the holding field instead (≤2GB,
  `HEAP_GRAPH_MAX_BYTES`)
- OQL or interactive object browsing (expand-any-object). For ad-hoc queries over an
  arbitrary object, use Eclipse MAT
- Parse non-HotSpot dumps (J9, Zing, etc.)
- Persist analyses or source sessions across restarts (in-memory only)
- Authenticate or authorize requests (designed for single-user self-hosted)

## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 Sushil Sharma.
