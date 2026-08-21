# tfa — Thread Flow Analyzer

Reconstructs per-thread execution flows from an offline log dump, compares
flows of the same kind against each other, and ranks the deviations. **The
population is the baseline** — no golden path is authored.

Runs locally and offline, streaming only, with flat memory over an arbitrarily
large corpus. See the V1 engineering charter for the full design.

## Modules

| Module | Contents |
|---|---|
| `tfa-core` | The library. No framework. Ingestion + model (Phase 1); segmentation, clustering, baselining, detection, ranking, reporting land in later phases. |
| `tfa-cli` | Thin CLI over the library — argument parsing only. |
| `tfa-testkit` | Synthetic log generation for tests. |

Public entry point (future POSTMORTEM integration seam):
`AnalysisResult analyze(Path logDirectory, AnalysisConfig config)` — added as the
pipeline is built out.

## Build

```bash
cd tfa
mvn test          # compile + run unit tests
mvn -DskipTests package   # build the CLI jar at tfa-cli/target/tfa.jar
```

Requires JDK 21.

## Phase 1 — ingestion (implemented)

Turns a directory of files into an ordered stream of `LogRecord`.

- **Format profiles (§3.4)** — a named, reusable definition supplying an
  envelope regex with canonical named groups (`ts, level, thread, class, line,
  msg`), a separate timestamp pattern, an explicit zone, and a declared
  capability set. The default profile matches
  `timestamp | LEVEL | threadId | Classname:lineNumber | message`. Load custom
  profiles from YAML with `--profile`.
- **Record contract (§3.2)** — one record = one envelope-matched line plus every
  following non-matching line (stack frames, multi-line payloads). Continuation
  lines are never dropped. Every input line lands in exactly one bucket:
  matched, continuation, or malformed; all three are counted. A non-matching
  line before *any* matched line in the corpus is malformed; once a record is
  open, non-matching lines are continuations — including across a file
  (rotation) boundary.
- **File ordering** — files are ordered by the first parseable timestamp inside
  them, never by filename.
- **Fail fast** — before streaming, a head sample is checked against the profile;
  below the threshold (default 95%) the run aborts and prints the failing lines
  rather than silently analysing a fraction of the corpus.

### CLI

```bash
# Parse a directory and print ingestion statistics
tfa parse <dir> [--profile <yaml>] [--profile-name <name>] \
                [--threshold 0.95] [--sample 1000]

# Sample a file and print a proposed format profile as YAML
tfa detect-format <file> [--sample 500]
```

`tfa parse` reports per-bucket line counts, record count, distinct threads,
distinct call sites, timestamp range, wall time, and peak heap.

## Phase 2 — episode segmentation (implemented)

Splits each thread's record stream into **episodes** — one contiguous execution
of one flow on one thread. A pooled thread runs request after request, so
`exec-7` at 14:32 and `exec-7` at 14:35 are different episodes.

- **`FlowKeyStrategy`** is the pluggable segmentation contract; nothing
  downstream depends on which implementation ran. To honor the streaming
  constraint (a thread may have millions of records), strategies express their
  logic as an incremental `ThreadSegmenter`, and `StreamingSegmenter` drives it
  over the whole stream holding only one open episode per active thread.
  - **`EntryMarkerStrategy`** (A) — a new episode begins at an entry call site
    and ends at a terminal (COMPLETED) or when the next entry appears
    (TRUNCATED). An ERROR-level record makes the episode ERRORED.
  - **`IdleGapStrategy`** (B) — a new episode begins when the gap since the
    previous record on the thread exceeds a threshold; status is TRUNCATED
    unless a configured terminal was reached.
  - **`CorrelationIdStrategy`** (C) — a stub proving the interface accommodates a
    future cross-thread key. Not implemented in V1.
- Strategy choice, entry/terminal call-site sets, and the gap threshold come
  from the run config (`AnalysisConfig`), populated from the Phase 0 report.

### CLI

```bash
tfa segment <dir> --config <yaml>
```

Prints total episodes, status breakdown, episodes-per-thread /
records-per-episode / episode-duration histograms, and the 10 longest episodes
with their call-site sequences.

Example config:

```yaml
profile: default
segmentation:
  strategy: ENTRY_MARKER            # ENTRY_MARKER | IDLE_GAP | CORRELATION_ID
  entryCallSites: [com.acme.web.Dispatcher:10]
  terminalCallSites: [com.acme.web.Dispatcher:99]
  idleGapMillis: 5000               # used by IDLE_GAP
```

> Note: duplicate appenders (§3.5) are not yet deduped — the Phase 0 recon
> measures the rate, and the dedupe decision is deferred. Under `IDLE_GAP`,
> duplicated records from a second appender file can surface as extra
> single-record episodes; `ENTRY_MARKER` drops them as orphan non-entry records.

## Phase 3 — flow clustering (implemented)

Groups episodes that represent the same kind of flow, so a login flow and a
nightly batch job are never compared against each other.

- **Signature = the first K call sites** of the episode (K configurable, default
  3). Episodes that begin identically are the same kind of work.
- Clusters below `minClusterSize` (default 10) are marked **UNDER_SAMPLED** and
  excluded from baselining — you cannot derive a consensus from three examples —
  but they are still reported, since a rare flow is itself interesting.
- A cluster count above `clusterCeiling` (default 200) warns that K is too large.

### CLI

```bash
tfa cluster <dir> --config <yaml>
```

Prints cluster count, episode total, under-sampled count, a cluster-size
distribution, and the top 20 clusters by size with their signature and a
representative episode.

Config additions:

```yaml
clustering:
  signatureK: 3
  minClusterSize: 10
  clusterCeiling: 200
```
