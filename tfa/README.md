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

## Phase 4 — consensus baseline (implemented)

Derives what "normal" looks like per cluster, over **collapsed** call-site
sequences (loops and retries collapsed to a single element with a repeat count,
so a retry storm doesn't swamp the comparison). Each `Episode` keeps both forms:
raw (`callSiteSequence()`) and collapsed (`collapsedSequence()` /
`collapsedRuns()`).

For each cluster above the minimum size, `ConsensusBuilder` computes a
`Baseline`:

1. **Modal sequence** — the most frequent exact collapsed sequence, with the
   share of episodes matching it, plus the top alternative sequences.
2. **Positional distribution** — per modal position, the frequency of each call
   site observed there (so a finding can read "94% went to X here").
3. **Transition probabilities** — P(B follows A) within the cluster.
4. **Transition timing** — median and p95 elapsed time per transition.

Everything is deterministic (ties broken lexicographically) for reproducibility.

**Baseline windowing**: the baseline can be derived from one time-bounded subset
(e.g. day 1) and evaluated against another (e.g. day 3). This matters — if the
defect is present throughout the baseline window, it becomes "normal" and is
never flagged.

### CLI

```bash
tfa baseline <dir> --config <yaml>
```

Prints, per cluster: modal sequence and its share, the top alternative
sequences, and the slowest transitions by p95.

Config additions:

```yaml
baseline:
  window:                     # optional; restricts which episodes form the baseline
    start: "2026-08-20T00:00:00Z"
    end:   "2026-08-21T00:00:00Z"
  evalWindow:                 # optional; restricts which episodes detection evaluates (Phase 5)
    start: "2026-08-22T00:00:00Z"
    end:   "2026-08-23T00:00:00Z"
  alternatives: 3
```

## Phase 5 — detection (implemented)

Three independent detectors, each taking `(Episode, Baseline)` and returning zero
or more `Finding`s. **Log level is never a detection trigger** — an ERROR record
is a ranking input, not a detector; the valuable defects are flows that silently
took a wrong branch and logged nothing at ERROR.

1. **TruncationDetector** — the episode did not complete, or the modal terminal
   was never reached. The primary "the flow broke" signal.
2. **DivergenceDetector** — compares the episode's collapsed sequence against the
   modal sequence and reports the FIRST position where they differ, with what the
   majority did there and how strong it was ("94% went to X here, this went to Y").
3. **TimingDetector** — any transition whose elapsed time exceeds baseline p95 by
   a factor (default 3x). Measured over collapsed runs, so a fast retry storm
   doesn't trip it.

**Boundary censoring (§3.5)**: `DetectionEngine` censors episodes overlapping a
margin (default: one p99 episode duration) of the corpus start/end before any
detector runs — they're usable for baselining but never eligible as findings, so
the top findings aren't just the requests in flight when the dump was taken.
Under-sampled clusters have no baseline and are skipped for detection.

### CLI

```bash
tfa detect <dir> --config <yaml>
```

Lists the raw (unranked) findings per cluster. Ranking, dedup, and the report
land in Phase 6 (`tfa analyze`).

Config additions:

```yaml
detection:
  timingFactor: 3.0
  censorMarginMillis: 60000   # optional; omit to derive from the p99 episode duration
```

> Note: because clusters group by the first K call sites, a divergence must occur
> **after** the signature prefix to be compared within its cluster. If a defect
> diverges within the first K call sites it forms its own (often under-sampled)
> cluster; lower K (or the Phase 0 entry analysis) governs this. On the sample
> corpus, K=2 keeps the divergent error flow in the main cluster and both the
> divergence and truncation detectors fire on it.
