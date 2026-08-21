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
