# TFA Phase 0 — Corpus reconnaissance (throwaway)

> **This is not shipped code.** It is the Phase 0 reconnaissance script from the
> Thread Flow Analyzer charter. Its only job is to profile a real log dump so its
> output can configure Phase 2 (episode segmentation). It is expected to be
> deleted once Phase 1 lands. No abstractions live here on purpose.

## What it answers

Runs against a directory of application log files and prints (plus optional JSON):

1. **Corpus** — file/line/byte counts, timestamp range, per-file first/last
   timestamp (files are ordered by timestamp, never filename), and the
   matched / continuation / malformed line split with a malformed sample.
2. **Threads** — distinct thread count, records-per-thread histogram, and the
   within-thread inter-record gap histogram used to choose an idle-gap threshold.
3. **Call sites** — distinct count, top-50 by frequency, and a package-prefix
   split (app code vs Spring/Hibernate/Tomcat/Hikari/JDK…).
4. **Entry / terminal candidates** — the important one. For gap thresholds of
   1s, 5s and 30s it computes `first_after_gap`, `mid_sequence` and
   `last_before_gap` per call site, ranks entry and terminal candidates, and
   states plainly whether a small set of call sites dominates as entry points
   (→ `EntryMarkerStrategy`) or the distribution is flat (→ `IdleGapStrategy`).
5. **Levels** — record count by level, per-hour level mix (to spot a logging
   config change mid-capture), and stack-trace record count.
6. **Integrity** — cross-file duplicate rate (duplicate appenders) and
   boundary pressure (threads active in the first/last 60s → censoring
   candidates).

## Usage

```bash
python3 recon/profile_corpus.py <log-dir> [--json out.json] [--no-dupes] \
        [--top-callsites 50] [--top-entries 30]
```

- Streams line by line; memory is bounded by #threads and #call-sites.
- Cross-file duplicate detection keeps one hash per distinct record tuple; pass
  `--no-dupes` to disable it on an extremely large corpus.
- Assumes the default TFA envelope
  `timestamp | LEVEL | threadId | Classname:lineNumber | message`.
  A non-matching line is a continuation of the preceding record, unless it
  appears before any matched line in a file, in which case it is malformed.

## Reading the output

The **verdict** at the end of section 4 decides Phase 2's strategy. If a handful
of call sites carry ~all first-after-gap records at a ratio ≥ 0.80, seed
`EntryMarkerStrategy`'s entry/terminal sets from the ranked lists. If the
distribution is flat, use `IdleGapStrategy` and pick its threshold from the
section-2 gap histogram (the smallest bucket boundary that sits in the valley
between intra-episode gaps and inter-episode idle time).
