#!/usr/bin/env python3
"""
Phase 0 — Corpus reconnaissance for the Thread Flow Analyzer (TFA).

THROWAWAY. Not shipped. Deleted after Phase 1. No abstractions on purpose.

Goal: profile a directory of application log files and print a report that
answers, empirically, how episodes should be segmented (which in turn
configures Phase 2).

Log line envelope (the default TFA format):

    timestamp | LEVEL | threadId | Classname:lineNumber | message

Continuation lines (stack-trace frames, multi-line payloads) do NOT match the
envelope and belong to the preceding record. A non-matching line that appears
before any matched line in a file is MALFORMED, not a continuation.

The script streams: it never loads whole files into memory. Aggregates it keeps
are bounded by #threads and #call-sites (both small relative to line count).
The one exception is cross-file duplicate detection, which keeps one hash per
distinct record tuple; use --no-dupes to disable it on a truly huge corpus.

Usage:
    python3 profile_corpus.py <log-dir> [--json out.json] [--no-dupes]
                              [--top-callsites 50] [--top-entries 30]
"""

from __future__ import annotations

import argparse
import gzip
import io
import json
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta

# --- envelope -------------------------------------------------------------

# timestamp | LEVEL | threadId | Classname:lineNumber | message
# msg is rest-of-line: it may contain '|', so it is captured greedily to EOL.
ENVELOPE = re.compile(
    r"^(?P<ts>\S+ \S+)\s*\|\s*"
    r"(?P<level>\w+)\s*\|\s*"
    r"(?P<thread>[^|]+?)\s*\|\s*"
    r"(?P<cls>[^:|]+):(?P<line>\d+)\s*\|\s*"
    r"(?P<msg>.*)$"
)

# lines that look like a Java stack frame or exception header
STACK_FRAME = re.compile(r"^\s*(at\s+\S+\(|Caused by:|\.\.\.\s+\d+\s+more|"
                         r"[\w.$]+(Exception|Error|Throwable)\b)")

TS_FORMATS = (
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S,%f",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%d/%b/%Y:%H:%M:%S",
)

# gap thresholds (seconds) evaluated for entry/terminal candidate analysis
GAP_THRESHOLDS = (1.0, 5.0, 30.0)

# inter-record gap histogram buckets (label, upper-bound-seconds)
GAP_BUCKETS = (
    ("<100ms", 0.1),
    ("<1s", 1.0),
    ("<5s", 5.0),
    ("<30s", 30.0),
    ("<5m", 300.0),
    ("longer", float("inf")),
)

# records-per-thread histogram buckets (label, upper-bound inclusive)
COUNT_BUCKETS = ((1, 1), (5, 5), (25, 25), (100, 100),
                 (1000, 1000), (10000, 10000), (float("inf"), float("inf")))


def parse_ts(s: str):
    for fmt in TS_FORMATS:
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


def open_text(path):
    if path.endswith(".gz"):
        return io.TextIOWrapper(gzip.open(path, "rb"), encoding="utf-8",
                                errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def iter_files(root):
    if os.path.isfile(root):
        yield root
        return
    for dirpath, _dirs, names in os.walk(root):
        for n in sorted(names):
            p = os.path.join(dirpath, n)
            if os.path.isfile(p):
                yield p


def first_timestamp(path):
    """Cheap pre-scan: read until the first envelope-matched, parseable ts."""
    try:
        with open_text(path) as fh:
            for _i, raw in enumerate(fh):
                if _i > 5000:      # give up; file has no parseable header early
                    return None
                m = ENVELOPE.match(raw.rstrip("\n"))
                if m:
                    ts = parse_ts(m.group("ts"))
                    if ts:
                        return ts
    except OSError:
        return None
    return None


def bucket_gap(seconds):
    for label, ub in GAP_BUCKETS:
        if seconds < ub:
            return label
    return "longer"


def bucket_count(n):
    for label, ub in COUNT_BUCKETS:
        if n <= ub:
            return f"<={label}" if label != float("inf") else ">10000"
    return ">10000"


class Recon:
    def __init__(self, want_dupes):
        self.want_dupes = want_dupes

        # CORPUS
        self.file_count = 0
        self.total_lines = 0
        self.total_bytes = 0
        self.corpus_min = None
        self.corpus_max = None
        self.per_file = {}          # path -> [first_ts, last_ts, lines]
        self.buckets = Counter()    # matched / continuation / malformed
        self.malformed_sample = []

        # THREADS
        self.thread_count = Counter()      # thread -> #records
        self.thread_last_ts = {}           # thread -> datetime (streaming)
        self.thread_first_ts = {}          # thread -> datetime
        self.gap_hist = Counter()          # gap bucket label -> count

        # CALL SITES
        self.callsite_count = Counter()    # callsite -> #records
        self.package_split = Counter()     # package prefix -> #records

        # ENTRY / TERMINAL   thr -> callsite -> {first, mid, last}
        self.et = {thr: defaultdict(lambda: [0, 0, 0]) for thr in GAP_THRESHOLDS}
        # per-thread previous callsite, for terminal accounting
        self.thread_last_cs = {}

        # LEVELS
        self.level_count = Counter()
        self.level_by_hour = defaultdict(Counter)   # "YYYY-MM-DD HH" -> level -> n
        self.stacktrace_records = 0

        # INTEGRITY
        self.dupe_seen = {}         # tuple-hash -> filename (first sighting)
        self.dupe_cross_file = 0
        self.dupe_hashes_flagged = set()

    # -- per-record ingestion ------------------------------------------------

    def record(self, path, ts, level, thread, callsite, cls, msg, has_stack):
        # CORPUS bounds
        if ts is not None:
            if self.corpus_min is None or ts < self.corpus_min:
                self.corpus_min = ts
            if self.corpus_max is None or ts > self.corpus_max:
                self.corpus_max = ts
            pf = self.per_file[path]
            if pf[0] is None or ts < pf[0]:
                pf[0] = ts
            if pf[1] is None or ts > pf[1]:
                pf[1] = ts

        # CALL SITES
        self.callsite_count[callsite] += 1
        self.package_split[package_prefix(cls)] += 1

        # LEVELS
        self.level_count[level] += 1
        if ts is not None:
            self.level_by_hour[ts.strftime("%Y-%m-%d %H")][level] += 1
        if has_stack:
            self.stacktrace_records += 1

        # THREADS + ENTRY/TERMINAL (needs previous record on same thread)
        self.thread_count[thread] += 1
        prev_ts = self.thread_last_ts.get(thread)
        prev_cs = self.thread_last_cs.get(thread)

        if ts is not None and prev_ts is not None:
            gap = (ts - prev_ts).total_seconds()
            if gap < 0:
                gap = 0.0
            self.gap_hist[bucket_gap(gap)] += 1
            for thr in GAP_THRESHOLDS:
                if gap > thr:
                    self.et[thr][callsite][0] += 1        # first_after_gap
                    if prev_cs is not None:
                        self.et[thr][prev_cs][2] += 1      # prev = last_before_gap
                else:
                    self.et[thr][callsite][1] += 1        # mid_sequence
        else:
            # first record on this thread (or unparseable ts): treat as entry
            for thr in GAP_THRESHOLDS:
                self.et[thr][callsite][0] += 1

        if ts is not None:
            self.thread_last_ts[thread] = ts
            if thread not in self.thread_first_ts:
                self.thread_first_ts[thread] = ts
        self.thread_last_cs[thread] = callsite

        # INTEGRITY — duplicate detection across files
        if self.want_dupes and ts is not None:
            h = hash((self.per_file_ts_key(ts), thread, callsite, msg))
            prev_file = self.dupe_seen.get(h)
            if prev_file is None:
                self.dupe_seen[h] = path
            elif prev_file != path:
                self.dupe_cross_file += 1
                self.dupe_hashes_flagged.add(h)

    @staticmethod
    def per_file_ts_key(ts):
        return ts.strftime("%Y-%m-%d %H:%M:%S.%f")

    def finalize_terminals(self):
        # every thread's final record is a last_before_gap for all thresholds
        for thread, cs in self.thread_last_cs.items():
            for thr in GAP_THRESHOLDS:
                self.et[thr][cs][2] += 1


def package_prefix(cls):
    """Coarse package/vendor bucket for a class name."""
    if "." not in cls:
        return "(simple) " + cls.split("$")[0]
    dotted = cls
    for prefix, label in (
        ("org.springframework", "spring"),
        ("org.hibernate", "hibernate"),
        ("org.apache.catalina", "tomcat"),
        ("org.apache.coyote", "tomcat"),
        ("com.zaxxer.hikari", "hikari"),
        ("org.apache", "apache"),
        ("java.", "jdk"),
        ("javax.", "jdk"),
        ("jakarta.", "jakarta"),
        ("io.netty", "netty"),
        ("reactor.", "reactor"),
        ("ch.qos.logback", "logback"),
        ("org.slf4j", "slf4j"),
    ):
        if dotted.startswith(prefix):
            return label
    parts = dotted.split(".")
    return ".".join(parts[:3]) if len(parts) >= 3 else dotted


def ingest(root, want_dupes):
    r = Recon(want_dupes)

    files = list(iter_files(root))
    # order files by first parseable timestamp, NOT by filename
    ordered = sorted(files, key=lambda p: (first_timestamp(p) or datetime.max, p))

    for path in ordered:
        r.file_count += 1
        r.per_file[path] = [None, None, 0]
        try:
            r.total_bytes += os.path.getsize(path)
        except OSError:
            pass

        # streaming state for the current open record
        cur = None      # dict of open record fields
        cur_has_stack = False

        def flush():
            nonlocal cur, cur_has_stack
            if cur is not None:
                r.record(path, cur["ts"], cur["level"], cur["thread"],
                         cur["callsite"], cur["cls"], cur["msg"], cur_has_stack)
            cur = None
            cur_has_stack = False

        try:
            with open_text(path) as fh:
                for raw in fh:
                    line = raw.rstrip("\n")
                    r.total_lines += 1
                    r.per_file[path][2] += 1
                    m = ENVELOPE.match(line)
                    if m:
                        flush()
                        r.buckets["matched"] += 1
                        cur = {
                            "ts": parse_ts(m.group("ts")),
                            "level": m.group("level"),
                            "thread": m.group("thread").strip(),
                            "cls": m.group("cls").strip(),
                            "callsite": f"{m.group('cls').strip()}:{m.group('line')}",
                            "msg": m.group("msg"),
                        }
                        cur_has_stack = False
                    elif cur is not None:
                        r.buckets["continuation"] += 1
                        if not cur_has_stack and STACK_FRAME.match(line):
                            cur_has_stack = True
                    else:
                        r.buckets["malformed"] += 1
                        if len(r.malformed_sample) < 20 and line.strip():
                            r.malformed_sample.append((path, r.per_file[path][2], line))
                flush()
        except OSError as e:
            print(f"WARN: could not read {path}: {e}", file=sys.stderr)

    r.finalize_terminals()
    return r


# --- reporting ------------------------------------------------------------

def hbar(n, total, width=40):
    if total <= 0:
        return ""
    filled = int(round(width * n / total))
    return "#" * filled


def report_text(r, top_callsites, top_entries, out=sys.stdout):
    p = lambda *a: print(*a, file=out)
    line = "=" * 78

    p(line)
    p("TFA PHASE 0 — CORPUS RECONNAISSANCE")
    p(line)

    # 1. CORPUS
    p("\n1. CORPUS")
    p(f"   files            : {r.file_count}")
    p(f"   total lines      : {r.total_lines:,}")
    p(f"   total bytes      : {r.total_bytes:,} ({r.total_bytes/1e6:.1f} MB)")
    p(f"   timestamp range  : {r.corpus_min}  ->  {r.corpus_max}")
    total_env = r.buckets['matched'] + r.buckets['continuation'] + r.buckets['malformed']
    p("   lines by bucket  :")
    for b in ("matched", "continuation", "malformed"):
        n = r.buckets[b]
        pct = 100.0 * n / total_env if total_env else 0.0
        p(f"       {b:<13}: {n:>12,}  ({pct:5.2f}%)")
    p("\n   files in TIMESTAMP order (first / last ts, lines):")
    ordered = sorted(r.per_file.items(),
                     key=lambda kv: (kv[1][0] or datetime.max, kv[0]))
    for path, (f0, f1, n) in ordered:
        p(f"       {os.path.basename(path):<32} {str(f0):<26} {str(f1):<26} {n:>10,}")
    p(f"\n   malformed sample (up to 20):")
    if not r.malformed_sample:
        p("       (none)")
    for path, ln, text in r.malformed_sample:
        p(f"       {os.path.basename(path)}:{ln}: {text[:160]}")

    # 2. THREADS
    p("\n2. THREADS")
    p(f"   distinct threads : {len(r.thread_count):,}")
    p("   records-per-thread histogram:")
    rpt = Counter()
    for _t, n in r.thread_count.items():
        rpt[bucket_count(n)] += 1
    order = ["<=1", "<=5", "<=25", "<=100", "<=1000", "<=10000", ">10000"]
    tt = sum(rpt.values()) or 1
    for label in order:
        n = rpt.get(label, 0)
        p(f"       {label:<8}: {n:>10,}  {hbar(n, tt)}")
    p("   inter-record gap histogram (within a thread):")
    gt = sum(r.gap_hist.values()) or 1
    for label, _ub in GAP_BUCKETS:
        n = r.gap_hist.get(label, 0)
        pct = 100.0 * n / gt
        p(f"       {label:<8}: {n:>12,}  ({pct:5.2f}%)  {hbar(n, gt)}")

    # 3. CALL SITES
    p("\n3. CALL SITES")
    p(f"   distinct call sites : {len(r.callsite_count):,}")
    p(f"   top {top_callsites} by frequency:")
    for cs, n in r.callsite_count.most_common(top_callsites):
        p(f"       {n:>10,}  {cs}")
    p("\n   records by package prefix (app code vs libraries):")
    pt = sum(r.package_split.values()) or 1
    for pkg, n in r.package_split.most_common(30):
        pct = 100.0 * n / pt
        p(f"       {n:>10,}  ({pct:5.2f}%)  {pkg}")

    # 4. ENTRY / TERMINAL CANDIDATES
    p("\n4. ENTRY / TERMINAL CANDIDATES   (the important one)")
    for thr in GAP_THRESHOLDS:
        p(f"\n   --- gap threshold = {thr:g}s ---")
        data = r.et[thr]
        # entries: rank by first / (first + mid), require some support
        entries = []
        terminals = []
        for cs, (first, mid, last) in data.items():
            occ = first + mid
            if occ <= 0:
                continue
            entries.append((first / occ, first, mid, occ, cs))
            terminals.append((last / occ, last, occ, cs))
        entries.sort(key=lambda x: (-x[0], -x[1], x[4]))
        terminals.sort(key=lambda x: (-x[0], -x[1], x[3]))
        p(f"   TOP {top_entries} ENTRY candidates (first_after_gap ratio):")
        p(f"       {'ratio':>6}  {'first':>10} {'mid':>10} {'occ':>10}  call site")
        for ratio, first, mid, occ, cs in entries[:top_entries]:
            p(f"       {ratio:6.3f}  {first:>10,} {mid:>10,} {occ:>10,}  {cs}")
        p(f"   TOP {top_entries} TERMINAL candidates (last_before_gap ratio):")
        p(f"       {'ratio':>6}  {'last':>10} {'occ':>10}  call site")
        for ratio, last, occ, cs in terminals[:top_entries]:
            p(f"       {ratio:6.3f}  {last:>10,} {occ:>10,}  {cs}")

    # verdict on separation, using the 5s threshold as reference
    p("\n   VERDICT — do entry points separate cleanly?")
    ref = r.et[5.0]
    scored = []
    for cs, (first, mid, last) in ref.items():
        occ = first + mid
        if occ >= 5:                       # ignore noise
            scored.append((first / occ, first, occ, cs))
    scored.sort(reverse=True)
    total_first = sum(s[1] for s in scored)
    if not scored or total_first == 0:
        p("       Not enough data to judge.")
    else:
        strong = [s for s in scored if s[0] >= 0.8]
        strong_first = sum(s[1] for s in strong)
        share = 100.0 * strong_first / total_first
        p(f"       {len(strong)} call sites have an entry ratio >= 0.80 at 5s.")
        p(f"       They account for {share:.1f}% of all first-after-gap records.")
        if share >= 70 and len(strong) <= 30:
            p("       => A SMALL SET OF CALL SITES DOMINATES AS ENTRY POINTS.")
            p("          EntryMarkerStrategy (Phase 2, Impl A) is viable. Seed the")
            p("          entry set from the high-ratio call sites above.")
        else:
            p("       => THE DISTRIBUTION IS FLAT. No clean entry markers.")
            p("          Prefer IdleGapStrategy (Phase 2, Impl B); pick the gap")
            p("          threshold from the inter-record gap histogram (section 2).")

    # 5. LEVELS
    p("\n5. LEVELS")
    lt = sum(r.level_count.values()) or 1
    for lvl, n in r.level_count.most_common():
        p(f"       {lvl:<8}: {n:>12,}  ({100.0*n/lt:5.2f}%)")
    p(f"   records containing a stack trace: {r.stacktrace_records:,}")
    p("   level mix per hour (share %, watch for a config change mid-corpus):")
    hours = sorted(r.level_by_hour.keys())
    levels_seen = [lvl for lvl, _ in r.level_count.most_common()]
    header = "       " + "hour".ljust(16) + "".join(f"{l[:6]:>8}" for l in levels_seen)
    p(header)
    for h in hours:
        c = r.level_by_hour[h]
        tot = sum(c.values()) or 1
        row = "       " + h.ljust(16)
        for l in levels_seen:
            row += f"{100.0*c.get(l,0)/tot:7.1f}%"
        p(row)

    # 6. INTEGRITY
    p("\n6. INTEGRITY")
    if r.want_dupes:
        tot_rec = r.buckets["matched"] or 1
        pct = 100.0 * r.dupe_cross_file / tot_rec
        p(f"   cross-file duplicate records : {r.dupe_cross_file:,}  ({pct:.3f}% of records)")
        p(f"   distinct duplicated tuples   : {len(r.dupe_hashes_flagged):,}")
        if pct >= 1.0:
            p("       => Multiple appenders are writing the same events to different")
            p("          files. Phase 1 must dedupe on (ts, thread, callsite, msg).")
        else:
            p("       => Duplication is negligible.")
    else:
        p("   duplicate detection disabled (--no-dupes)")
    # boundary pressure
    if r.corpus_min and r.corpus_max:
        lead = r.corpus_min + timedelta(seconds=60)
        tail = r.corpus_max - timedelta(seconds=60)
        head_threads = set()
        tail_threads = set()
        for t, f0 in r.thread_first_ts.items():
            f1 = r.thread_last_ts.get(t)
            if f0 is not None and f0 <= lead:
                head_threads.add(t)
            if f1 is not None and f1 >= tail:
                tail_threads.add(t)
        p(f"   boundary pressure (60s margin):")
        p(f"       threads active in first 60s : {len(head_threads):,}")
        p(f"       threads active in last  60s : {len(tail_threads):,}")
        p("       => These episodes are CENSORING candidates (section 3.5): usable")
        p("          for baselining up to their cut, never eligible as findings.")
    p("\n" + line)


def report_json(r, top_callsites, top_entries):
    ref = r.et[5.0]
    out = {
        "corpus": {
            "files": r.file_count,
            "total_lines": r.total_lines,
            "total_bytes": r.total_bytes,
            "timestamp_min": str(r.corpus_min),
            "timestamp_max": str(r.corpus_max),
            "buckets": dict(r.buckets),
            "per_file": {
                os.path.basename(p_): {
                    "first_ts": str(v[0]), "last_ts": str(v[1]), "lines": v[2]
                } for p_, v in r.per_file.items()
            },
            "malformed_sample": [
                {"file": os.path.basename(p_), "line": ln, "text": t}
                for p_, ln, t in r.malformed_sample
            ],
        },
        "threads": {
            "distinct": len(r.thread_count),
            "gap_histogram": dict(r.gap_hist),
        },
        "call_sites": {
            "distinct": len(r.callsite_count),
            "top": r.callsite_count.most_common(top_callsites),
            "package_split": dict(r.package_split),
        },
        "entry_terminal": {
            str(thr): {
                "entries": sorted(
                    [
                        {"call_site": cs, "first": f, "mid": m, "last": la,
                         "entry_ratio": (f / (f + m)) if (f + m) else 0.0}
                        for cs, (f, m, la) in data.items() if (f + m) > 0
                    ],
                    key=lambda d: -d["entry_ratio"],
                )[:top_entries]
            }
            for thr, data in r.et.items()
        },
        "levels": {
            "by_level": dict(r.level_count),
            "by_hour": {h: dict(c) for h, c in r.level_by_hour.items()},
            "stacktrace_records": r.stacktrace_records,
        },
        "integrity": {
            "dupes_enabled": r.want_dupes,
            "cross_file_duplicates": r.dupe_cross_file,
            "distinct_duplicated_tuples": len(r.dupe_hashes_flagged),
        },
    }
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description="TFA Phase 0 corpus reconnaissance")
    ap.add_argument("logdir", help="directory of application log files")
    ap.add_argument("--json", metavar="FILE", help="also write the report as JSON")
    ap.add_argument("--no-dupes", action="store_true",
                    help="disable cross-file duplicate detection (saves memory)")
    ap.add_argument("--top-callsites", type=int, default=50)
    ap.add_argument("--top-entries", type=int, default=30)
    args = ap.parse_args(argv)

    if not os.path.exists(args.logdir):
        ap.error(f"path not found: {args.logdir}")

    r = ingest(args.logdir, want_dupes=not args.no_dupes)
    report_text(r, args.top_callsites, args.top_entries)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(report_json(r, args.top_callsites, args.top_entries),
                      fh, indent=2, default=str)
        print(f"\n[json written to {args.json}]", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
