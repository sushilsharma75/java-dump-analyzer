"""Thin CLI over the tfa library. Port of `tfa.cli.Main` (argparse-based)."""
from __future__ import annotations

import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from . import VERSION, AnalysisResult, analyze
from .baseline import build_baseline
from .cluster import SignatureClusterer
from .config import AnalysisConfig
from .detect import DetectionEngine
from .ingest import (FileSetReader, MatchRateError, ParseStats, RecordParser,
                     detect_format, epoch_millis, profile_to_yaml)
from .model import FlowCluster, TerminalStatus
from .rank import Suppressions
from .report import CorpusFingerprint, Report, render_json, render_text, sha256_hex
from .segment import StreamingSegmenter
from .validate import Explainer, GroundTruth, Validator

USAGE = """tfa - Thread Flow Analyzer (Python)

Usage:
  tfa parse <dir> [--threshold 0.95] [--sample 1000]
  tfa detect-format <file> [--sample 500]
  tfa segment  <dir> --config <yaml>
  tfa cluster  <dir> --config <yaml>
  tfa baseline <dir> --config <yaml>
  tfa detect   <dir> --config <yaml>
  tfa analyze  <dir> --config <yaml> [--out <file>] [--suppressions <file>]
  tfa validate <dir> --config <yaml> --ground-truth <file>
  tfa explain  <dir> --config <yaml> --thread <id> --at <timestamp>
  tfa compare  <dir> --good <refId> --bad <refId> [--config <yaml>] [--all] [--out <file>]
  tfa serve [--port 8080]
"""


def _opt(args: list[str], key: str, default=None):
    flag = "--" + key
    if flag in args:
        i = args.index(flag)
        if i + 1 < len(args):
            return args[i + 1]
    return default


def _histogram(title, labels, counts):
    total = sum(counts) or 1
    print(title)
    for label, n in zip(labels, counts):
        print(f"      {label:<9}: {n:>10,} ({100.0 * n / total:5.1f}%)")


def _bucket_index(bounds, value):
    for i, b in enumerate(bounds):
        if value <= b:
            return i
    return len(bounds) - 1


# --------------------------------------------------------------------- parse

def cmd_parse(args):
    d = args[0]
    profile = None
    from .ingest import FormatProfile
    profile = FormatProfile.default()
    threshold = float(_opt(args, "threshold", "0.95"))
    sample = int(_opt(args, "sample", "1000"))
    stats = ParseStats()
    reader = FileSetReader(Path(d), RecordParser(profile), stats)
    print(f"profile           : {profile.name} (capabilities {sorted(c.value for c in profile.capabilities)})")
    print(f"files (ts order)  : {len(reader.ordered_files)}")
    mr = reader.require_match_rate(sample, threshold)
    print(f"sample match rate : {mr.rate * 100:.2f}% ({mr.matched} matched / {mr.malformed} malformed of {mr.sampled_lines} sampled)")

    threads, sites = set(), set()
    tmin = tmax = None
    count = 0
    t0 = time.time()
    for r in reader.records():
        count += 1
        if r.thread_id:
            threads.add(r.thread_id)
        cs = r.call_site()
        if cs:
            sites.add(cs)
        if r.timestamp is not None:
            tmin = r.timestamp if tmin is None or r.timestamp < tmin else tmin
            tmax = r.timestamp if tmax is None or r.timestamp > tmax else tmax
    elapsed = int((time.time() - t0) * 1000)
    print("-" * 58)
    print("INGESTION STATISTICS")
    print(f"  lines total     : {stats.total_lines:,}")
    print(f"    matched       : {stats.matched:,}")
    print(f"    continuation  : {stats.continuation:,}")
    print(f"    malformed     : {stats.malformed:,}")
    print(f"  records         : {count:,}")
    print(f"  distinct threads: {len(threads):,}")
    print(f"  distinct sites  : {len(sites):,}")
    print(f"  timestamp range : {tmin}  ->  {tmax}")
    if stats.timestamp_parse_failures:
        print(f"  ts parse fails  : {stats.timestamp_parse_failures:,}")
    print(f"  wall time       : {elapsed:,} ms")
    if stats.malformed:
        print("  malformed sample:")
        for f, ln, text in stats.malformed_sample:
            print(f"    {Path(f).name}:{ln}  {text[:140]}")


# ------------------------------------------------------------- detect-format

def cmd_detect_format(args):
    d = detect_format(Path(args[0]), int(_opt(args, "sample", "500")))
    print(f"# detected from {args[0]} ({d.sampled} lines sampled)")
    print(f"# proposed profile match rate: {d.match_rate * 100:.2f}%")
    print(f"# note: {d.note}\n")
    print(profile_to_yaml(d.profile), end="")
    if d.match_rate < 0.95:
        print(f"\n# WARNING: match rate {d.match_rate * 100:.2f}% is below 95%. Review before use.")


# ------------------------------------------------------------------- segment

_REC_B = [1, 5, 10, 25, 100, 1000, float("inf")]
_REC_L = ["1", "2-5", "6-10", "11-25", "26-100", "101-1000", ">1000"]
_PT_B = [1, 5, 25, 100, 1000, float("inf")]
_PT_L = ["1", "2-5", "6-25", "26-100", "101-1000", ">1000"]
_DUR_B = [100, 1000, 5000, 30000, 300000, float("inf")]
_DUR_L = ["<100ms", "<1s", "<5s", "<30s", "<5m", "longer"]


def cmd_segment(args):
    d, config = args[0], AnalysisConfig.load(Path(_opt(args, "config")))
    reader = FileSetReader(Path(d), RecordParser(config.profile), ParseStats())
    reader.require_match_rate(config.sample_lines, config.match_threshold)
    strategy = config.segmentation.build_strategy()
    print(f"profile           : {config.profile.name}")
    print(f"strategy          : {strategy.name}")

    per_thread: dict[str, int] = {}
    rec_counts = [0] * len(_REC_B)
    dur_counts = [0] * len(_DUR_B)
    status_counts: dict[TerminalStatus, int] = {}
    longest: list = []
    total = 0

    def sink(e):
        nonlocal total
        total += 1
        per_thread[e.thread_id] = per_thread.get(e.thread_id, 0) + 1
        rec_counts[_bucket_index(_REC_B, e.size())] += 1
        dur = 0 if e.start is None or e.end is None else max(0, epoch_millis(e.end) - epoch_millis(e.start))
        dur_counts[_bucket_index(_DUR_B, dur)] += 1
        status_counts[e.status] = status_counts.get(e.status, 0) + 1
        longest.append(e)
        longest.sort(key=lambda x: -x.size())
        del longest[10:]

    StreamingSegmenter(strategy).segment(reader.records(), sink)

    print("-" * 58)
    print("SEGMENTATION")
    print(f"  total episodes  : {total:,}")
    print(f"  distinct threads: {len(per_thread):,}")
    print("  status breakdown:")
    for s in TerminalStatus:
        n = status_counts.get(s, 0)
        print(f"      {s.value:<10}: {n:,} ({100.0 * n / (total or 1):.1f}%)")
    pt_counts = [0] * len(_PT_B)
    for c in per_thread.values():
        pt_counts[_bucket_index(_PT_B, c)] += 1
    _histogram("  episodes-per-thread histogram:", _PT_L, pt_counts)
    _histogram("  records-per-episode histogram:", _REC_L, rec_counts)
    _histogram("  episode-duration histogram:", _DUR_L, dur_counts)
    print("  10 longest episodes (by record count):")
    for e in longest:
        print(f"      thread={e.thread_id} size={e.size()} status={e.status.value} start={e.start}")
        print("        seq: " + " -> ".join(e.call_site_sequence())[:300])


# ------------------------------------------------- cluster / baseline / detect

def _clusters_from(d: Path, config: AnalysisConfig) -> list[FlowCluster]:
    reader = FileSetReader(d, RecordParser(config.profile), ParseStats())
    reader.require_match_rate(config.sample_lines, config.match_threshold)
    clusterer = SignatureClusterer(config.clustering.signature_k)
    StreamingSegmenter(config.segmentation.build_strategy()).segment(reader.records(), clusterer.add)
    return clusterer.finish(config.clustering.min_cluster_size)


_CS_B = [1, 9, 49, 199, 999, float("inf")]
_CS_L = ["1", "2-9", "10-49", "50-199", "200-999", ">=1000"]


def cmd_cluster(args):
    d, config = Path(args[0]), AnalysisConfig.load(Path(_opt(args, "config")))
    k = config.clustering.signature_k
    print(f"profile           : {config.profile.name}")
    print(f"strategy          : {config.segmentation.strategy.value}")
    print(f"signature K       : {k}   (min cluster size {config.clustering.min_cluster_size}, "
          f"ceiling {config.clustering.cluster_ceiling})")
    clusters = _clusters_from(d, config)
    total = sum(c.size() for c in clusters)
    under = sum(1 for c in clusters if c.under_sampled)
    print("-" * 58)
    print("CLUSTERING")
    print(f"  clusters        : {len(clusters):,}")
    print(f"  episodes        : {total:,}")
    print(f"  under-sampled   : {under:,} (size < {config.clustering.min_cluster_size}, excluded from baselining)")
    if len(clusters) > config.clustering.cluster_ceiling:
        print(f"  WARNING: cluster count {len(clusters):,} exceeds ceiling {config.clustering.cluster_ceiling:,} - K={k} may be too large.")
    counts = [0] * len(_CS_B)
    for c in clusters:
        counts[_bucket_index(_CS_B, c.size())] += 1
    _histogram("  cluster-size distribution:", _CS_L, counts)
    print("  top 20 clusters by size:")
    for c in clusters[:20]:
        rep = c.representative()
        tag = " UNDER_SAMPLED" if c.under_sampled else ""
        print(f"      [{c.size():,}]{tag}  {c.signature}")
        if rep:
            print(f"        rep: thread={rep.thread_id} start={rep.start} status={rep.status.value}")
            print("        seq: " + " -> ".join(rep.call_site_sequence())[:300])


def cmd_baseline(args):
    d, config = Path(args[0]), AnalysisConfig.load(Path(_opt(args, "config")))
    clusters = _clusters_from(d, config)
    print(f"profile           : {config.profile.name}")
    print(f"strategy          : {config.segmentation.strategy.value}")
    if config.baseline.baseline_start or config.baseline.baseline_end:
        print(f"baseline window   : {config.baseline.baseline_start} -> {config.baseline.baseline_end}")
    baselined = 0
    for c in clusters:
        if c.under_sampled:
            continue
        b = build_baseline(c, config.baseline)
        if b is None:
            continue
        baselined += 1
        print("=" * 58)
        print(f"cluster: {c.signature}")
        print(f"  episodes baselined : {b.episodes_used} (of {c.size()} in cluster)")
        print(f"  modal sequence     : {b.modal_share * 100:.1f}% ({b.modal_count} episodes)")
        print("     " + " -> ".join(b.modal_sequence)[:400])
        if b.alternatives:
            print("  top alternative sequences:")
            for alt in b.alternatives:
                print(f"     {alt.share * 100:5.1f}% ({alt.count})  " + " -> ".join(alt.sequence)[:300])
        slow = b.slowest_by_p95(5)
        if slow:
            print("  slowest transitions (by p95):")
            for t in slow:
                print(f"     p95={t.p95_millis:,.0f}ms median={t.median_millis:,.0f}ms (n={t.count})  {t.frm} -> {t.to}")
    print("=" * 58)
    print(f"baselined {baselined} cluster(s); {sum(1 for c in clusters if c.under_sampled)} under-sampled skipped.")


def cmd_detect(args):
    d, config = Path(args[0]), AnalysisConfig.load(Path(_opt(args, "config")))
    clusters = _clusters_from(d, config)
    result = DetectionEngine(config.detection, config.baseline).detect(clusters)
    print(f"profile           : {config.profile.name}")
    print(f"strategy          : {config.segmentation.strategy.value}")
    print(f"episodes evaluated: {result.episodes_evaluated:,}   censored: {result.episodes_censored:,}   "
          f"censor margin: {result.margin_millis:,}ms")
    print(f"corpus            : {result.corpus_start} -> {result.corpus_end}")
    allf = result.all_findings()
    print("-" * 58)
    print(f"RAW FINDINGS (unranked): {len(allf):,}")
    for cf in result.per_cluster:
        if not cf.findings:
            continue
        print(f"  cluster [{cf.cluster.size()}] {cf.cluster.signature}")
        for f in cf.findings:
            print(f"    {f.type.value:<11} idx={f.divergence_index}  expected={f.expected_call_site} "
                  f"({f.expected_share * 100:.0f}%)  observed={f.observed}  thread={f.episode.thread_id} @ {f.episode.start}")
    print("(ranking, dedup and report land in `tfa analyze`.)")


# ------------------------------------------------------------------- analyze

def cmd_analyze(args):
    d, config_path = Path(args[0]), Path(_opt(args, "config"))
    config = AnalysisConfig.load(config_path)
    suppressions = Suppressions.none()
    supp = _opt(args, "suppressions")
    if supp:
        suppressions = Suppressions.load(Path(supp))
    result = analyze(d, config, suppressions)
    report = _build_report(config, config_path, result)
    print(render_text(report), end="")
    out = _opt(args, "out")
    if out:
        Path(out).write_text(render_json(report), encoding="utf-8")
        print(f"\n[JSON report written to {out}]")


def _build_report(config, config_path, result: AnalysisResult) -> Report:
    fp = CorpusFingerprint.of(result.ordered_files, result.detection.corpus_start,
                              result.detection.corpus_end)
    config_hash = sha256_hex(Path(config_path).read_bytes())
    return Report(VERSION, datetime.now(timezone.utc), config_hash, fp,
                  config.profile.name, config.segmentation.strategy.value,
                  result.detection.episodes_evaluated, result.detection.episodes_censored,
                  result.detection.margin_millis, len(result.ranking.ranked),
                  result.ranking.suppressed_count, result.ranking.top,
                  result.detection.clusters_total, result.detection.clusters_under_sampled,
                  result.detection.episodes_skipped_under_sampled,
                  config.clustering.min_cluster_size)


# --------------------------------------------------------- validate / explain

def cmd_validate(args):
    d, config = Path(args[0]), AnalysisConfig.load(Path(_opt(args, "config")))
    result = analyze(d, config)
    truth = GroundTruth.load(Path(_opt(args, "ground-truth")))
    report = Validator(result, config).validate(truth)
    print("=" * 58)
    print("TFA VALIDATION")
    print("=" * 58)
    for o in report.outcomes:
        status = "PASS" if o.within_top(report.top_n) else ("WARN" if o.found else "FAIL")
        print(f"  [{status}] {o.id} - {o.description}")
        if o.found:
            print(f"        found at rank #{o.rank} ({o.type}); {o.note}")
        else:
            print(f"        {o.note}")
    print("-" * 58)
    print(f"  {report.passed()} of {len(report.outcomes)} defects in the top {report.top_n}.")
    if report.all_passed():
        print("  SUCCESS TEST PASSED.")
    else:
        print("  SUCCESS TEST NOT PASSED. Use `tfa explain` on a missing defect.")
        sys.exit(4)


def cmd_explain(args):
    d, config = Path(args[0]), AnalysisConfig.load(Path(_opt(args, "config")))
    thread = _opt(args, "thread")
    at = _opt(args, "at")
    result = analyze(d, config)
    from .config import _parse_instant
    trace = Explainer(result, config).explain(thread, _parse_instant(at))
    print("=" * 58)
    print(f"TFA EXPLAIN - thread {thread} at {at}")
    print("=" * 58)
    for line in trace.lines:
        print("  " + line)
    print("=" * 58)


def cmd_compare(args):
    """Compare one known-GOOD reference flow against one known-BAD one."""
    from .compare import compare_flows, episodes_for_ids, render_comparison
    from .ingest import FormatProfile
    d = args[0] if args and not args[0].startswith("--") else None
    good = _opt(args, "good")
    bad = _opt(args, "bad")
    if d is None or not good or not bad:
        print("usage: tfa compare <dir> --good <refId> --bad <refId> "
              "[--config <yaml>] [--all] [--out <file>]", file=sys.stderr)
        sys.exit(1)

    cfg_path = _opt(args, "config")
    if cfg_path:
        config = AnalysisConfig.load(Path(cfg_path))
        profile, threshold, sample = config.profile, config.match_threshold, config.sample_lines
    else:
        profile, threshold, sample = FormatProfile.default(), 0.95, 1000

    reader = FileSetReader(Path(d), RecordParser(profile), ParseStats())
    reader.require_match_rate(sample, threshold)
    good_ep, bad_ep = episodes_for_ids(reader.records(), good, bad)
    result = compare_flows(good_ep, bad_ep, good, bad)

    print(render_comparison(result, show_all="--all" in args), end="")

    out = _opt(args, "out")
    if out:
        import json
        payload = {
            "goodId": result.good_id, "badId": result.bad_id,
            "goodRecords": result.good.size(), "badRecords": result.bad.size(),
            "goodDurationMs": result.good_duration_ms, "badDurationMs": result.bad_duration_ms,
            "breakIndex": result.break_index,
            "steps": [{"kind": s.kind, "callSite": s.call_site,
                       "fields": [{"key": f.key, "good": f.good, "bad": f.bad, "kind": f.kind}
                                  for f in s.fields]} for s in result.steps],
            "errorsInBad": [f"{r.timestamp} | {r.level} | {r.call_site()} | {r.message}"
                            for r in result.errors_only_in_bad],
        }
        Path(out).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        print(f"\n[JSON comparison written to {out}]")
    if result.break_index is not None:
        sys.exit(5)


def cmd_serve(args):
    from .web import start
    start(int(_opt(args, "port", "8080")))


COMMANDS = {
    "parse": cmd_parse, "detect-format": cmd_detect_format, "segment": cmd_segment,
    "cluster": cmd_cluster, "baseline": cmd_baseline, "detect": cmd_detect,
    "analyze": cmd_analyze, "validate": cmd_validate, "explain": cmd_explain,
    "compare": cmd_compare,
    "serve": cmd_serve,
}


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(USAGE)
        return 0 if argv else 1
    cmd = argv[0]
    fn = COMMANDS.get(cmd)
    if fn is None:
        print(f"unknown command: {cmd}", file=sys.stderr)
        print(USAGE)
        return 1
    try:
        fn(argv[1:])
        return 0
    except MatchRateError as e:
        print(f"ABORTED: {e}", file=sys.stderr)
        for f, ln, text in e.report.failures:
            print(f"  {Path(f).name}:{ln}  {text[:160]}", file=sys.stderr)
        print("Fix the profile (try `tfa detect-format <file>`) or lower --threshold.", file=sys.stderr)
        return 2
    except NotImplementedError as e:
        print(f"unsupported: {e}", file=sys.stderr)
        return 3
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
