"""Reporting: corpus fingerprint, log-context extraction, text and JSON
reporters, and reproducibility metadata. Port of `tfa.report`."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

from .model import Episode, Finding
from .rank import RankedFinding


def sha256_hex(data) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


# ----------------------------------------------------------- corpus fingerprint

@dataclass(frozen=True)
class FileEntry:
    name: str
    size_bytes: int


@dataclass(frozen=True)
class CorpusFingerprint:
    hash: str
    files: list[FileEntry]
    corpus_start: Optional[datetime]
    corpus_end: Optional[datetime]

    @staticmethod
    def of(ordered_files: list[Path], corpus_start, corpus_end) -> "CorpusFingerprint":
        entries = []
        material = []
        for p in ordered_files:
            size = p.stat().st_size
            entries.append(FileEntry(p.name, size))
            material.append(f"{p.name}:{size}")
        material.append(f"start={corpus_start}")
        material.append(f"end={corpus_end}")
        return CorpusFingerprint(sha256_hex("\n".join(material) + "\n"),
                                 entries, corpus_start, corpus_end)


# --------------------------------------------------------------- log context

def _anchor_index(episode: Episode, finding: Finding) -> int:
    anchor = finding.divergence_call_site
    if anchor is not None:
        for i, r in enumerate(episode.records):
            if r.call_site() == anchor:
                return i
    return 0 if not episode.records else len(episode.records) - 1


def _envelope(r) -> str:
    return f"{r.timestamp} | {r.level} | {r.thread_id} | {r.call_site()} | {r.message}"


def log_context(finding: Finding, before: int = 5, after: int = 5) -> list[str]:
    episode = finding.episode
    records = episode.records
    if not records:
        return []
    anchor = _anchor_index(episode, finding)
    frm = max(0, anchor - before)
    to = min(len(records) - 1, anchor + after)
    out: list[str] = []
    for i in range(frm, to + 1):
        r = records[i]
        marker = "  >> " if i == anchor else "     "
        out.append(marker + _envelope(r))
        for cont in r.continuation_lines:
            out.append("       " + cont)
    return out


# -------------------------------------------------------------------- report

@dataclass
class Report:
    tool_version: str
    run_timestamp: datetime
    config_hash: str
    corpus: CorpusFingerprint
    strategy_name: str
    episodes_evaluated: int
    episodes_censored: int
    censor_margin_millis: int
    total_findings: int
    suppressed_count: int
    top: list[RankedFinding]
    clusters_total: int = 0
    clusters_under_sampled: int = 0
    episodes_skipped_under_sampled: int = 0
    min_cluster_size: int = 0


def render_text(report: Report) -> str:
    L = []
    line = "=" * 66
    L.append(line)
    L.append("TFA ANALYSIS REPORT")
    L.append(line)
    L.append(f"  tool version    : {report.tool_version}")
    L.append(f"  run timestamp   : {report.run_timestamp}")
    L.append(f"  config hash     : {report.config_hash}")
    L.append(f"  corpus hash     : {report.corpus.hash}")
    L.append(f"  corpus range    : {report.corpus.corpus_start} -> {report.corpus.corpus_end}")
    L.append(f"  strategy        : {report.strategy_name}")
    L.append(f"  episodes        : {report.episodes_evaluated:,} evaluated, "
             f"{report.episodes_censored:,} censored (margin {report.censor_margin_millis:,}ms)")
    L.append(f"  findings        : {report.total_findings:,} total, "
             f"{report.suppressed_count:,} suppressed, top {len(report.top)} shown")
    if report.suppressed_count > 0:
        L.append(f"  ({report.suppressed_count} findings suppressed)")
    L.append("")
    for rank, rf in enumerate(report.top, 1):
        f = rf.representative
        L.append("-" * 66)
        L.append(f"#{rank}  score={rf.score:.3f}  {f.type.value}  x{rf.occurrences} occurrence(s)")
        L.append(f"    cluster : {rf.cluster_signature}  (size {rf.cluster_size})")
        L.append(f"    at      : {f.divergence_call_site}  [collapsed index {f.divergence_index}]")
        L.append(f"    majority: {f.expected_call_site} ({f.expected_share * 100:.0f}%);  this: {f.observed}")
        L.append(f"    example : thread={f.episode.thread_id}  @ {f.episode.start}")
        L.append("    log context (>> marks the divergence point):")
        for cl in log_context(f, 5, 5):
            L.append("    " + cl)
    if not report.top:
        L.append(_no_findings_explanation(report))
    L.append(line)
    return "\n".join(L) + "\n"


def _no_findings_explanation(r: Report) -> str:
    """Say WHY nothing was reported. A zero-episode run is not a clean run."""
    if r.episodes_evaluated > 0:
        return ("No findings. " + f"{r.episodes_evaluated:,} episodes were compared against their "
                "baselines and none deviated - this really is a clean run.")
    lines = ["NOTHING WAS ANALYSED - this is NOT a clean run.", ""]
    if r.clusters_total == 0:
        lines += ["  No flows were found at all. Check that segmentation matches your logs:",
                  "    - ENTRY_MARKER: are entryCallSites/terminalCallSites the real call sites?",
                  "    - CORRELATION_ID: does correlationIdPattern match the id in your messages?"]
    elif r.clusters_under_sampled == r.clusters_total:
        lines += [f"  All {r.clusters_total} flow group(s) were too small to baseline "
                  f"({r.episodes_skipped_under_sampled:,} episodes skipped).",
                  f"  A group needs at least minClusterSize={r.min_cluster_size} examples, because this",
                  "  tool finds defects by comparing a flow against OTHER RUNS OF THE SAME FLOW.",
                  "",
                  "  Fix by either:",
                  "    - analysing more traffic (more runs of each flow), or",
                  "    - lowering clustering.minClusterSize (results get statistically weak), or",
                  "    - lowering clustering.signatureK so similar flows group together."]
    else:
        lines += [f"  {r.clusters_under_sampled} of {r.clusters_total} flow groups were too small to "
                  f"baseline ({r.episodes_skipped_under_sampled:,} episodes skipped),",
                  "  and every remaining episode was excluded (boundary-censored or outside the eval window)."]
    return "\n".join(lines)


def render_json(report: Report) -> str:
    def finding_obj(rank, rf: RankedFinding):
        f = rf.representative
        b = rf.breakdown
        return {
            "rank": rank,
            "score": round(rf.score, 6),
            "type": f.type.value,
            "occurrences": rf.occurrences,
            "clusterSignature": rf.cluster_signature,
            "clusterSize": rf.cluster_size,
            "divergenceCallSite": f.divergence_call_site,
            "divergenceIndex": f.divergence_index,
            "expectedCallSite": f.expected_call_site,
            "expectedShare": round(f.expected_share, 6),
            "observed": f.observed,
            "exampleThread": f.episode.thread_id,
            "exampleTimestamp": str(f.episode.start),
            "scoreBreakdown": {
                "rarity": round(b.rarity, 6), "severity": round(b.severity, 6),
                "errorPresence": round(b.error_presence, 6), "magnitude": round(b.magnitude, 6),
                "clusterTrust": round(b.cluster_trust, 6), "variantPenalty": round(b.variant_penalty, 6),
            },
            "logContext": log_context(f, 5, 5),
        }

    root = {
        "meta": {
            "toolVersion": report.tool_version,
            "runTimestamp": str(report.run_timestamp),
            "configHash": report.config_hash,
            "corpusHash": report.corpus.hash,
            "corpusStart": str(report.corpus.corpus_start),
            "corpusEnd": str(report.corpus.corpus_end),
            "strategy": report.strategy_name,
            "files": [{"name": fe.name, "sizeBytes": fe.size_bytes} for fe in report.corpus.files],
        },
        "summary": {
            "episodesEvaluated": report.episodes_evaluated,
            "episodesCensored": report.episodes_censored,
            "censorMarginMillis": report.censor_margin_millis,
            "totalFindings": report.total_findings,
            "suppressedCount": report.suppressed_count,
            "clustersTotal": report.clusters_total,
            "clustersUnderSampled": report.clusters_under_sampled,
            "episodesSkippedUnderSampled": report.episodes_skipped_under_sampled,
            "minClusterSize": report.min_cluster_size,
            "noFindingsReason": _no_findings_explanation(report) if not report.top else "",
        },
        "findings": [finding_obj(i, rf) for i, rf in enumerate(report.top, 1)],
    }
    return json.dumps(root, indent=2) + "\n"
