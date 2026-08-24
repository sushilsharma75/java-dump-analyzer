"""Detection: sequence diff, three detectors, boundary censoring, and the
engine. Port of `tfa.detect`. Log level is never a detection trigger."""
from __future__ import annotations

import math
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from .baseline import build_baseline
from .config import BaselineConfig, DetectionConfig
from .ingest import epoch_millis
from .model import (Baseline, Episode, Finding, FindingType, FlowCluster,
                    TerminalStatus)


# ------------------------------------------------------------- sequence diff

class DivKind(Enum):
    SUBSTITUTION = "SUBSTITUTION"
    INSERTION = "INSERTION"


@dataclass(frozen=True)
class Divergence:
    index: int
    observed_call_site: str
    kind: DivKind


def edit_distance(a: list[str], b: list[str]) -> int:
    m, n = len(a), len(b)
    prev = list(range(n + 1))
    for i in range(1, m + 1):
        cur = [i] + [0] * n
        for j in range(1, n + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(cur[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost)
        prev = cur
    return prev[n]


def _common_prefix(a: list[str], b: list[str]) -> int:
    i = 0
    for x, y in zip(a, b):
        if x != y:
            break
        i += 1
    return i


def first_divergence(modal: list[str], observed: list[str]) -> Optional[Divergence]:
    p = _common_prefix(modal, observed)
    modal_done = p == len(modal)
    observed_done = p == len(observed)
    if modal_done and observed_done:
        return None
    if observed_done:
        return None  # observed is a prefix -> truncation
    if modal_done:
        return Divergence(p, observed[p], DivKind.INSERTION)
    return Divergence(p, observed[p], DivKind.SUBSTITUTION)


# ----------------------------------------------------------------- detectors

def _common_prefix_len(a, b):
    return _common_prefix(a, b)


def truncation_detector(episode: Episode, baseline: Baseline) -> list[Finding]:
    seq = episode.collapsed_sequence()
    modal_terminal = baseline.modal_terminal()
    incomplete = episode.status is not TerminalStatus.COMPLETED
    terminal_reached = modal_terminal is not None and bool(seq) and seq[-1] == modal_terminal
    if not incomplete and terminal_reached:
        return []
    if not incomplete and modal_terminal is None:
        return []
    last_reached = seq[-1] if seq else None
    index = len(seq) - 1
    matched = _common_prefix_len(seq, baseline.modal_sequence)
    modal_len = max(1, len(baseline.modal_sequence))
    raw = (modal_len - matched) / modal_len
    return [Finding(episode, FindingType.TRUNCATION, last_reached, index,
                    modal_terminal, baseline.modal_share, episode.status.value, raw)]


def divergence_detector(episode: Episode, baseline: Baseline) -> list[Finding]:
    d = first_divergence(baseline.modal_sequence, episode.collapsed_sequence())
    if d is None:
        return []
    expected = baseline.expected_at(d.index)
    if expected is not None:
        expected_cs, expected_share = expected.call_site, expected.share
    else:
        expected_cs, expected_share = "<end-of-flow>", baseline.modal_share
    return [Finding(episode, FindingType.DIVERGENCE, d.observed_call_site, d.index,
                    expected_cs, expected_share, d.observed_call_site, expected_share)]


class TimingDetector:
    def __init__(self, factor: float):
        self.factor = factor

    def detect(self, episode: Episode, baseline: Baseline) -> list[Finding]:
        runs = episode.collapsed_runs()
        findings: list[Finding] = []
        for i in range(len(runs) - 1):
            a, b = runs[i], runs[i + 1]
            timing = baseline.timing_for(a.call_site, b.call_site)
            if timing is None or timing.p95_millis <= 0:
                continue
            if a.first_timestamp is None or b.first_timestamp is None:
                continue
            elapsed = max(0, epoch_millis(b.first_timestamp) - epoch_millis(a.first_timestamp))
            if elapsed > timing.p95_millis * self.factor:
                multiple = elapsed / timing.p95_millis
                observed = f"elapsed={elapsed}ms p95={timing.p95_millis:.0f}ms ({multiple:.1f}x)"
                findings.append(Finding(episode, FindingType.TIMING, b.call_site, i + 1,
                                        a.call_site, 0.0, observed, multiple))
        return findings


# ------------------------------------------------------------------- censor

class Censor:
    def __init__(self, corpus_start, corpus_end, margin_millis):
        self.corpus_start = corpus_start
        self.corpus_end = corpus_end
        self.margin_millis = max(0, margin_millis)

    def is_censored(self, episode: Episode) -> bool:
        # A COMPLETED episode reached its modal terminal, so it is whole -- it was
        # not cut off by the dump boundary, even if it sits near the edge. Only
        # potentially-cut-off episodes (not COMPLETED) are censoring candidates.
        # This stops a slow-but-complete flow near the boundary from being hidden,
        # and stops a single slow outlier's inflated p99-duration margin from
        # censoring legitimate flows (see charter section 3.5).
        if episode.status is TerminalStatus.COMPLETED:
            return False
        start, end = episode.start, episode.end
        if self.corpus_start is not None and start is not None:
            if epoch_millis(start) <= epoch_millis(self.corpus_start) + self.margin_millis:
                return True
        if self.corpus_end is not None and end is not None:
            if epoch_millis(end) >= epoch_millis(self.corpus_end) - self.margin_millis:
                return True
        return False


# ------------------------------------------------------------------- engine

@dataclass
class ClusterFindings:
    cluster: FlowCluster
    baseline: Baseline
    findings: list[Finding]


@dataclass
class DetectionResult:
    per_cluster: list[ClusterFindings]
    episodes_evaluated: int
    episodes_censored: int
    margin_millis: int
    corpus_start: object
    corpus_end: object
    clusters_total: int = 0
    clusters_under_sampled: int = 0
    episodes_skipped_under_sampled: int = 0

    def all_findings(self) -> list[Finding]:
        out: list[Finding] = []
        for cf in self.per_cluster:
            out.extend(cf.findings)
        return out


def _p99(durations: list[int]) -> int:
    if not durations:
        return 0
    s = sorted(durations)
    rank = math.ceil(0.99 * len(s))
    rank = max(1, min(rank, len(s)))
    return s[rank - 1]


class DetectionEngine:
    def __init__(self, detection_config: DetectionConfig, baseline_config: BaselineConfig):
        self.detection_config = detection_config
        self.baseline_config = baseline_config
        self.timing = TimingDetector(detection_config.timing_factor)

    def detect(self, clusters: list[FlowCluster]) -> DetectionResult:
        corpus_start = corpus_end = None
        durations: list[int] = []
        for c in clusters:
            for e in c.episodes:
                s, en = e.start, e.end
                if s is not None and (corpus_start is None or s < corpus_start):
                    corpus_start = s
                if en is not None and (corpus_end is None or en > corpus_end):
                    corpus_end = en
                if s is not None and en is not None:
                    durations.append(max(0, epoch_millis(en) - epoch_millis(s)))

        margin = (self.detection_config.censor_margin_millis
                  if self.detection_config.has_explicit_margin() else _p99(durations))
        censor = Censor(corpus_start, corpus_end, margin)

        per_cluster: list[ClusterFindings] = []
        evaluated = censored = 0
        under_sampled = skipped = 0
        for cluster in clusters:
            if cluster.under_sampled:
                under_sampled += 1
                skipped += cluster.size()
                continue
            baseline = build_baseline(cluster, self.baseline_config)
            if baseline is None:
                continue
            findings: list[Finding] = []
            for episode in cluster.episodes:
                if not self.baseline_config.in_eval_window(episode.start):
                    continue
                if censor.is_censored(episode):
                    censored += 1
                    continue
                evaluated += 1
                findings.extend(truncation_detector(episode, baseline))
                findings.extend(divergence_detector(episode, baseline))
                findings.extend(self.timing.detect(episode, baseline))
            per_cluster.append(ClusterFindings(cluster, baseline, findings))

        return DetectionResult(per_cluster, evaluated, censored, margin, corpus_start, corpus_end,
                               len(clusters), under_sampled, skipped)
