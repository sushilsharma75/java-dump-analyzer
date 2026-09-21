"""Validation against ground truth and the explain reasoning trail. Port of
`tfa.validate`."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import yaml

from . import AnalysisResult
from .baseline import build_baseline
from .config import AnalysisConfig, _parse_instant
from .detect import Censor, TimingDetector, divergence_detector, truncation_detector
from .model import Episode, Finding, FlowCluster
from .rank import RankingResult, RankedFinding


# --------------------------------------------------------------- ground truth

@dataclass(frozen=True)
class Defect:
    id: str
    thread_id: str
    window_start: Optional[datetime]
    window_end: Optional[datetime]
    expected_divergence_call_site: Optional[str]
    description: Optional[str]

    def contains(self, t: Optional[datetime]) -> bool:
        if t is None:
            return False
        if self.window_start is not None and t < self.window_start:
            return False
        return self.window_end is None or t <= self.window_end


@dataclass(frozen=True)
class GroundTruth:
    defects: list[Defect]

    @staticmethod
    def load(path: Path) -> "GroundTruth":
        doc = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        if not isinstance(doc, dict):
            raise ValueError(f"ground-truth file is not a YAML mapping: {path}")
        defects = []
        for item in (doc.get("defects") or []):
            if isinstance(item, dict):
                win = item.get("timestampWindow") or {}
                defects.append(Defect(
                    str(item.get("id")), str(item.get("threadId")),
                    _parse_instant(win.get("start")), _parse_instant(win.get("end")),
                    item.get("expectedDivergenceCallSite"), item.get("description")))
        return GroundTruth(defects)


# ------------------------------------------------------------------ rank index

class RankIndex:
    def __init__(self, ranking: RankingResult):
        self._rank: dict[str, int] = {}
        self._suppressed: dict[str, str] = {}
        rank = 0
        for rf in ranking.ranked:
            key = rf.representative.dedupe_key(rf.cluster_signature)
            if rf.suppressed:
                self._suppressed[key] = rf.suppression_reason
            else:
                rank += 1
                self._rank[key] = rank

    def rank_of(self, finding: Finding, cluster_signature: str) -> Optional[int]:
        return self._rank.get(finding.dedupe_key(cluster_signature))

    def is_suppressed(self, finding: Finding, cluster_signature: str) -> bool:
        return finding.dedupe_key(cluster_signature) in self._suppressed

    def suppression_reason(self, finding: Finding, cluster_signature: str) -> Optional[str]:
        return self._suppressed.get(finding.dedupe_key(cluster_signature))


# -------------------------------------------------------------------- explainer

@dataclass
class Trace:
    episode_found: bool
    outcome: str
    reported_rank: Optional[int]
    lines: list[str]


class Explainer:
    def __init__(self, result: AnalysisResult, config: AnalysisConfig):
        self.result = result
        self.config = config
        self.censor = Censor(result.detection.corpus_start, result.detection.corpus_end,
                             result.detection.margin_millis)
        self.rank_index = RankIndex(result.ranking)

    def locate(self, thread_id: str, at: datetime) -> Optional[tuple[FlowCluster, Episode]]:
        best = None
        best_delta = None
        for cluster in self.result.clusters:
            for e in cluster.episodes:
                if e.thread_id != thread_id:
                    continue
                s, en = e.start, e.end
                if s is not None and en is not None and s <= at <= en:
                    return cluster, e
                if s is not None:
                    delta = abs((s - at).total_seconds())
                    if best_delta is None or delta < best_delta:
                        best_delta = delta
                        best = (cluster, e)
        return best

    def explain(self, thread_id: str, at: datetime) -> Trace:
        lines: list[str] = []
        located = self.locate(thread_id, at)
        if located is None:
            outcome = f"no episode found for thread {thread_id} at {at}"
            return Trace(False, outcome, None, [outcome])
        cluster, episode = located

        lines.append(f"episode           : thread={episode.thread_id}  start={episode.start}  "
                     f"end={episode.end}  status={episode.status.value}")
        us = ", UNDER_SAMPLED)" if cluster.under_sampled else ")"
        lines.append(f"cluster           : {cluster.signature}  (size {cluster.size()}{us}")
        lines.append("own sequence      : " + " -> ".join(episode.collapsed_sequence()))

        censored = self.censor.is_censored(episode)
        in_eval = self.config.baseline.in_eval_window(episode.start)

        if cluster.under_sampled:
            lines.append("baseline          : none (cluster is UNDER_SAMPLED; excluded from baselining)")
            outcome = (f"NOT REPORTED - cluster under-sampled (size {cluster.size()} "
                       f"< minClusterSize {self.config.clustering.min_cluster_size})")
            lines.append(outcome)
            return Trace(True, outcome, None, lines)

        baseline = build_baseline(cluster, self.config.baseline)
        if baseline is None:
            outcome = "NOT REPORTED - no baseline could be built in the baseline window"
            lines.append(outcome)
            return Trace(True, outcome, None, lines)
        lines.append(f"baseline modal    : {baseline.modal_share * 100:.0f}%  "
                     + " -> ".join(baseline.modal_sequence))

        fired: list[Finding] = []
        self._explain_detector(lines, "truncation", truncation_detector(episode, baseline), fired,
                               "reached the modal terminal and completed")
        self._explain_detector(lines, "divergence", divergence_detector(episode, baseline), fired,
                               "sequence matches the modal path (or is a prefix, which truncation owns)")
        self._explain_detector(lines, "timing",
                               TimingDetector(self.config.detection.timing_factor).detect(episode, baseline),
                               fired, f"every transition is within p95 x {self.config.detection.timing_factor}")

        if not in_eval:
            outcome = "NOT REPORTED - episode start is outside the evaluation window"
            lines.append(outcome)
            return Trace(True, outcome, None, lines)
        if censored:
            outcome = (f"NOT REPORTED - CENSORED: episode overlaps the "
                       f"{self.result.detection.margin_millis}ms corpus-boundary margin (section 3.5)")
            lines.append(outcome)
            return Trace(True, outcome, None, lines)
        if not fired:
            outcome = "NOT REPORTED - no detector fired (this episode matches the consensus)"
            lines.append(outcome)
            return Trace(True, outcome, None, lines)

        best_rank = None
        best_finding = None
        for f in fired:
            rank = self.rank_index.rank_of(f, cluster.signature)
            if rank is not None and (best_rank is None or rank < best_rank):
                best_rank, best_finding = rank, f
        if best_rank is None:
            reason = self.rank_index.suppression_reason(fired[0], cluster.signature)
            outcome = "DETECTED but SUPPRESSED" + (f" ({reason})" if reason else "")
            lines.append(outcome)
            return Trace(True, outcome, None, lines)
        outcome = f"REPORTED at rank #{best_rank} as {best_finding.type.value}"
        lines.append(outcome)
        return Trace(True, outcome, best_rank, lines)

    @staticmethod
    def _explain_detector(lines, name, findings, fired, quiet_reason):
        if not findings:
            lines.append(f"  {name:<11}: no finding - {quiet_reason}")
        else:
            fired.extend(findings)
            for f in findings:
                lines.append(f"  {name:<11}: FIRED rawScore={f.raw_score:.3f} at {f.divergence_call_site} "
                             f"(expected {f.expected_call_site} {f.expected_share * 100:.0f}%, observed {f.observed})")


# -------------------------------------------------------------------- validator

@dataclass
class DefectOutcome:
    id: str
    description: Optional[str]
    found: bool
    rank: Optional[int]
    type: Optional[str]
    note: str

    def within_top(self, top_n: int) -> bool:
        return self.found and self.rank is not None and self.rank <= top_n


@dataclass
class ValidationReport:
    outcomes: list[DefectOutcome]
    top_n: int

    def passed(self) -> int:
        return sum(1 for o in self.outcomes if o.within_top(self.top_n))

    def all_passed(self) -> bool:
        return bool(self.outcomes) and self.passed() == len(self.outcomes)


class Validator:
    def __init__(self, result: AnalysisResult, config: AnalysisConfig):
        self.result = result
        self.config = config
        self.rank_index = RankIndex(result.ranking)
        self.explainer = Explainer(result, config)

    def validate(self, truth: GroundTruth) -> ValidationReport:
        return ValidationReport([self._evaluate(d) for d in truth.defects],
                                self.config.ranking.top_n)

    def _evaluate(self, defect: Defect) -> DefectOutcome:
        candidates: list[tuple[Finding, str]] = []
        for cf in self.result.detection.per_cluster:
            sig = cf.cluster.signature
            for f in cf.findings:
                if f.episode.thread_id == defect.thread_id and defect.contains(f.episode.start):
                    candidates.append((f, sig))

        expected = defect.expected_divergence_call_site
        at_different = False
        if expected is not None and candidates:
            matching = [c for c in candidates if c[0].divergence_call_site == expected]
            if matching:
                candidates = matching
            else:
                at_different = True

        if not candidates:
            at = defect.window_start or defect.window_end or datetime.now(timezone.utc)
            trace = self.explainer.explain(defect.thread_id, at)
            return DefectOutcome(defect.id, defect.description, False, None, None,
                                 "not detected - " + trace.outcome)

        best_rank = None
        best_type = None
        any_suppressed = False
        for f, sig in candidates:
            rank = self.rank_index.rank_of(f, sig)
            if rank is None:
                any_suppressed |= self.rank_index.is_suppressed(f, sig)
                continue
            if best_rank is None or rank < best_rank:
                best_rank, best_type = rank, f.type.value

        if best_rank is None:
            note = "detected but suppressed" if any_suppressed else "detected but not ranked"
            return DefectOutcome(defect.id, defect.description, False, None, None, note)

        note = (f"in top {self.config.ranking.top_n}" if best_rank <= self.config.ranking.top_n
                else f"ranked but below top {self.config.ranking.top_n}")
        if at_different:
            note += "; note: found at a different call site than expected"
        return DefectOutcome(defect.id, defect.description, True, best_rank, best_type, note)
