"""Ranking: dedup, weighted scoring with the benign-variant guard, suppressions,
and a deterministic sort. Port of `tfa.rank`."""
from __future__ import annotations

import math
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import yaml

from .config import RankingConfig
from .detect import DetectionResult
from .model import Finding, FindingType, TerminalStatus


@dataclass(frozen=True)
class ScoreBreakdown:
    rarity: float
    severity: float
    error_presence: float
    magnitude: float
    cluster_trust: float
    variant_penalty: float
    total: float


@dataclass(frozen=True)
class RankedFinding:
    representative: Finding
    cluster_signature: str
    cluster_size: int
    occurrences: int
    score: float
    breakdown: ScoreBreakdown
    suppressed: bool
    suppression_reason: Optional[str]


# ------------------------------------------------------------- suppressions

@dataclass(frozen=True)
class SuppressionRule:
    cluster_signature: Optional[str]
    divergence_call_site: Optional[str]
    type: Optional[FindingType]
    reason: Optional[str]

    def matches(self, rf: RankedFinding) -> bool:
        if self.cluster_signature is not None and self.cluster_signature != rf.cluster_signature:
            return False
        if self.divergence_call_site is not None \
                and self.divergence_call_site != rf.representative.divergence_call_site:
            return False
        return self.type is None or self.type == rf.representative.type


class Suppressions:
    def __init__(self, rules: list[SuppressionRule]):
        self.rules = list(rules)

    @staticmethod
    def none() -> "Suppressions":
        return Suppressions([])

    def is_empty(self) -> bool:
        return not self.rules

    def reason_for(self, rf: RankedFinding) -> Optional[str]:
        for r in self.rules:
            if r.matches(rf):
                return r.reason or "suppressed"
        return None

    @staticmethod
    def load(path: Path) -> "Suppressions":
        doc = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        if doc is None:
            return Suppressions.none()
        if not isinstance(doc, dict):
            raise ValueError(f"suppressions file is not a YAML mapping: {path}")
        rules = []
        for item in (doc.get("suppressions") or []):
            if isinstance(item, dict):
                t = item.get("type")
                rules.append(SuppressionRule(
                    item.get("clusterSignature"),
                    item.get("divergenceCallSite"),
                    FindingType(str(t).strip()) if t is not None else None,
                    item.get("reason")))
        return Suppressions(rules)


# ---------------------------------------------------------------- the ranker

@dataclass
class RankingResult:
    ranked: list[RankedFinding]
    top: list[RankedFinding]
    suppressed_count: int


_SEVERITY = {FindingType.TRUNCATION: 1.0, FindingType.DIVERGENCE: 0.6, FindingType.TIMING: 0.3}


def _clamp01(v: float) -> float:
    return max(0.0, min(1.0, v))


class FindingRanker:
    def __init__(self, config: RankingConfig, suppressions: Suppressions):
        self.config = config
        self.suppressions = suppressions

    def rank(self, detection: DetectionResult) -> RankingResult:
        # 1. dedup
        groups: dict[str, tuple[str, int, list[Finding]]] = {}
        for cf in detection.per_cluster:
            sig = cf.cluster.signature
            size = cf.cluster.size()
            for f in cf.findings:
                key = f.dedupe_key(sig)
                if key not in groups:
                    groups[key] = (sig, size, [])
                groups[key][2].append(f)

        # 2. score
        ranked: list[RankedFinding] = []
        for sig, size, findings in groups.values():
            rep = self._representative(findings)
            occ = len(findings)
            breakdown = self._score(rep, occ, size)
            rf = RankedFinding(rep, sig, size, occ, breakdown.total, breakdown, False, None)
            reason = self.suppressions.reason_for(rf)
            if reason is not None:
                rf = RankedFinding(rep, sig, size, occ, breakdown.total, breakdown, True, reason)
            ranked.append(rf)

        # 3. deterministic sort
        ranked.sort(key=self._order_key)

        # 4. top N of non-suppressed
        top: list[RankedFinding] = []
        suppressed = 0
        for rf in ranked:
            if rf.suppressed:
                suppressed += 1
            elif len(top) < self.config.top_n:
                top.append(rf)
        return RankingResult(ranked, top, suppressed)

    @staticmethod
    def _representative(findings: list[Finding]) -> Finding:
        def key(f: Finding):
            return (-f.raw_score,
                    f.episode.thread_id or "",
                    epoch_or_max(f.episode.start))
        return min(findings, key=key)

    def _score(self, rep: Finding, occurrences: int, cluster_size: int) -> ScoreBreakdown:
        rarity = 0.0 if cluster_size <= 0 else _clamp01(1.0 - occurrences / cluster_size)
        severity = _SEVERITY[rep.type]
        e = rep.episode
        error_presence = 1.0 if (e.has_error_record() or e.has_stack_trace()) else 0.0
        magnitude = _clamp01(math.log10(max(1.0, rep.raw_score)) / 2.0) if rep.type is FindingType.TIMING else 0.0
        cluster_trust = _clamp01(math.log10(max(1, cluster_size)) / 3.0)
        benign = (rep.type is FindingType.DIVERGENCE and e.status is TerminalStatus.COMPLETED
                  and not e.has_error_record() and not e.has_stack_trace())
        variant_penalty = self.config.benign_variant_penalty if benign else 1.0
        weighted = (self.config.rarity_weight * rarity
                    + self.config.severity_weight * severity
                    + self.config.error_weight * error_presence
                    + self.config.magnitude_weight * magnitude
                    + self.config.cluster_size_weight * cluster_trust)
        total = variant_penalty * weighted
        return ScoreBreakdown(rarity, severity, error_presence, magnitude,
                              cluster_trust, variant_penalty, total)

    @staticmethod
    def _order_key(rf: RankedFinding):
        r = rf.representative
        return (-rf.score, rf.cluster_signature or "", r.divergence_call_site or "",
                r.divergence_index, r.episode.thread_id or "", epoch_or_max(r.episode.start))


def epoch_or_max(dt) -> float:
    return dt.timestamp() if dt is not None else float("inf")
