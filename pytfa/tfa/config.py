"""Run configuration loaded from a single YAML file. Port of `tfa.config`."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

import yaml

from .ingest import Capability, FormatProfile


class StrategyKind(Enum):
    ENTRY_MARKER = "ENTRY_MARKER"
    IDLE_GAP = "IDLE_GAP"
    CORRELATION_ID = "CORRELATION_ID"


def _parse_instant(value) -> Optional[datetime]:
    if value is None:
        return None
    dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


@dataclass(frozen=True)
class SegmentationConfig:
    strategy: StrategyKind
    entry_call_sites: frozenset[str]
    terminal_call_sites: frozenset[str]
    idle_gap_millis: int

    def build_strategy(self):
        from .segment import EntryMarkerStrategy, IdleGapStrategy, CorrelationIdStrategy
        if self.strategy is StrategyKind.ENTRY_MARKER:
            if not self.entry_call_sites:
                raise ValueError("ENTRY_MARKER strategy requires a non-empty entryCallSites set")
            return EntryMarkerStrategy(self.entry_call_sites, self.terminal_call_sites)
        if self.strategy is StrategyKind.IDLE_GAP:
            if self.idle_gap_millis <= 0:
                raise ValueError("IDLE_GAP strategy requires idleGapMillis > 0")
            return IdleGapStrategy(self.idle_gap_millis, self.terminal_call_sites)
        return CorrelationIdStrategy()


@dataclass(frozen=True)
class ClusteringConfig:
    signature_k: int = 3
    min_cluster_size: int = 10
    cluster_ceiling: int = 200


@dataclass(frozen=True)
class BaselineConfig:
    baseline_start: Optional[datetime] = None
    baseline_end: Optional[datetime] = None
    eval_start: Optional[datetime] = None
    eval_end: Optional[datetime] = None
    alternatives_to_report: int = 3

    @staticmethod
    def _in_window(t, start, end) -> bool:
        if t is None:
            return start is None and end is None
        if start is not None and t < start:
            return False
        return end is None or t < end

    def in_baseline_window(self, start) -> bool:
        return self._in_window(start, self.baseline_start, self.baseline_end)

    def in_eval_window(self, start) -> bool:
        return self._in_window(start, self.eval_start, self.eval_end)


@dataclass(frozen=True)
class DetectionConfig:
    timing_factor: float = 3.0
    censor_margin_millis: Optional[int] = None

    def has_explicit_margin(self) -> bool:
        return self.censor_margin_millis is not None


@dataclass(frozen=True)
class RankingConfig:
    rarity_weight: float = 1.0
    severity_weight: float = 1.0
    error_weight: float = 0.5
    magnitude_weight: float = 0.5
    cluster_size_weight: float = 0.5
    benign_variant_penalty: float = 0.2
    top_n: int = 20


@dataclass
class AnalysisConfig:
    profile: FormatProfile
    match_threshold: float
    sample_lines: int
    segmentation: SegmentationConfig
    clustering: ClusteringConfig
    baseline: BaselineConfig
    detection: DetectionConfig
    ranking: RankingConfig

    @staticmethod
    def load(path: Path) -> "AnalysisConfig":
        doc = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        if not isinstance(doc, dict):
            raise ValueError(f"config is not a YAML mapping: {path}")

        profile = _resolve_profile(doc)
        ingest = doc.get("ingest") or {}
        threshold = float(ingest.get("matchThreshold", 0.95))
        sample_lines = int(ingest.get("sampleLines", 1000))

        seg = doc.get("segmentation")
        if not isinstance(seg, dict):
            raise ValueError("config missing required 'segmentation' section")
        segmentation = SegmentationConfig(
            StrategyKind(str(seg.get("strategy", "ENTRY_MARKER")).strip()),
            frozenset(str(x).strip() for x in (seg.get("entryCallSites") or [])),
            frozenset(str(x).strip() for x in (seg.get("terminalCallSites") or [])),
            int(seg.get("idleGapMillis", 5000)))

        c = doc.get("clustering") or {}
        clustering = ClusteringConfig(int(c.get("signatureK", 3)),
                                      int(c.get("minClusterSize", 10)),
                                      int(c.get("clusterCeiling", 200)))

        b = doc.get("baseline") or {}
        win = b.get("window") or {}
        ev = b.get("evalWindow") or {}
        baseline = BaselineConfig(
            _parse_instant(win.get("start")), _parse_instant(win.get("end")),
            _parse_instant(ev.get("start")), _parse_instant(ev.get("end")),
            int(b.get("alternatives", 3)))

        d = doc.get("detection") or {}
        margin = d.get("censorMarginMillis")
        detection = DetectionConfig(float(d.get("timingFactor", 3.0)),
                                    int(margin) if margin is not None else None)

        r = doc.get("ranking") or {}
        w = r.get("weights") or {}
        ranking = RankingConfig(
            float(w.get("rarity", 1.0)), float(w.get("severity", 1.0)),
            float(w.get("error", 0.5)), float(w.get("magnitude", 0.5)),
            float(w.get("clusterSize", 0.5)),
            float(r.get("benignVariantPenalty", 0.2)), int(r.get("topN", 20)))

        return AnalysisConfig(profile, threshold, sample_lines, segmentation,
                              clustering, baseline, detection, ranking)


def _profile_from_map(name: str, m: dict) -> FormatProfile:
    envelope = m.get("envelope")
    if envelope is None:
        raise ValueError("profile missing required key 'envelope'")
    caps = {Capability(str(c).strip()) for c in (m.get("capabilities") or [])}
    return FormatProfile(name, envelope, m.get("timestampPattern"),
                         str(m.get("zone", "UTC")), caps)


def _resolve_profile(doc: dict) -> FormatProfile:
    name = str(doc.get("profile", "default"))
    profiles = doc.get("profiles")
    if isinstance(profiles, dict) and name in profiles:
        return _profile_from_map(name, profiles[name])
    if name != "default":
        raise ValueError(f"profile '{name}' not defined under 'profiles:'")
    return FormatProfile.default()
