"""Thread Flow Analyzer — Python port.

Public entry point: ``analyze(log_directory, config, suppressions=None)`` — the
seam a future POSTMORTEM integration joins on.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .cluster import SignatureClusterer
from .config import AnalysisConfig
from .detect import DetectionEngine, DetectionResult
from .ingest import FileSetReader, ParseStats, RecordParser
from .model import FlowCluster
from .rank import FindingRanker, RankingResult, Suppressions
from .segment import StreamingSegmenter

VERSION = "0.1.0"


@dataclass
class AnalysisResult:
    clusters: list[FlowCluster]
    detection: DetectionResult
    ranking: RankingResult
    ordered_files: list[Path]


def analyze(log_directory: Path, config: AnalysisConfig,
            suppressions: Optional[Suppressions] = None) -> AnalysisResult:
    if suppressions is None:
        suppressions = Suppressions.none()
    parser = RecordParser(config.profile)
    reader = FileSetReader(Path(log_directory), parser, ParseStats())
    reader.require_match_rate(config.sample_lines, config.match_threshold)
    ordered_files = reader.ordered_files

    segmenter = StreamingSegmenter(config.segmentation.build_strategy())
    clusterer = SignatureClusterer(config.clustering.signature_k)
    segmenter.segment(reader.records(), clusterer.add)
    clusters = clusterer.finish(config.clustering.min_cluster_size)

    detection = DetectionEngine(config.detection, config.baseline).detect(clusters)
    ranking = FindingRanker(config.ranking, suppressions).rank(detection)
    return AnalysisResult(clusters, detection, ranking, ordered_files)
