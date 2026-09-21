from datetime import datetime, timedelta, timezone

from tfa import AnalysisResult
from tfa.cluster import SignatureClusterer
from tfa.config import (AnalysisConfig, BaselineConfig, ClusteringConfig, DetectionConfig,
                        RankingConfig, SegmentationConfig, StrategyKind)
from tfa.detect import DetectionEngine
from tfa.ingest import FormatProfile
from tfa.model import Episode, FindingType, FlowCluster, LogRecord, TerminalStatus
from tfa.rank import FindingRanker, SuppressionRule, Suppressions
from tfa.report import CorpusFingerprint, Report, log_context, render_text
from tfa.validate import Defect, Explainer, GroundTruth, Validator
from tfa import testkit

T0 = datetime(2026, 8, 20, 10, 0, 0, tzinfo=timezone.utc)


def _detection(cluster):
    return DetectionEngine(DetectionConfig(3.0, 0), BaselineConfig()).detect([cluster])


def _corpus_5wrong_1trunc():
    c = FlowCluster("sig")
    for i in range(100):
        c.add(testkit.clean(f"clean-{i}", T0 + timedelta(seconds=10 + i)))
    for i in range(5):
        c.add(testkit.wrong_branch(f"wrong-{i}", T0 + timedelta(seconds=30 + i)))
    c.add(testkit.truncated("trunc", T0 + timedelta(seconds=50)))
    return c


def _first(ranked, t):
    return next((r for r in ranked if r.representative.type is t), None)


def test_dedup():
    r = FindingRanker(RankingConfig(), Suppressions.none()).rank(_detection(_corpus_5wrong_1trunc()))
    div = _first(r.ranked, FindingType.DIVERGENCE)
    assert div.occurrences == 5


def test_completed_rare_below_truncated():
    r = FindingRanker(RankingConfig(), Suppressions.none()).rank(_detection(_corpus_5wrong_1trunc()))
    trunc = _first(r.ranked, FindingType.TRUNCATION)
    div = _first(r.ranked, FindingType.DIVERGENCE)
    assert trunc.score > div.score
    assert r.ranked.index(trunc) < r.ranked.index(div)


def test_reproducible():
    d = _detection(_corpus_5wrong_1trunc())
    ranker = FindingRanker(RankingConfig(), Suppressions.none())
    assert ranker.rank(d).ranked == ranker.rank(d).ranked


def test_suppressions():
    supp = Suppressions([SuppressionRule("sig", "com.acme.Wrong:8", FindingType.DIVERGENCE, "known")])
    r = FindingRanker(RankingConfig(), supp).rank(_detection(_corpus_5wrong_1trunc()))
    assert all(rf.representative.type is not FindingType.DIVERGENCE for rf in r.top)
    assert r.suppressed_count == 1


def _errored_stack(thread, start):
    e = Episode(thread)
    t = start
    for cs in ("com.acme.Entry:1", "com.acme.Svc:2"):
        cls, _, ln = cs.rpartition(":")
        e.add(LogRecord(t, "INFO", thread, cls, int(ln), "m", (), "f", 1))
        t += timedelta(milliseconds=100)
    e.add(LogRecord(t, "ERROR", thread, "com.acme.Proc", 3, "boom",
                    ("java.lang.RuntimeException: boom", "\tat com.acme.Proc.run(Proc.java:3)"), "f", 1))
    e.set_status(TerminalStatus.ERRORED)
    return e


def test_report_renders_stack_traces():
    c = FlowCluster("sig")
    for i in range(100):
        c.add(testkit.clean(f"clean-{i}", T0 + timedelta(seconds=10 + i)))
    c.add(_errored_stack("boom", T0 + timedelta(seconds=40)))
    ranking = FindingRanker(RankingConfig(), Suppressions.none()).rank(_detection(c))
    report = Report("test", T0, "cfg", CorpusFingerprint("h", [], T0, T0), "default", "ENTRY_MARKER",
                    0, 0, 0, len(ranking.ranked), ranking.suppressed_count, ranking.top)
    text = render_text(report)
    assert "java.lang.RuntimeException: boom" in text
    assert "at com.acme.Proc.run(Proc.java:3)" in text


# ---------------- validate / explain ----------------

def _config(margin):
    return AnalysisConfig(FormatProfile.default(), 0.95, 1000,
                          SegmentationConfig(StrategyKind.ENTRY_MARKER,
                                             frozenset({"com.acme.Entry:1"}), frozenset({"com.acme.Entry:99"}), 5000),
                          ClusteringConfig(3, 10, 200), BaselineConfig(),
                          DetectionConfig(3.0, margin), RankingConfig())


def _result(episodes, cfg):
    c = SignatureClusterer(cfg.clustering.signature_k)
    for e in episodes:
        c.add(e)
    clusters = c.finish(cfg.clustering.min_cluster_size)
    d = DetectionEngine(cfg.detection, cfg.baseline).detect(clusters)
    r = FindingRanker(cfg.ranking, Suppressions.none()).rank(d)
    return AnalysisResult(clusters, d, r, [])


def _corpus_trunc():
    eps = [testkit.clean(f"clean-{i}", T0 + timedelta(seconds=10 + i)) for i in range(100)]
    eps.append(testkit.truncated("trunc", T0 + timedelta(seconds=30)))
    return eps


def test_ground_truth_load(tmp_path):
    f = tmp_path / "gt.yaml"
    f.write_text("""
defects:
  - id: DEF-1
    threadId: exec-3
    timestampWindow:
      start: "2026-08-20T10:00:00Z"
      end:   "2026-08-20T10:05:00Z"
    expectedDivergenceCallSite: "com.acme.repo.OrderRepository:30"
    description: "DB timeout"
""")
    gt = GroundTruth.load(f)
    assert len(gt.defects) == 1
    d = gt.defects[0]
    assert d.id == "DEF-1" and d.contains(datetime(2026, 8, 20, 10, 2, tzinfo=timezone.utc))
    assert not d.contains(datetime(2026, 8, 20, 11, tzinfo=timezone.utc))


def test_validator_finds_defect():
    cfg = _config(0)
    r = _result(_corpus_trunc(), cfg)
    gt = GroundTruth([Defect("DEF-1", "trunc", T0 + timedelta(seconds=29), T0 + timedelta(seconds=31),
                             "com.acme.Proc:3", "truncated flow")])
    report = Validator(r, cfg).validate(gt)
    assert report.all_passed()
    o = report.outcomes[0]
    assert o.found and o.rank == 1 and o.type == "TRUNCATION"


def test_validator_missing():
    cfg = _config(0)
    r = _result(_corpus_trunc(), cfg)
    gt = GroundTruth([Defect("GHOST", "ghost", T0, T0 + timedelta(seconds=5), None, "nope")])
    report = Validator(r, cfg).validate(gt)
    assert not report.all_passed()
    assert not report.outcomes[0].found and "no episode" in report.outcomes[0].note.lower()


def test_explain_reports_rank():
    cfg = _config(0)
    r = _result(_corpus_trunc(), cfg)
    trace = Explainer(r, cfg).explain("trunc", T0 + timedelta(seconds=30))
    assert trace.reported_rank == 1 and trace.outcome.startswith("REPORTED")


def test_explain_clean_not_reported():
    cfg = _config(0)
    r = _result(_corpus_trunc(), cfg)
    trace = Explainer(r, cfg).explain("clean-25", T0 + timedelta(seconds=35))
    assert "no detector fired" in trace.outcome


def test_explain_censored():
    cfg = _config(3_600_000)
    r = _result(_corpus_trunc(), cfg)
    trace = Explainer(r, cfg).explain("trunc", T0 + timedelta(seconds=30))
    assert "CENSORED" in trace.outcome
