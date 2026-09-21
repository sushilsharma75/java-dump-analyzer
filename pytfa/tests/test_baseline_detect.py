from datetime import datetime, timedelta, timezone

from tfa.baseline import build_baseline
from tfa.config import BaselineConfig, DetectionConfig
from tfa.detect import (Censor, DetectionEngine, TimingDetector, divergence_detector,
                        edit_distance, first_divergence, truncation_detector)
from tfa.detect import DivKind
from tfa.model import Episode, FindingType, FlowCluster, LogRecord, TerminalStatus
from tfa import testkit

T0 = datetime(2026, 8, 20, 10, 0, 0, tzinfo=timezone.utc)


def _ep(start, *css):
    e = Episode("t")
    t = start
    for cs in css:
        cls, _, ln = cs.rpartition(":")
        e.add(LogRecord(t, "INFO", "t", cls, int(ln), "m", (), "f", 1))
        t += timedelta(milliseconds=100)
    return e


# ---------------- baseline ----------------

def test_collapse():
    e = _ep(T0, "A:1", "A:1", "A:1", "B:2", "B:2", "C:3")
    assert e.call_site_sequence() == ["A:1", "A:1", "A:1", "B:2", "B:2", "C:3"]
    assert e.collapsed_sequence() == ["A:1", "B:2", "C:3"]
    runs = e.collapsed_runs()
    assert (runs[0].count, runs[1].count, runs[2].count) == (3, 2, 1)


def test_modal_80_20():
    c = FlowCluster("sig")
    for _ in range(80):
        c.add(_ep(T0, "A:1", "B:2", "C:3"))
    for _ in range(20):
        c.add(_ep(T0, "A:1", "X:9", "C:3"))
    b = build_baseline(c, BaselineConfig())
    assert b.modal_sequence == ["A:1", "B:2", "C:3"]
    assert b.modal_count == 80 and abs(b.modal_share - 0.8) < 1e-9
    assert len(b.alternatives) == 1
    assert b.alternatives[0].sequence == ("A:1", "X:9", "C:3") and b.alternatives[0].count == 20


def test_positional_and_transition():
    c = FlowCluster("sig")
    for _ in range(80):
        c.add(_ep(T0, "A:1", "B:2", "C:3"))
    for _ in range(20):
        c.add(_ep(T0, "A:1", "X:9", "C:3"))
    b = build_baseline(c, BaselineConfig())
    exp = b.expected_at(1)
    assert exp.call_site == "B:2" and abs(exp.share - 0.8) < 1e-9
    assert abs(b.transition_probability("A:1", "B:2") - 0.8) < 1e-9
    assert abs(b.transition_probability("A:1", "X:9") - 0.2) < 1e-9


def test_timing_median_p95():
    c = FlowCluster("sig")
    for _ in range(20):
        c.add(_ep(T0, "A:1", "B:2", "C:3"))
    b = build_baseline(c, BaselineConfig())
    ab = b.timing_for("A:1", "B:2")
    assert ab.median_millis == 100.0 and ab.p95_millis == 100.0 and ab.count == 20


def test_loop_collapse_keeps_retry_on_modal():
    c = FlowCluster("sig")
    for _ in range(15):
        c.add(_ep(T0, "A:1", "B:2", "C:3"))
    for _ in range(5):
        c.add(_ep(T0, "A:1", "B:2", "B:2", "B:2", "C:3"))
    b = build_baseline(c, BaselineConfig())
    assert b.modal_sequence == ["A:1", "B:2", "C:3"] and abs(b.modal_share - 1.0) < 1e-9
    assert not b.alternatives


def test_baseline_window():
    c = FlowCluster("sig")
    d1 = datetime(2026, 8, 20, 10, tzinfo=timezone.utc)
    d3 = datetime(2026, 8, 22, 10, tzinfo=timezone.utc)
    for _ in range(30):
        c.add(_ep(d1, "A:1", "B:2", "C:3"))
    for _ in range(30):
        c.add(_ep(d3, "A:1", "X:9", "C:3"))
    cfg = BaselineConfig(datetime(2026, 8, 20, tzinfo=timezone.utc),
                         datetime(2026, 8, 21, tzinfo=timezone.utc), None, None, 3)
    b = build_baseline(c, cfg)
    assert b.episodes_used == 30 and b.modal_sequence == ["A:1", "B:2", "C:3"]


# ---------------- sequence diff ----------------

def test_edit_distance_and_divergence():
    assert edit_distance(["A", "B", "C"], ["A", "X", "C"]) == 1
    assert first_divergence(["A", "B", "C"], ["A", "B", "C"]) is None
    assert first_divergence(["A", "B", "C"], ["A", "B"]) is None  # prefix
    d = first_divergence(["A", "B", "C", "D"], ["A", "B", "X", "D"])
    assert d.index == 2 and d.observed_call_site == "X" and d.kind is DivKind.SUBSTITUTION
    d2 = first_divergence(["A", "B"], ["A", "B", "C"])
    assert d2.index == 2 and d2.kind is DivKind.INSERTION


# ---------------- detectors ----------------

def _clean_baseline():
    c = FlowCluster("sig")
    for i in range(50):
        c.add(testkit.clean(f"t{i}", T0 + timedelta(seconds=i)))
    return build_baseline(c, BaselineConfig())


def test_truncation_detector():
    b = _clean_baseline()
    assert len(truncation_detector(testkit.truncated("d", T0), b)) == 1
    assert truncation_detector(testkit.clean("c", T0), b) == []


def test_divergence_detector():
    b = _clean_baseline()
    f = divergence_detector(testkit.wrong_branch("d", T0), b)
    assert len(f) == 1 and f[0].type is FindingType.DIVERGENCE
    assert f[0].divergence_index == 3 and f[0].expected_call_site == "com.acme.Repo:4"
    assert divergence_detector(testkit.clean("c", T0), b) == []
    assert divergence_detector(testkit.truncated("t", T0), b) == []


def test_timing_detector():
    b = _clean_baseline()
    det = TimingDetector(3.0)
    assert any(x.type is FindingType.TIMING for x in det.detect(testkit.slow_transition("d", T0), b))
    assert det.detect(testkit.clean("c", T0), b) == []
    assert det.detect(testkit.retry_storm("r", T0), b) == []


def test_engine_finds_each_defect_zero_fp():
    c = FlowCluster("sig")
    for i in range(50):
        c.add(testkit.clean(f"clean-{i}", T0 + timedelta(seconds=10 + i)))
    c.add(testkit.truncated("trunc", T0 + timedelta(seconds=30)))
    c.add(testkit.wrong_branch("wrong", T0 + timedelta(seconds=31)))
    c.add(testkit.slow_transition("slow", T0 + timedelta(seconds=32)))
    c.add(testkit.retry_storm("retry", T0 + timedelta(seconds=33)))
    result = DetectionEngine(DetectionConfig(3.0, 500), BaselineConfig()).detect([c])
    fs = result.all_findings()

    def n(t):
        return sum(1 for f in fs if f.type is t)
    assert n(FindingType.TRUNCATION) == 1
    assert n(FindingType.DIVERGENCE) == 1
    assert n(FindingType.TIMING) == 1
    for f in fs:
        assert f.episode.thread_id in ("trunc", "wrong", "slow")


def test_completed_slow_episode_at_boundary_is_flagged_not_censored():
    # Regression: a slow-but-COMPLETE flow at the corpus edge must not be hidden
    # by the p99-duration censor margin (which the outlier itself inflates).
    c = FlowCluster("sig")
    for i in range(30):
        c.add(testkit.clean(f"clean-{i}", T0 + timedelta(seconds=25 * i)))
    # the slow episode is the LAST one (at the boundary) and it completes
    slow = testkit.slow_transition("slow", T0 + timedelta(seconds=25 * 30))
    c.add(slow)
    result = DetectionEngine(DetectionConfig(3.0, None), BaselineConfig()).detect([c])
    timing = [f for f in result.all_findings() if f.type is FindingType.TIMING]
    assert timing, "the slow completed flow at the boundary should be flagged"
    assert all(f.episode.thread_id == "slow" for f in timing)
    assert result.episodes_censored == 0


def test_boundary_censoring():
    c = FlowCluster("sig")
    for i in range(50):
        c.add(testkit.clean(f"clean-{i}", T0 + timedelta(seconds=10 + i)))
    c.add(testkit.truncated("mid", T0 + timedelta(seconds=30)))
    c.add(testkit.truncated("boundary", T0 + timedelta(seconds=120)))
    result = DetectionEngine(DetectionConfig(3.0, 5000), BaselineConfig()).detect([c])
    threads = [f.episode.thread_id for f in result.all_findings() if f.type is FindingType.TRUNCATION]
    assert "mid" in threads and "boundary" not in threads
    assert result.episodes_censored >= 1
