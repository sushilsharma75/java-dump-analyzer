from datetime import datetime, timezone

from tfa.cluster import SignatureClusterer
from tfa.ingest import FileSetReader, ParseStats
from tfa.model import Episode, LogRecord, TerminalStatus
from tfa.segment import (CorrelationIdStrategy, EntryMarkerStrategy, FlowKeyStrategy,
                         IdleGapStrategy, StreamingSegmenter)
from tfa.testkit import FlowDef, Scenario


def rec(ms, thread, cs, level="INFO"):
    cls, _, ln = cs.rpartition(":")
    return LogRecord(datetime.fromtimestamp(ms / 1000, tz=timezone.utc), level, thread, cls, int(ln),
                     "m", (), "f", 1)


def test_entry_marker_completed_truncated_completed():
    s = EntryMarkerStrategy({"A:1"}, {"C:3"})
    eps = s.segment("t", [rec(0, "t", "A:1"), rec(1, "t", "B:2"), rec(2, "t", "C:3"),
                          rec(3, "t", "A:1"), rec(4, "t", "B:2"),
                          rec(5, "t", "A:1"), rec(6, "t", "X:9"), rec(7, "t", "C:3")])
    assert [e.call_site_sequence() for e in eps] == [
        ["A:1", "B:2", "C:3"], ["A:1", "B:2"], ["A:1", "X:9", "C:3"]]
    assert [e.status for e in eps] == [TerminalStatus.COMPLETED, TerminalStatus.TRUNCATED, TerminalStatus.COMPLETED]


def test_entry_marker_error_makes_errored():
    s = EntryMarkerStrategy({"A:1"}, {"C:3"})
    eps = s.segment("t", [rec(0, "t", "A:1"), rec(1, "t", "B:2", "ERROR"), rec(2, "t", "C:3")])
    assert eps[0].status is TerminalStatus.ERRORED


def test_entry_marker_leading_dropped():
    s = EntryMarkerStrategy({"A:1"}, {"C:3"})
    eps = s.segment("t", [rec(0, "t", "B:2"), rec(1, "t", "Z:9"), rec(2, "t", "A:1"), rec(3, "t", "C:3")])
    assert len(eps) == 1 and eps[0].call_site_sequence() == ["A:1", "C:3"]


def test_idle_gap():
    s = IdleGapStrategy(5000, {"T:9"})
    eps = s.segment("t", [rec(0, "t", "A:1"), rec(100, "t", "B:2"), rec(200, "t", "T:9"),
                          rec(10200, "t", "C:3"), rec(10300, "t", "D:4")])
    assert len(eps) == 2
    assert eps[0].status is TerminalStatus.COMPLETED
    assert eps[1].call_site_sequence() == ["C:3", "D:4"] and eps[1].status is TerminalStatus.TRUNCATED


def test_correlation_id_groups_one_flow_across_threads_and_services():
    """A flow spanning several threads/services is ONE episode when joined by id."""
    s = CorrelationIdStrategy(r"trace_id=([0-9a-f]+)", {"Order:38"})
    assert s.name == "CORRELATION_ID"
    assert isinstance(s, FlowKeyStrategy)

    def r(ms, thread, cs, trace):
        cls, _, ln = cs.rpartition(":")
        return LogRecord(datetime.fromtimestamp(ms / 1000, tz=timezone.utc), "INFO", thread,
                         cls, int(ln), f"work [trace_id={trace}]", (), "f", 1)

    # trace aaa spans 3 threads (order -> inventory -> payment), interleaved with bbb
    stream = [r(0, "order-1", "Order:28", "aaa"), r(1, "order-9", "Order:28", "bbb"),
              r(2, "inv-7", "Inventory:31", "aaa"), r(3, "pay-2", "Payment:29", "aaa"),
              r(4, "order-1", "Order:38", "aaa"), r(5, "order-9", "Order:38", "bbb")]
    eps = StreamingSegmenter(s).segment_to_list(iter(stream))

    assert len(eps) == 2, "one episode per correlation id, not per thread"
    aaa = next(e for e in eps if e.thread_id == "aaa")
    assert aaa.call_site_sequence() == ["Order:28", "Inventory:31", "Payment:29", "Order:38"]
    assert aaa.status is TerminalStatus.COMPLETED


def test_correlation_id_sorts_records_into_time_order():
    """Records arrive per-file, so a flow's records must be re-sorted by time."""
    s = CorrelationIdStrategy(r"trace_id=(\w+)")

    def r(ms, cs):
        cls, _, ln = cs.rpartition(":")
        return LogRecord(datetime.fromtimestamp(ms / 1000, tz=timezone.utc), "INFO", "t",
                         cls, int(ln), "m [trace_id=x]", (), "f", 1)

    # deliberately out of order (as if read from separate service files)
    eps = StreamingSegmenter(s).segment_to_list(iter([r(300, "C:3"), r(100, "A:1"), r(200, "B:2")]))
    assert eps[0].call_site_sequence() == ["A:1", "B:2", "C:3"]


def test_records_without_correlation_id_are_dropped():
    s = CorrelationIdStrategy(r"trace_id=(\w+)")
    good = LogRecord(datetime.fromtimestamp(0, tz=timezone.utc), "INFO", "t", "A", 1,
                     "m [trace_id=x]", (), "f", 1)
    bad = LogRecord(datetime.fromtimestamp(1, tz=timezone.utc), "INFO", "t", "B", 2,
                    "no id here", (), "f", 1)
    eps = StreamingSegmenter(s).segment_to_list(iter([good, bad]))
    assert len(eps) == 1 and eps[0].call_site_sequence() == ["A:1"]


def test_streaming_interleaved_threads():
    s = StreamingSegmenter(EntryMarkerStrategy({"A:1"}, {"C:3"}))
    stream = [rec(0, "t1", "A:1"), rec(1, "t2", "A:1"), rec(2, "t1", "B:2"), rec(3, "t2", "B:2"),
              rec(4, "t1", "C:3"), rec(5, "t2", "C:3"), rec(6, "t1", "A:1"), rec(7, "t1", "C:3")]
    eps = s.segment_to_list(iter(stream))
    t1 = [e for e in eps if e.thread_id == "t1"]
    t2 = [e for e in eps if e.thread_id == "t2"]
    assert len(t1) == 2 and len(t2) == 1
    assert t1[0].call_site_sequence() == ["A:1", "B:2", "C:3"]
    assert t1[1].call_site_sequence() == ["A:1", "C:3"]


FLOWS = [
    FlowDef("login", ["com.acme.Login:10", "com.acme.Token:20", "com.acme.Login:99"]),
    FlowDef("order", ["com.acme.Order:10", "com.acme.Repo:20", "com.acme.Order:99"]),
    FlowDef("batch", ["com.acme.Batch:10", "com.acme.Job:20", "com.acme.Job:30", "com.acme.Batch:99"]),
]


def _run(directory, strategy):
    reader = FileSetReader(directory, ParseStats())
    return StreamingSegmenter(strategy).segment_to_list(reader.records())


def _by_thread(eps):
    out = {}
    for e in eps:
        out.setdefault(e.thread_id, []).append(e.call_site_sequence())
    return out


def _expected(res):
    return {t.thread_id: t.episode_sequences for t in res.truths}


def test_pipeline_entry_marker_recovers_boundaries(tmp_path):
    res = Scenario(FLOWS).threads(4).episodes(5).within(50).idle(10000).files(3).generate(tmp_path)
    strategy = EntryMarkerStrategy(res.entry_call_sites, res.terminal_call_sites)
    assert _by_thread(_run(tmp_path, strategy)) == _expected(res)


def test_pipeline_idle_gap_recovers_boundaries(tmp_path):
    res = Scenario(FLOWS).threads(4).episodes(5).within(50).idle(10000).files(3).generate(tmp_path)
    strategy = IdleGapStrategy(5000, res.terminal_call_sites)
    assert _by_thread(_run(tmp_path, strategy)) == _expected(res)


# -- clustering --

def _episode(thread, *css):
    e = Episode(thread)
    t = 0
    for cs in css:
        cls, _, ln = cs.rpartition(":")
        e.add(LogRecord(datetime.fromtimestamp(t, tz=timezone.utc), "INFO", thread, cls, int(ln), "m", (), "f", 1))
        t += 1
    return e


CLUSTER_FLOWS = [
    ["X:1", "X:2", "X:3", "X:4"], ["X:1", "X:2", "Y:3", "Y:4"],
    ["Z:1", "Z:2", "Z:3"], ["Z:1", "W:2", "W:3"],
    ["M:1", "M:2", "M:3", "M:4", "M:5", "M:6"],
]


def _cluster_count(k, copies=12):
    c = SignatureClusterer(k)
    for f in range(len(CLUSTER_FLOWS)):
        for i in range(copies):
            c.add(_episode(f"t{f}-{i}", *CLUSTER_FLOWS[f]))
    return len(c.finish(1))


def test_k3_recovers_five_clusters():
    assert _cluster_count(3) == 5


def test_k_sensitivity():
    assert _cluster_count(1) == 3
    assert _cluster_count(3) == 5
    assert _cluster_count(5) == 5


def test_under_sampled_marked():
    c = SignatureClusterer(3)
    for i in range(15):
        c.add(_episode(f"a{i}", *CLUSTER_FLOWS[0]))
    for i in range(3):
        c.add(_episode(f"c{i}", *CLUSTER_FLOWS[2]))
    clusters = c.finish(10)
    assert len(clusters) == 2
    assert not clusters[0].under_sampled and clusters[0].size() == 15
    assert clusters[1].under_sampled and clusters[1].size() == 3
