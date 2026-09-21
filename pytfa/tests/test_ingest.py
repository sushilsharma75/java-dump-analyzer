from datetime import datetime, timezone

from tfa.ingest import (FileSetReader, FormatProfile, MatchRateError, ParseStats,
                        RecordParser, detect_format)


def _reader(d, stats=None):
    return FileSetReader(d, RecordParser(FormatProfile.default()), stats or ParseStats())


def _read_all(r):
    return list(r.records())


def test_parses_canonical_envelope():
    p = RecordParser(FormatProfile.default())
    env = p.try_match("2026-08-20 10:00:00.123 | INFO | exec-7 | com.acme.OrderService:142 | processing")
    assert env.ts == "2026-08-20 10:00:00.123"
    assert env.level == "INFO"
    assert env.thread == "exec-7"
    assert env.cls == "com.acme.OrderService"
    assert env.line == "142"
    assert env.msg == "processing"
    rec = p.build(env, [], "app.log", 1, ParseStats())
    assert rec.call_site() == "com.acme.OrderService:142"
    assert rec.timestamp == datetime(2026, 8, 20, 10, 0, 0, 123000, tzinfo=timezone.utc)


def test_non_envelope_line_does_not_match():
    p = RecordParser(FormatProfile.default())
    assert p.try_match("\tat com.acme.Repo.load(Repo.java:30)") is None
    assert p.try_match("plain text") is None


def test_multiline_stack_trace_attaches(tmp_path):
    (tmp_path / "app.log").write_text(
        "2026-08-20 10:00:00.100 | INFO | exec-1 | com.acme.Web:10 | begin\n"
        "2026-08-20 10:00:00.200 | ERROR | exec-1 | com.acme.Repo:30 | boom\n"
        "java.sql.SQLException: timeout\n"
        "\tat com.acme.Repo.load(Repo.java:30)\n"
        "\tat com.acme.Svc.run(Svc.java:20)\n"
        "2026-08-20 10:00:00.300 | INFO | exec-1 | com.acme.Web:99 | end\n")
    stats = ParseStats()
    recs = _read_all(_reader(tmp_path, stats))
    assert len(recs) == 3
    assert recs[1].call_site() == "com.acme.Repo:30"
    assert len(recs[1].continuation_lines) == 3
    assert recs[1].has_stack_trace()
    assert stats.matched == 3 and stats.continuation == 3 and stats.malformed == 0


def test_malformed_lines_counted(tmp_path):
    (tmp_path / "app.log").write_text(
        "### rotated header\ngarbage\n"
        "2026-08-20 10:00:00.100 | INFO | exec-1 | com.acme.Web:10 | begin\n"
        "a trailing continuation\n")
    stats = ParseStats()
    recs = _read_all(_reader(tmp_path, stats))
    assert len(recs) == 1
    assert stats.malformed == 2 and stats.matched == 1 and stats.continuation == 1


def test_files_in_timestamp_order_not_filename(tmp_path):
    (tmp_path / "zzz-first.log").write_text("2026-08-20 09:00:00.000 | INFO | t | com.acme.A:1 | early\n")
    (tmp_path / "aaa-second.log").write_text("2026-08-20 11:00:00.000 | INFO | t | com.acme.B:2 | late\n")
    r = _reader(tmp_path)
    assert r.ordered_files[0].name == "zzz-first.log"
    recs = _read_all(r)
    assert recs[0].call_site() == "com.acme.A:1"
    assert recs[1].call_site() == "com.acme.B:2"


def test_continuation_split_across_file_boundary(tmp_path):
    (tmp_path / "part-a.log").write_text(
        "2026-08-20 10:00:00.100 | ERROR | exec-1 | com.acme.Repo:30 | boom\n"
        "java.sql.SQLException: timeout\n\tat com.acme.Repo.load(Repo.java:30)\n")
    (tmp_path / "part-b.log").write_text(
        "\tat com.acme.Svc.run(Svc.java:20)\n\tat com.acme.Web.handle(Web.java:10)\n"
        "2026-08-20 10:00:05.000 | INFO | exec-1 | com.acme.Web:99 | end\n")
    stats = ParseStats()
    recs = _read_all(_reader(tmp_path, stats))
    assert len(recs) == 2
    assert len(recs[0].continuation_lines) == 4
    assert stats.malformed == 0


def test_empty_and_nomatch_and_separator(tmp_path):
    (tmp_path / "empty.log").write_text("")
    (tmp_path / "junk.log").write_text("not a log\nanother\n")
    stats = ParseStats()
    assert _read_all(_reader(tmp_path, stats)) == []
    assert stats.malformed == 2

    (tmp_path / "sep.log").write_text(
        "2026-08-20 10:00:00.000 | INFO | t | com.acme.A:1 | payload a=1 | b=2 | c=3\n")
    recs = _read_all(_reader(tmp_path / "sep.log", ParseStats()))
    assert recs[0].message == "payload a=1 | b=2 | c=3"


def test_match_rate_fails_below_threshold(tmp_path):
    lines = ["junk %d" % i for i in range(60)]
    lines += ["2026-08-20 10:00:00.00%d | INFO | t | com.acme.A:1 | ok" % (i % 10) for i in range(40)]
    (tmp_path / "mixed.log").write_text("\n".join(lines) + "\n")
    r = _reader(tmp_path)
    assert r.check_match_rate(1000).rate < 0.95
    try:
        r.require_match_rate(1000, 0.95)
        assert False
    except MatchRateError as e:
        assert e.report.failures


def test_detect_format(tmp_path):
    f = tmp_path / "app.log"
    f.write_text("".join(
        f"2026-08-20 10:00:0{i % 10}.123 | INFO | exec-{i % 4} | com.acme.Svc:{10 + i % 5} | work\n"
        for i in range(100)))
    d = detect_format(f)
    assert d.match_rate > 0.95
    assert d.profile.timestamp_pattern == "yyyy-MM-dd HH:mm:ss.SSS"
