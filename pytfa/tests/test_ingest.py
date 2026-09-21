"""Ingestion is format-agnostic: any text log is read, nothing is ever rejected."""
from tfa.extract import (call_site_of, level_of, normalise_template,
                         parse_any_timestamp, thread_of)
from tfa.ingest import FileSetReader, LineExtractor, ParseStats


def write(tmp_path, name, text):
    (tmp_path / name).write_text(text, encoding="utf-8")


def read(tmp_path, stats=None):
    stats = stats or ParseStats()
    return list(FileSetReader(tmp_path, stats).records()), stats


# ------------------------------------------------------------ field extraction

def test_extracts_fields_from_the_canonical_pipe_format():
    line = ("2026-08-20 10:00:00.123 | INFO | exec-7 | com.acme.OrderService:142 | "
            "processing [trace_id=abc]")
    r = LineExtractor().build(line, "f", 1)
    assert r.timestamp is not None
    assert r.level == "INFO"
    assert r.thread_id == "exec-7"
    assert r.call_site() == "com.acme.OrderService:142"


def test_extracts_fields_from_a_completely_different_format():
    r = LineExtractor().build('{"ts":"2026-01-01T10:00:00Z","level":"ERROR","msg":"boom"}', "f", 1)
    assert r.timestamp is not None and r.level == "ERROR"
    # no Class:line in JSON - a message template stands in as the identity
    assert r.call_site() and "msg" in r.call_site()


def test_lines_without_a_timestamp_are_still_records(tmp_path):
    write(tmp_path, "a.log", "no timestamp at all here\nanother bare line\n")
    recs, stats = read(tmp_path)
    assert len(recs) == 2 and stats.without_timestamp == 2
    assert stats.records == 2          # nothing rejected, no malformed bucket


def test_helpers():
    assert parse_any_timestamp("2026-01-01 10:00:00.100 x") is not None
    assert parse_any_timestamp("nothing here") is None
    assert level_of("a WARNING b") == "WARN"
    assert call_site_of("a Foo:12 b") == "Foo:12"
    assert thread_of("x | INFO | http-nio-8081-exec-1 | y") == "http-nio-8081-exec-1"
    assert normalise_template("qty=1") == normalise_template("qty=9999")


# --------------------------------------------------------------- record contract

def test_stack_trace_attaches_to_the_record_above(tmp_path):
    write(tmp_path, "app.log",
          "2026-08-20 10:00:00.100 | INFO | t | com.acme.Web:10 | begin\n"
          "2026-08-20 10:00:00.200 | ERROR | t | com.acme.Repo:30 | boom\n"
          "java.sql.SQLException: timeout\n"
          "\tat com.acme.Repo.load(Repo.java:30)\n"
          "2026-08-20 10:00:00.300 | INFO | t | com.acme.Web:99 | end\n")
    recs, stats = read(tmp_path)
    assert len(recs) == 3
    assert len(recs[1].continuation_lines) == 2
    assert recs[1].has_stack_trace()
    assert recs[2].continuation_lines == ()
    assert stats.continuation == 2


def test_indented_payload_lines_attach_too(tmp_path):
    write(tmp_path, "a.log", "2026-01-01 10:00:00 start\n    field: value\n")
    recs, _ = read(tmp_path)
    assert len(recs) == 1 and recs[0].continuation_lines == ("    field: value",)


def test_every_line_is_accounted_for(tmp_path):
    write(tmp_path, "a.log", "2026-01-01 10:00:00 a\n\tcont\n2026-01-01 10:00:01 b\n")
    _, stats = read(tmp_path)
    assert stats.total_lines == stats.records + stats.continuation


# --------------------------------------------------------------- file ordering

def test_files_ordered_by_timestamp_not_filename(tmp_path):
    write(tmp_path, "zzz-first.log", "2026-08-20 09:00:00.000 A:1 early\n")
    write(tmp_path, "aaa-second.log", "2026-08-20 11:00:00.000 B:2 late\n")
    reader = FileSetReader(tmp_path)
    assert reader.ordered_files[0].name == "zzz-first.log"
    recs = list(reader.records())
    assert recs[0].call_site() == "A:1" and recs[1].call_site() == "B:2"


def test_file_without_any_timestamp_sorts_last(tmp_path):
    write(tmp_path, "a-noswhen.log", "no time here A:1\n")
    write(tmp_path, "b-timed.log", "2026-08-20 09:00:00.000 B:2 x\n")
    assert FileSetReader(tmp_path).ordered_files[-1].name == "a-noswhen.log"


def test_mixed_formats_in_one_folder_all_read(tmp_path):
    write(tmp_path, "pipe.log", "2026-01-01 10:00:00.100 | INFO | t | A:1 | ok\n")
    write(tmp_path, "json.log", '{"ts":"2026-01-01T10:00:01.100Z","msg":"ok"}\n')
    write(tmp_path, "syslog.log", "Jan  1 10:00:02 host app[1]: ok\n")
    recs, stats = read(tmp_path)
    assert len(recs) == 3 and stats.records == 3


def test_empty_file_and_blank_lines(tmp_path):
    write(tmp_path, "empty.log", "")
    write(tmp_path, "blank.log", "\n\n")
    recs, _ = read(tmp_path)
    assert len(recs) == 2      # blank lines are records, not crashes
