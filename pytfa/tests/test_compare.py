from datetime import datetime, timedelta, timezone

import pytest

from tfa.compare import (compare_flows, episodes_for_ids, extract_payload,
                         render_comparison, validate_reference_id)
from tfa.model import LogRecord

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


def rec(i, cs, msg, level="INFO", conts=()):
    cls, _, ln = cs.rpartition(":")
    return LogRecord(T0 + timedelta(milliseconds=100 * i), level, "t", cls, int(ln),
                     msg, tuple(conts), "f", i)


def test_extract_payload_including_nested_block():
    p = extract_payload("POST /x payload={item=laptop, quantity=1} status=OK")
    assert p["item"] == "laptop" and p["quantity"] == "1" and p["status"] == "OK"


def test_reference_id_must_be_a_single_token():
    assert validate_reference_id("  abc123 ") == "abc123"
    with pytest.raises(ValueError):
        validate_reference_id("has space")
    with pytest.raises(ValueError):
        validate_reference_id("")


def test_ids_matched_exactly_not_as_substring():
    records = [rec(0, "A:1", "start [trace_id=abc]"),
               rec(1, "A:1", "start [trace_id=abcdef]"),      # must NOT match "abc"
               rec(2, "B:2", "next [trace_id=abc]")]
    good, bad = episodes_for_ids(records, "abc", "abcdef")
    assert good.call_site_sequence() == ["A:1", "B:2"]
    assert bad.call_site_sequence() == ["A:1"]


def test_identical_ids_rejected():
    with pytest.raises(ValueError):
        episodes_for_ids([], "same", "same")


def _pair(good_records, bad_records):
    good, bad = episodes_for_ids(good_records + bad_records, "G", "B")
    return compare_flows(good, bad, "G", "B")


def test_detects_missing_parameter_in_payload():
    g = [rec(0, "A:1", "call payload={item=x, qty=1} [G]")]
    b = [rec(0, "A:1", "call payload={item=x} [B]")]
    c = _pair(g, b)
    f = c.break_step.fields[0]
    assert f.key == "qty" and f.kind == "MISSING_IN_BAD" and f.good == "1"


def test_detects_wrong_payload_value():
    g = [rec(0, "A:1", "call qty=1 [G]")]
    b = [rec(0, "A:1", "call qty=9999 [B]")]
    c = _pair(g, b)
    f = c.break_step.fields[0]
    assert f.kind == "VALUE_DIFFERS" and (f.good, f.bad) == ("1", "9999")


def test_detects_business_logic_branch_and_missing_interface_call():
    g = [rec(0, "Ctl:1", "begin [G]"), rec(1, "Ok:2", "stock ok [G]"),
         rec(2, "Pay:3", "charge [G]"), rec(3, "Ctl:9", "done [G]")]
    b = [rec(0, "Ctl:1", "begin [B]"), rec(1, "Fail:4", "stock short [B]"),
         rec(2, "Ctl:9", "done [B]")]
    c = _pair(g, b)
    kinds = {(s.kind, s.call_site) for s in c.steps}
    assert ("ONLY_IN_GOOD", "Ok:2") in kinds      # branch the good flow took
    assert ("ONLY_IN_GOOD", "Pay:3") in kinds     # interface call the bad flow never made
    assert ("ONLY_IN_BAD", "Fail:4") in kinds     # branch the bad flow took instead
    assert c.break_index is not None


def test_detects_exception_only_in_bad():
    g = [rec(0, "A:1", "ok [G]")]
    b = [rec(0, "A:1", "ok [B]"),
         rec(1, "A:2", "boom [B]", level="ERROR",
             conts=["java.lang.RuntimeException: boom", "\tat A.run(A.java:2)"])]
    c = _pair(g, b)
    assert any(r.call_site() == "A:2" for r in c.errors_only_in_bad)
    text = render_comparison(c)
    assert "java.lang.RuntimeException: boom" in text


def test_no_break_when_flows_match():
    g = [rec(0, "A:1", "ok qty=1 [G]"), rec(1, "A:2", "done [G]")]
    b = [rec(0, "A:1", "ok qty=1 [B]"), rec(1, "A:2", "done [B]")]
    c = _pair(g, b)
    assert c.break_index is None
    assert "NO BREAK FOUND" in render_comparison(c)


def test_report_flags_missing_reference_id():
    g = [rec(0, "A:1", "ok [G]")]
    c = _pair(g, [])
    assert "no log lines found" in render_comparison(c)
