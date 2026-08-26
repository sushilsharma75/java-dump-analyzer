"""compare must work on ANY log format - no profile, no config, no match rate."""
import pytest

from tfa.compare import (compare_flows, extract_payload, normalise_template,
                         parse_any_timestamp, read_reference_flows,
                         render_comparison, validate_reference_id)


def write(tmp_path, name, text):
    (tmp_path / name).write_text(text, encoding="utf-8")


def run(tmp_path, good="G1", bad="B1"):
    g, b = read_reference_flows(tmp_path, good, bad)
    return compare_flows(g, b)


# ---------------------------------------------------------------- extraction

def test_extract_payload_handles_kv_json_and_nested_blocks():
    p = extract_payload('POST /x payload={item=laptop, quantity=1} status=OK')
    assert p["item"] == "laptop" and p["quantity"] == "1" and p["status"] == "OK"
    j = extract_payload('{"item":"laptop","qty":1,"ok":true}')
    assert j["item"] == "laptop" and j["qty"] == "1" and j["ok"] == "true"


def test_clock_digits_are_not_read_as_fields():
    p = extract_payload("2026-01-01T10:00:00.100Z msg=hi")
    assert p == {"msg": "hi"}


def test_template_keeps_keys_so_statements_stay_distinct():
    a = normalise_template('{"msg":"order received","qty":1}')
    b = normalise_template('{"msg":"stock check","available":50}')
    assert a != b


def test_timestamp_recognised_in_several_layouts():
    assert parse_any_timestamp("2026-01-01 10:00:00.100 x") is not None
    assert parse_any_timestamp("2026-01-01T10:00:00Z x") is not None
    assert parse_any_timestamp("no timestamp here") is None


def test_reference_id_must_be_a_single_token():
    assert validate_reference_id("  abc123 ") == "abc123"
    for bad in ("has space", ""):
        with pytest.raises(ValueError):
            validate_reference_id(bad)


def test_ids_matched_exactly_not_as_substring(tmp_path):
    write(tmp_path, "a.log", "start abc\nstart abcdef\nnext abc\n")
    good, bad = read_reference_flows(tmp_path, "abc", "abcdef")
    assert good.size() == 2 and bad.size() == 1


def test_identical_ids_rejected(tmp_path):
    with pytest.raises(ValueError):
        read_reference_flows(tmp_path, "same", "same")


# ------------------------------------------------- the four ways flows break

def test_wrong_payload_value_any_format(tmp_path):
    write(tmp_path, "a.log", '{"msg":"recv","reqId":"G1","qty":1}\n'
                             '{"msg":"recv","reqId":"B1","qty":9999}\n')
    f = run(tmp_path).break_step.fields[0]
    assert f.key == "qty" and f.kind == "VALUE_DIFFERS" and (f.good, f.bad) == ("1", "9999")


def test_missing_request_parameter(tmp_path):
    write(tmp_path, "a.log", "call G1 payload={item=x, qty=1}\ncall B1 payload={item=x}\n")
    f = run(tmp_path).break_step.fields[0]
    assert f.key == "qty" and f.kind == "MISSING_IN_BAD" and f.good == "1"


def test_business_logic_branch_and_missing_interface_call(tmp_path):
    write(tmp_path, "a.log",
          "10:00:00.100 G1 begin\n10:00:00.200 G1 stock ok\n"
          "10:00:00.300 G1 charge card\n10:00:00.400 G1 done\n"
          "10:00:01.100 B1 begin\n10:00:01.200 B1 stock short\n10:00:01.400 B1 done\n")
    c = run(tmp_path)
    kinds = {(s.kind, s.label) for s in c.steps}
    assert any(k == "ONLY_IN_GOOD" and "stock ok" in lbl for k, lbl in kinds)
    assert any(k == "ONLY_IN_GOOD" and "charge card" in lbl for k, lbl in kinds)
    assert any(k == "ONLY_IN_BAD" and "stock short" in lbl for k, lbl in kinds)
    assert c.break_index is not None


def test_exception_with_stack_trace_only_in_bad(tmp_path):
    write(tmp_path, "a.log",
          "10:00:00.100 G1 ok\n"
          "10:00:01.100 B1 ok\n"
          "10:00:01.200 B1 ERROR boom\n"
          "java.lang.RuntimeException: boom\n"
          "\tat com.app.X.run(X.java:2)\n")
    c = run(tmp_path)
    assert c.errors_only_in_bad
    text = render_comparison(c)
    assert "java.lang.RuntimeException: boom" in text
    assert "at com.app.X.run(X.java:2)" in text


# ------------------------------------------------------------------- report

def test_reference_id_field_itself_is_not_reported_as_a_difference(tmp_path):
    write(tmp_path, "a.log", 'recv reqId=G1 qty=1\nrecv reqId=B1 qty=1\n')
    assert run(tmp_path).break_index is None


def test_no_break_when_flows_match(tmp_path):
    write(tmp_path, "a.log", "10:00:00.100 G1 ok qty=1\n10:00:00.200 G1 done\n"
                             "10:00:01.100 B1 ok qty=1\n10:00:01.200 B1 done\n")
    c = run(tmp_path)
    assert c.break_index is None and "NO BREAK FOUND" in render_comparison(c)


def test_flows_are_stitched_across_differently_formatted_files(tmp_path):
    write(tmp_path, "json.log", '{"ts":"2026-01-01T10:00:00.100Z","msg":"recv","id":"G1"}\n'
                                '{"ts":"2026-01-01T10:00:01.100Z","msg":"recv","id":"B1"}\n')
    write(tmp_path, "plain.log", "2026-01-01 10:00:00.900 G1 status=CONFIRMED\n"
                                 "2026-01-01 10:00:01.900 B1 status=FAILED\n")
    c = run(tmp_path)
    assert c.good.size() == 2 and c.bad.size() == 2      # both formats, one flow each
    assert any(f.key == "status" for s in c.steps for f in s.fields)


def test_missing_reference_id_is_reported_clearly(tmp_path):
    write(tmp_path, "a.log", "10:00:00.100 G1 ok\n")
    assert "no log lines found" in render_comparison(run(tmp_path))


# ------------------------------------------- business ids via linked technical ids

def test_business_id_reaches_the_full_cross_service_flow(tmp_path):
    """An order id logged by only one service still pulls in the whole flow via
    the trace id it co-occurs with."""
    write(tmp_path, "order.log",
          "2026-01-01 10:00:00.100 new order ORD-1 [trace_id=aaaaaaaa1111]\n"
          "2026-01-01 10:00:01.100 new order ORD-2 [trace_id=bbbbbbbb2222]\n")
    write(tmp_path, "payment.log",             # never mentions the order id
          "2026-01-01 10:00:00.500 charge ok amount=10 [trace_id=aaaaaaaa1111]\n"
          "2026-01-01 10:00:01.500 charge REFUSED amount=10 [trace_id=bbbbbbbb2222]\n")
    good, bad = read_reference_flows(tmp_path, "ORD-1", "ORD-2")
    assert good.size() == 2 and bad.size() == 2          # order + payment legs
    assert good.direct_lines == 1                        # only one line had the order id
    assert good.linked_ids == {"trace_id": "aaaaaaaa1111"}


def test_linking_can_be_disabled(tmp_path):
    write(tmp_path, "order.log",
          "2026-01-01 10:00:00.100 new order ORD-1 [trace_id=aaaaaaaa1111]\n"
          "2026-01-01 10:00:01.100 new order ORD-2 [trace_id=bbbbbbbb2222]\n")
    write(tmp_path, "payment.log",
          "2026-01-01 10:00:00.500 charge ok [trace_id=aaaaaaaa1111]\n"
          "2026-01-01 10:00:01.500 charge no [trace_id=bbbbbbbb2222]\n")
    good, _ = read_reference_flows(tmp_path, "ORD-1", "ORD-2", follow_links=False)
    assert good.size() == 1


def test_a_shared_linking_id_never_merges_the_two_flows(tmp_path):
    """If both references carry the SAME secondary id, it must not be followed -
    otherwise the good and bad flows would collapse into each other."""
    write(tmp_path, "a.log",
          "2026-01-01 10:00:00.100 start ORD-1 sessionId=sharedsession9\n"
          "2026-01-01 10:00:01.100 start ORD-2 sessionId=sharedsession9\n"
          "2026-01-01 10:00:02.100 unrelated noise sessionId=sharedsession9\n")
    good, bad = read_reference_flows(tmp_path, "ORD-1", "ORD-2")
    assert good.size() == 1 and bad.size() == 1
    assert good.linked_ids == {} and bad.linked_ids == {}


def test_link_expansion_is_reported(tmp_path):
    write(tmp_path, "order.log",
          "2026-01-01 10:00:00.100 new order ORD-1 [trace_id=aaaaaaaa1111]\n"
          "2026-01-01 10:00:01.100 new order ORD-2 [trace_id=bbbbbbbb2222]\n")
    write(tmp_path, "payment.log",
          "2026-01-01 10:00:00.500 charge ok [trace_id=aaaaaaaa1111]\n"
          "2026-01-01 10:00:01.500 charge no [trace_id=bbbbbbbb2222]\n")
    text = render_comparison(compare_flows(*read_reference_flows(tmp_path, "ORD-1", "ORD-2")))
    assert "linked via trace_id=aaaaaaaa1111" in text
