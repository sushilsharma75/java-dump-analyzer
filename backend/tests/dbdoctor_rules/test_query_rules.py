from app.vendor.dbdoctor.engine.run import run_all
from .conftest import make_query, make_snapshot


def _fired(result, rule_id):
    return [f for f in result.findings if f.rule_id == rule_id]


def test_q1_fires_at_20_pct_and_evidence_arithmetic_matches():
    snap = make_snapshot(
        queries=[
            make_query(
                query_digest="hot",
                normalized_sql="SELECT * FROM orders WHERE customer_id = ?",
                calls=1000,
                total_time_ms=3000.0,
                mean_time_ms=3.0,
                rows_returned=2000,
            ),
            *[
                make_query(
                    query_digest=f"rest{i}", total_time_ms=1000.0, calls=10, mean_time_ms=100.0
                )
                for i in range(7)
            ],
        ]
    )
    f = _fired(run_all(snap), "R-Q1")
    assert len(f) == 1
    ev = f[0].evidence
    assert ev["pct_of_captured_query_time"] == 30.0  # 3000 / 10000
    assert ev["rows_per_call"] == 2.0
    assert ev["calls"] == 1000
    assert f[0].severity == "HIGH"


def test_q1_critical_above_40_pct():
    snap = make_snapshot(
        queries=[
            make_query(query_digest="hot", total_time_ms=9000.0),
            make_query(query_digest="rest", total_time_ms=1000.0),
        ]
    )
    assert _fired(run_all(snap), "R-Q1")[0].severity == "CRITICAL"


def test_q2_severity_scales_with_calls():
    for calls, expected in ((5, "LOW"), (500, "MEDIUM"), (50_000, "HIGH")):
        snap = make_snapshot(
            queries=[make_query(mean_time_ms=1500.0, calls=calls, total_time_ms=1500.0 * calls)]
        )
        assert _fired(run_all(snap), "R-Q2")[0].severity == expected


def test_q3_uses_delta_rate_at_high_confidence():
    snap = make_snapshot(
        queries=[
            make_query(
                normalized_sql="SELECT * FROM items WHERE order_id = ?",
                calls=10_000_000,
                calls_per_day=80_000.0,
                delta_low_confidence=False,
            )
        ]
    )
    f = _fired(run_all(snap), "R-Q3")[0]
    assert f.confidence == "high"
    assert f.evidence["calls_per_day"] == 80_000


def test_q3_single_snapshot_heuristic_is_low_confidence():
    snap = make_snapshot(
        queries=[make_query(normalized_sql="SELECT * FROM t WHERE id = ?", calls=90_000)]
    )
    f = _fired(run_all(snap), "R-Q3")[0]
    assert f.confidence == "low"
    assert "calls_since_stats_reset" in f.evidence


def test_q3_ignores_transaction_control_noise():
    snap = make_snapshot(queries=[make_query(normalized_sql="COMMIT", calls=5_000_000)])
    assert not _fired(run_all(snap), "R-Q3")
