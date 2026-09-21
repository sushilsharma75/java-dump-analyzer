from datetime import UTC, datetime

from app.vendor.dbdoctor.engine.models import ConnectionInfo, LockWait
from app.vendor.dbdoctor.engine.run import run_all
from .conftest import GB, MB, make_snapshot, make_table


def _fired(result, rule_id):
    return [f for f in result.findings if f.rule_id == rule_id]


# --- R-L1 ------------------------------------------------------------------


def test_l1_fires_on_long_wait_and_names_both_digests():
    snap = make_snapshot(
        lock_waits=[
            LockWait(blocker_digest="aaa", blocked_digest="bbb", wait_ms=6100.0),
            LockWait(blocker_digest="ccc", blocked_digest="ddd", wait_ms=100.0),  # below threshold
        ]
    )
    f = _fired(run_all(snap), "R-L1")
    assert len(f) == 1
    assert f[0].evidence["blocker_digest"] == "aaa"
    assert f[0].evidence["blocked_digest"] == "bbb"
    assert f[0].severity == "HIGH"


# --- R-C1 ------------------------------------------------------------------


def test_c1_thresholds_and_peak_preference():
    def result_for(current, peak, limit=100):
        return run_all(
            make_snapshot(connections=ConnectionInfo(current=current, peak=peak, max_limit=limit))
        )

    assert not _fired(result_for(50, 70), "R-C1")
    f = _fired(result_for(10, 85), "R-C1")  # peak wins over current
    assert f[0].severity == "HIGH" and f[0].evidence["peak_connections"] == 85
    assert _fired(result_for(10, 95), "R-C1")[0].severity == "CRITICAL"
    # no peak info (PG): current is the basis, confidence drops
    f = _fired(result_for(85, None), "R-C1")
    assert f[0].confidence == "medium" and f[0].evidence["current_connections"] == 85


# --- R-G1 ------------------------------------------------------------------


def test_g1_projects_90_days_and_needs_size_and_growth():
    snap = make_snapshot(
        tables=[
            make_table(name="events", size_bytes=1 * GB, growth_30d_pct=50.0),
            make_table(name="small_fast", size_bytes=10 * MB, growth_30d_pct=90.0),
            make_table(name="big_slow", size_bytes=2 * GB, growth_30d_pct=5.0),
        ]
    )
    f = _fired(run_all(snap), "R-G1")
    assert [x.affected_object for x in f] == ["public.events"]
    # Linear extrapolation: 1GB * (1 + 3 * 0.5) = 2.5 GB
    assert f[0].evidence["projected_size_in_90d"] == "2.5 GB"
    assert f[0].confidence == "medium"


# --- R-M1..M3 (PG) ---------------------------------------------------------


def test_m1_vacuum_lag_and_severity_scaling():
    snap = make_snapshot(
        tables=[
            make_table(name="lagging", size_bytes=200 * MB, dead_tuple_ratio=0.25),
            make_table(name="very_lagging", size_bytes=200 * MB, dead_tuple_ratio=0.50),
            make_table(name="clean", size_bytes=200 * MB, dead_tuple_ratio=0.01),
        ]
    )
    f = {x.affected_object: x for x in _fired(run_all(snap), "R-M1")}
    assert set(f) == {"public.lagging", "public.very_lagging"}
    assert f["public.lagging"].severity == "MEDIUM"
    assert f["public.very_lagging"].severity == "HIGH"


def test_m2_autovacuum_off_globally_and_never_ran():
    from app.vendor.dbdoctor.engine.models import ConfigSetting

    snap = make_snapshot(
        settings=[ConfigSetting(name="autovacuum", value="off")],
        tables=[make_table(name="active", size_bytes=200 * MB, dead_tuple_ratio=0.10)],
    )
    f = _fired(run_all(snap), "R-M2")
    objs = {x.affected_object for x in f}
    assert objs == {"autovacuum", "public.active"}
    # a table that HAS been vacuumed is not flagged
    snap2 = make_snapshot(
        tables=[
            make_table(
                name="vacuumed",
                size_bytes=200 * MB,
                dead_tuple_ratio=0.10,
                last_autovacuum=datetime(2026, 7, 1, tzinfo=UTC),
            )
        ]
    )
    assert not _fired(run_all(snap2), "R-M2")


def test_m3_bloat_is_estimate_low_confidence_never_exact_bytes():
    snap = make_snapshot(
        tables=[make_table(name="bloated", size_bytes=1 * GB, dead_tuple_ratio=0.15)]
    )
    f = _fired(run_all(snap), "R-M3")
    assert len(f) == 1
    assert f[0].confidence == "low"
    assert "estimate" in str(f[0].evidence["estimated_reclaimable"]).lower()
    assert "pgstattuple" in f[0].suggested_action


# --- R-M4 (MySQL) ----------------------------------------------------------


def test_m4_fragmentation_with_optimize_caveats():
    snap = make_snapshot(
        engine="mysql",
        tables=[
            make_table(name="fragged", size_bytes=1000 * MB, data_free_bytes=400 * MB),
            make_table(name="fine", size_bytes=1 * GB, data_free_bytes=50 * MB),
        ],
    )
    f = _fired(run_all(snap), "R-M4")
    assert [x.affected_object for x in f] == ["public.fragged"]
    assert "OPTIMIZE TABLE" in f[0].suggested_action
    assert "maintenance window" in f[0].suggested_action
    assert f[0].evidence["fragmentation_pct"] == 40.0


def test_pg_maintenance_rules_skip_mysql_snapshots():
    snap = make_snapshot(
        engine="mysql",
        tables=[make_table(name="t", size_bytes=1 * GB, dead_tuple_ratio=0.9)],
    )
    result = run_all(snap)
    assert not {"R-M1", "R-M2", "R-M3"} & {f.rule_id for f in result.findings}
