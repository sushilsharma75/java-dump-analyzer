"""T2.9 acceptance: registry auto-discovery, one-file rule addition,
golden-style harness demonstrated with a single rule."""

from app.vendor.dbdoctor.engine.models import Snapshot
from app.vendor.dbdoctor.engine.rules.base import REGISTRY, Finding, Rule
from app.vendor.dbdoctor.engine.run import discover_rules, run_all
from .conftest import make_query, make_snapshot


def test_rules_are_auto_discovered():
    rules = discover_rules()
    ids = {r.id for r in rules}
    # one rule per planned module is enough to prove discovery works
    assert {"R-Q1", "R-I1", "R-L1", "R-M1", "R-CFG-PG", "R-CFG-MY"} <= ids
    assert len(ids) == len(rules), "duplicate rule ids registered"


def test_dummy_rule_needs_only_registration(monkeypatch):
    """Adding a rule = subclass + @register; run_all picks it up."""

    class AlwaysFires(Rule):
        id = "R-TEST-1"
        title = "dummy"
        category = "other"

        def evaluate(self, snapshot: Snapshot) -> list[Finding]:
            return [
                self.finding(
                    snapshot,
                    severity="INFO",
                    affected_object="everything",
                    suggested_action="nothing",
                    evidence={"answer": 42},
                )
            ]

    monkeypatch.setattr("app.vendor.dbdoctor.engine.run.REGISTRY", [*REGISTRY, AlwaysFires])
    result = run_all(make_snapshot())
    fired = [f for f in result.findings if f.rule_id == "R-TEST-1"]
    assert len(fired) == 1
    assert fired[0].engine == "postgres"
    assert fired[0].evidence == {"answer": 42}


def test_engine_filter_skips_foreign_rules():
    """A PG-only rule never runs on a MySQL snapshot."""
    mysql_snap = make_snapshot(engine="mysql")
    result = run_all(mysql_snap)
    pg_only = {"R-M1", "R-M2", "R-M3", "R-CFG-PG"}
    assert not pg_only & {f.rule_id for f in result.findings}


def test_findings_sorted_by_severity_then_impact():
    snap = make_snapshot(
        queries=[
            # 25% of time -> R-Q1 HIGH; also slow mean, few calls -> R-Q2 LOW
            make_query(
                query_digest="a",
                normalized_sql="SELECT * FROM big WHERE x = ?",
                total_time_ms=2500.0,
                mean_time_ms=2500.0,
                calls=1,
            ),
            make_query(
                query_digest="b",
                normalized_sql="SELECT * FROM huge WHERE y = ?",
                total_time_ms=7500.0,
                mean_time_ms=75.0,
                calls=100,
            ),
        ]
    )
    result = run_all(snap)
    ranks = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    positions = [ranks.index(f.severity) for f in result.findings]
    assert positions == sorted(positions)
    # the 75% query (CRITICAL) outranks the 25% one (HIGH)
    q1 = [f for f in result.findings if f.rule_id == "R-Q1"]
    assert q1[0].evidence["pct_of_captured_query_time"] == 75.0
