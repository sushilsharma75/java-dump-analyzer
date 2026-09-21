"""Query rules R-Q1..R-Q3 (shared across engines)."""

from __future__ import annotations

from app.vendor.dbdoctor.engine.models import QueryStat, Snapshot
from app.vendor.dbdoctor.engine.rules.base import Finding, Rule, register
from app.vendor.dbdoctor.engine.thresholds import THRESHOLDS as T

_DML_PREFIXES = ("select", "insert", "update", "delete", "with")


def _is_workload_query(q: QueryStat) -> bool:
    """Ignore transaction control / SET noise for frequency-based rules."""
    return q.normalized_sql.lower().startswith(_DML_PREFIXES)


def _short(sql: str, n: int = 80) -> str:
    return sql if len(sql) <= n else sql[: n - 1] + "…"


@register
class HighTotalTimeQuery(Rule):
    id = "R-Q1"
    title = "One query consumes a large share of captured statement time"
    category = "queries"

    def evaluate(self, snapshot: Snapshot) -> list[Finding]:
        total_ms = sum(q.total_time_ms for q in snapshot.queries)
        if total_ms <= 0:
            return []
        findings = []
        for q in snapshot.queries:
            pct = q.total_time_ms / total_ms
            if pct < T.q1_pct_of_db_time:
                continue
            findings.append(
                self.finding(
                    snapshot,
                    severity="CRITICAL" if pct >= T.q1_critical_pct else "HIGH",
                    affected_object=_short(q.normalized_sql),
                    evidence={
                        "calls": q.calls,
                        "total_ms": round(q.total_time_ms, 1),
                        "pct_of_captured_query_time": round(pct * 100, 1),
                        "mean_ms": round(q.mean_time_ms, 2),
                        "rows_per_call": round(q.rows_returned / q.calls, 1) if q.calls else 0,
                        "query_digest": q.query_digest,
                    },
                    suggested_action=(
                        "This statement dominates execution time among captured statements. Investigate its "
                        "execution plan first; typical fixes are an index on its filter "
                        "columns, caching its result if it repeats, or restructuring the "
                        "query. Test any change in staging first."
                    ),
                    impact=q.total_time_ms,
                )
            )
        return findings


@register
class SlowMeanTimeQuery(Rule):
    id = "R-Q2"
    title = "Query has high average execution time"
    category = "queries"

    def evaluate(self, snapshot: Snapshot) -> list[Finding]:
        findings = []
        for q in snapshot.queries:
            if q.mean_time_ms < T.q2_mean_ms:
                continue
            if q.calls >= T.q2_high_calls:
                severity = "HIGH"
            elif q.calls >= T.q2_medium_calls:
                severity = "MEDIUM"
            else:
                severity = "LOW"
            findings.append(
                self.finding(
                    snapshot,
                    severity=severity,
                    affected_object=_short(q.normalized_sql),
                    evidence={
                        "mean_ms": round(q.mean_time_ms, 1),
                        "calls": q.calls,
                        "total_ms": round(q.total_time_ms, 1),
                        "rows_per_call": round(q.rows_returned / q.calls, 1) if q.calls else 0,
                        "query_digest": q.query_digest,
                    },
                    suggested_action=(
                        "The observed mean exceeds the slow-query threshold; individual latencies vary. Check the execution plan for "
                        "full scans or sorts; an index on the filter/sort columns is the "
                        "usual fix. If the result changes rarely, cache it. Test in "
                        "staging first."
                    ),
                    impact=q.mean_time_ms * max(q.calls, 1),
                )
            )
        return findings


@register
class HighFrequencyQuery(Rule):
    id = "R-Q3"
    title = "Query runs at very high frequency"
    category = "queries"

    def evaluate(self, snapshot: Snapshot) -> list[Finding]:
        findings = []
        for q in snapshot.queries:
            if not _is_workload_query(q):
                continue
            if q.calls_per_day is not None:
                rate, confidence, basis = q.calls_per_day, "high", "calls_per_day"
                if q.delta_low_confidence:
                    confidence = "low"
            else:
                # single snapshot: counter-since-reset heuristic only
                rate, confidence, basis = float(q.calls), "low", "calls_since_stats_reset"
            if rate < T.q3_calls_per_day:
                continue
            findings.append(
                self.finding(
                    snapshot,
                    severity="HIGH" if rate >= T.q3_high_calls_per_day else "MEDIUM",
                    affected_object=_short(q.normalized_sql),
                    evidence={
                        basis: round(rate, 0),
                        "calls": q.calls,
                        "mean_ms": round(q.mean_time_ms, 2),
                        "total_ms": round(q.total_time_ms, 1),
                        "query_digest": q.query_digest,
                    },
                    suggested_action=(
                        "This statement runs extremely often. Check whether the "
                        "application repeats it per item instead of batching (N+1 "
                        "pattern), and whether its result can be cached. Even a fast "
                        "query at this volume costs real capacity."
                    ),
                    confidence=confidence,
                    impact=rate,
                )
            )
        return findings
