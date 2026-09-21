"""Operational-risk rules: locks (R-L1), connections (R-C1), growth (R-G1)."""

from __future__ import annotations

from app.vendor.dbdoctor.engine.models import Snapshot
from app.vendor.dbdoctor.engine.rules.base import Finding, Rule, fmt_bytes, register
from app.vendor.dbdoctor.engine.thresholds import THRESHOLDS as T


@register
class LockWaitChain(Rule):
    id = "R-L1"
    title = "Sessions were blocked waiting on locks"
    category = "ops"

    def evaluate(self, snapshot: Snapshot) -> list[Finding]:
        findings = []
        for lw in snapshot.lock_waits:
            if lw.wait_ms < T.l1_wait_ms:
                continue
            findings.append(
                self.finding(
                    snapshot,
                    severity="HIGH",
                    affected_object=f"blocked digest {lw.blocked_digest or 'unknown'}",
                    evidence={
                        "wait_ms": round(lw.wait_ms, 0),
                        "blocker_digest": lw.blocker_digest or "unknown",
                        "blocked_digest": lw.blocked_digest or "unknown",
                    },
                    suggested_action=(
                        "A session held a lock long enough to stall others at collection "
                        "time. Look for transactions that stay open across application "
                        "work (user input, API calls, batch loops); keep transactions "
                        "short and commit promptly."
                    ),
                    impact=lw.wait_ms,
                )
            )
        return findings


@register
class ConnectionHeadroom(Rule):
    id = "R-C1"
    title = "Connection usage is close to the configured limit"
    category = "ops"

    def evaluate(self, snapshot: Snapshot) -> list[Finding]:
        conn = snapshot.connections
        if conn is None or conn.max_limit <= 0:
            return []
        observed = max(conn.current, conn.peak or 0)
        basis = "peak_connections" if (conn.peak or 0) > conn.current else "current_connections"
        pct = observed / conn.max_limit
        if pct < T.c1_high_pct:
            return []
        return [
            self.finding(
                snapshot,
                severity="CRITICAL" if pct >= T.c1_critical_pct else "HIGH",
                affected_object="connections",
                evidence={
                    basis: observed,
                    "max_connections": conn.max_limit,
                    "usage_pct": round(pct * 100, 1),
                },
                suggested_action=(
                    "Connections have neared the server limit; the next spike returns "
                    "'too many connections' errors to users. Add connection pooling "
                    "(PgBouncer / ProxySQL or app-side pools) before raising "
                    "max_connections — each connection costs server memory."
                ),
                confidence="high" if conn.peak is not None else "medium",
                impact=pct,
            )
        ]


@register
class TableGrowthRisk(Rule):
    id = "R-G1"
    title = "Table is growing fast"
    category = "ops"

    def evaluate(self, snapshot: Snapshot) -> list[Finding]:
        findings = []
        for t in snapshot.tables:
            if t.growth_30d_pct is None or t.growth_30d_pct < T.g1_growth_30d_pct:
                continue
            if t.size_bytes < T.g1_min_size_bytes:
                continue
            projected_90d = t.size_bytes * (1 + 3 * t.growth_30d_pct / 100)
            findings.append(
                self.finding(
                    snapshot,
                    severity="MEDIUM",
                    affected_object=f"{t.schema_name}.{t.name}",
                    evidence={
                        "current_size": fmt_bytes(t.size_bytes),
                        "growth_30d_pct": round(t.growth_30d_pct, 1),
                        "projected_size_in_90d": fmt_bytes(projected_90d),
                    },
                    suggested_action=(
                        "A linear extrapolation of the observed interval suggests increased "
                        "storage within a quarter; growth may not persist. Decide now whether old rows can be "
                        "archived or partitioned, before size forces an emergency "
                        "instance upgrade."
                    ),
                    confidence="medium",  # extrapolated from one interval
                    impact=float(t.size_bytes) * t.growth_30d_pct,
                )
            )
        return findings
