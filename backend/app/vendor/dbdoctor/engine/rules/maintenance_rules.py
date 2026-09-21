"""Maintenance rules: PG vacuum/bloat (R-M1..R-M3), MySQL fragmentation (R-M4).

Wording discipline: bloat numbers are ESTIMATES derived from dead-tuple
ratios — findings say so and never claim exact bytes."""

from __future__ import annotations

from app.vendor.dbdoctor.engine.models import Snapshot
from app.vendor.dbdoctor.engine.rules.base import Finding, Rule, fmt_bytes, register
from app.vendor.dbdoctor.engine.thresholds import THRESHOLDS as T

PG_ONLY = frozenset({"postgres"})
MYSQL_ONLY = frozenset({"mysql", "mariadb"})


@register
class VacuumLag(Rule):
    id = "R-M1"
    title = "Dead tuples are accumulating faster than vacuum reclaims them"
    category = "maintenance"
    engines = PG_ONLY

    def evaluate(self, snapshot: Snapshot) -> list[Finding]:
        findings = []
        for t in snapshot.tables:
            if t.dead_tuple_ratio is None or t.dead_tuple_ratio < T.m1_dead_tuple_ratio:
                continue
            if t.size_bytes < T.m1_min_size_bytes:
                continue
            findings.append(
                self.finding(
                    snapshot,
                    severity="HIGH"
                    if t.dead_tuple_ratio >= 2 * T.m1_dead_tuple_ratio
                    else "MEDIUM",
                    affected_object=f"{t.schema_name}.{t.name}",
                    evidence={
                        "dead_tuple_pct": round(t.dead_tuple_ratio * 100, 1),
                        "table_size": fmt_bytes(t.size_bytes),
                        "last_autovacuum": t.last_autovacuum.isoformat()
                        if t.last_autovacuum
                        else "not recorded",
                    },
                    suggested_action=(
                        "A large share of this table is dead row versions, which slows "
                        "scans and wastes cache. Lower autovacuum_vacuum_scale_factor "
                        "for this table (ALTER TABLE ... SET (autovacuum_vacuum_scale_"
                        "factor = 0.02)) or schedule a manual VACUUM in a quiet window."
                    ),
                    impact=t.size_bytes * t.dead_tuple_ratio,
                )
            )
        return findings


@register
class AutovacuumNotRunning(Rule):
    id = "R-M2"
    title = "Autovacuum is disabled or has no recorded run for an active table"
    category = "maintenance"
    engines = PG_ONLY

    def evaluate(self, snapshot: Snapshot) -> list[Finding]:
        findings = []
        autovac = next((s.value for s in snapshot.settings if s.name == "autovacuum"), None)
        if autovac == "off":
            findings.append(
                self.finding(
                    snapshot,
                    severity="HIGH",
                    affected_object="autovacuum",
                    evidence={"autovacuum": "off"},
                    suggested_action=(
                        "Autovacuum is disabled server-wide. Unless a carefully managed "
                        "manual vacuum schedule exists, dead rows and transaction-ID age "
                        "will grow unbounded. Re-enable it and tune per-table instead."
                    ),
                    impact=100.0,
                )
            )
        for t in snapshot.tables:
            if t.last_autovacuum is not None:
                continue
            if t.dead_tuple_ratio is None or t.dead_tuple_ratio < T.m2_dead_tuple_ratio:
                continue
            if t.size_bytes < T.m2_min_size_bytes:
                continue
            findings.append(
                self.finding(
                    snapshot,
                    severity="MEDIUM",
                    affected_object=f"{t.schema_name}.{t.name}",
                    evidence={
                        "last_autovacuum": "not recorded",
                        "dead_tuple_pct": round(t.dead_tuple_ratio * 100, 1),
                        "table_size": fmt_bytes(t.size_bytes),
                    },
                    suggested_action=(
                        "This table accumulates dead rows but no autovacuum run was recorded "
                        "in the available statistics — its thresholds are likely too high for a table "
                        "of this size. Set per-table autovacuum parameters."
                    ),
                    impact=t.size_bytes * t.dead_tuple_ratio,
                )
            )
        return findings


@register
class BloatEstimate(Rule):
    id = "R-M3"
    title = "Table likely carries reclaimable bloat (estimate)"
    category = "maintenance"
    engines = PG_ONLY

    def evaluate(self, snapshot: Snapshot) -> list[Finding]:
        findings = []
        for t in snapshot.tables:
            if t.dead_tuple_ratio is None or t.dead_tuple_ratio < T.m3_dead_tuple_ratio:
                continue
            if t.size_bytes < T.m3_min_size_bytes:
                continue
            est = t.size_bytes * t.dead_tuple_ratio
            findings.append(
                self.finding(
                    snapshot,
                    severity="LOW",
                    affected_object=f"{t.schema_name}.{t.name}",
                    evidence={
                        "estimated_reclaimable": f"~{fmt_bytes(est)} (estimate)",
                        "dead_tuple_pct": round(t.dead_tuple_ratio * 100, 1),
                        "table_size": fmt_bytes(t.size_bytes),
                    },
                    suggested_action=(
                        "Rough estimate from dead-tuple statistics only — confirm with "
                        "the pgstattuple extension before acting. If confirmed, VACUUM "
                        "FULL or pg_repack in a maintenance window reclaims the space."
                    ),
                    confidence="low",
                    impact=est,
                )
            )
        return findings


@register
class InnodbFragmentation(Rule):
    id = "R-M4"
    title = "Table carries significant reclaimable space (fragmentation)"
    category = "maintenance"
    engines = MYSQL_ONLY

    def evaluate(self, snapshot: Snapshot) -> list[Finding]:
        findings = []
        for t in snapshot.tables:
            if not t.data_free_bytes or t.size_bytes < T.m4_min_size_bytes:
                continue
            ratio = t.data_free_bytes / t.size_bytes
            if ratio < T.m4_fragmentation_ratio:
                continue
            findings.append(
                self.finding(
                    snapshot,
                    severity="MEDIUM",
                    affected_object=f"{t.schema_name}.{t.name}",
                    evidence={
                        "data_free": fmt_bytes(t.data_free_bytes),
                        "fragmentation_pct": round(ratio * 100, 1),
                        "table_size": fmt_bytes(t.size_bytes),
                    },
                    suggested_action=(
                        "OPTIMIZE TABLE rebuilds the table and reclaims the space — but "
                        "it locks the table while running and briefly needs a full copy "
                        "on disk. Run it only in a maintenance window, largest tables "
                        "last, and skip it if the space would be reused by growth soon."
                    ),
                    confidence="medium",  # data_free includes shared-tablespace slack
                    impact=float(t.data_free_bytes),
                )
            )
        return findings
