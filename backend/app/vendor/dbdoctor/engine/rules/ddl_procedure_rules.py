"""Static procedure review prompts. They do not claim measured performance issues."""

from app.vendor.dbdoctor.engine.models import Snapshot
from app.vendor.dbdoctor.engine.rules.base import Rule, register


@register
class ProcedureReview(Rule):
    id = "R-SP1"
    title = "Stored routine needs runtime validation"
    category = "queries"

    def evaluate(self, snapshot: Snapshot):
        if not snapshot.schema_catalog:
            return []
        findings = []
        for routine in snapshot.schema_catalog.routines:
            reasons = []
            if routine.loop_lines:
                reasons.append(
                    "Measure statements inside loops before considering batching or set-based SQL."
                )
            if routine.temporary_tables:
                reasons.append(
                    "Measure temporary-table row counts and plans at the point of use; compare "
                    "index and statistics options in staging."
                )
            if routine.dynamic_sql_lines:
                reasons.append(
                    "Capture representative generated SQL locally; its dependencies cannot be "
                    "determined from the definition."
                )
            if routine.variables or routine.parameters:
                reasons.append(
                    "Compare representative parameter cases; lexical variable references do not "
                    "establish runtime values or plan quality."
                )
            if reasons:
                findings.append(
                    self.finding(
                        snapshot,
                        severity="INFO",
                        confidence="low",
                        affected_object=routine.name,
                        evidence={
                            "loop_sites": len(routine.loop_lines),
                            "temporary_tables": len(routine.temporary_tables),
                            "dynamic_sql_sites": len(routine.dynamic_sql_lines),
                            "parameters": len(routine.parameters),
                            "local_variables": len(routine.variables),
                            "parsed_statements": sum(s.parsed for s in routine.statements),
                        },
                        suggested_action=" ".join(reasons),
                    )
                )
        return findings
