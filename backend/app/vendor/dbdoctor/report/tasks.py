"""Findings → paste-ready GitHub/Jira tickets (G4: dev-ready task export).

Every ticket carries: the problem in plain English, the evidence table,
a concrete SQL change where one applies (PG index changes always say
CONCURRENTLY; MySQL notes ALGORITHM=INPLACE), a 3-step staging test plan,
and a rollback note.
"""

from __future__ import annotations

from app.vendor.dbdoctor.engine.rules.base import Finding
from app.vendor.dbdoctor.engine.run import AnalysisResult

TOP_N_TICKETS = 10


def _index_name(table: str, columns: str) -> str:
    cols = columns.replace(" ", "").replace(",", "_")
    return f"idx_{table.split('.')[-1]}_{cols}"[:60]


def suggested_sql(finding: Finding) -> str | None:
    """A concrete SQL change for findings that have one."""
    import re

    def quoted(name):
        quote = '"' if finding.engine == "postgres" else "`"
        return ".".join(
            quote + part.replace(quote, quote + quote) + quote for part in name.split(".")
        )

    table = quoted(str(finding.evidence.get("qualified_table", finding.affected_object)))
    if finding.rule_id == "R-I1":
        columns = str(finding.evidence.get("candidate_columns", ""))
        if not columns:
            return None
        if not all(re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", c.strip()) for c in columns.split(",")):
            return None
        name = quoted(_index_name(finding.affected_object, columns))
        columns = ", ".join(quoted(c.strip()) for c in columns.split(","))
        if finding.engine == "postgres":
            return (
                f"-- CONCURRENTLY avoids locking writes during the build\n"
                f"CREATE INDEX CONCURRENTLY {name} ON {table} ({columns});"
            )
        return (
            f"-- INPLACE keeps the table writable during the build (verify on your version)\n"
            f"ALTER TABLE {table} ADD INDEX {name} ({columns}), ALGORITHM=INPLACE, LOCK=NONE;"
        )
    if finding.rule_id in ("R-I2", "R-I3"):
        parts = finding.affected_object.split(".")
        if len(parts) != 3:
            return None
        schema, table_name, index_name = parts
        index = quoted(f"{schema}.{index_name}" if finding.engine == "postgres" else index_name)
        table = quoted(f"{schema}.{table_name}")
        if finding.engine == "postgres":
            return (
                f"-- keep the definition somewhere first, so it can be recreated\n"
                f"DROP INDEX CONCURRENTLY IF EXISTS {index};"
            )
        return f"ALTER TABLE {table} DROP INDEX {index}, ALGORITHM=INPLACE, LOCK=NONE;"
    return None


def _staging_plan(finding: Finding) -> list[str]:
    if finding.category == "indexes":
        return [
            "Measure the baseline: run EXPLAIN (and time) the affected queries in staging.",
            "Apply the change in staging with production-sized data.",
            "Compare plans and timings; only then schedule the production change.",
        ]
    if finding.category == "config":
        return [
            "Record the current value and how to revert it.",
            "Apply the new value in staging and run a representative workload.",
            "Compare throughput/latency before scheduling the production change.",
        ]
    return [
        "Reproduce the problem in staging using the evidence above as the baseline.",
        "Apply the suggested change in staging only.",
        "Re-measure against the baseline; proceed to production only on clear improvement.",
    ]


def _rollback_note(finding: Finding) -> str:
    if finding.rule_id == "R-I1":
        return "Rollback: DROP the new index (CONCURRENTLY on PostgreSQL). No data is affected."
    if finding.rule_id in ("R-I2", "R-I3"):
        return "Rollback: re-create the index from the saved definition. No data is affected."
    if finding.category == "config":
        return "Rollback: restore the recorded previous value and reload/restart as required."
    return "Rollback: revert the applied change; no schema or data migration is involved."


def ticket_markdown(finding: Finding, ai_text: str | None = None) -> str:
    """One finding as GitHub/Jira-ready markdown."""
    lines = [
        f"# [DB] {finding.title}",
        "",
        f"**Severity:** {finding.severity} · **Rule:** {finding.rule_id} · "
        f"**Engine:** {finding.engine} · **Confidence:** {finding.confidence}",
        f"**Object:** `{finding.affected_object}`",
        "",
        "## Problem",
        ai_text or finding.suggested_action,
        "",
        "## Evidence",
        "| fact | value |",
        "|---|---|",
    ]
    lines += [f"| {k} | {v} |" for k, v in finding.evidence.items()]

    sql = suggested_sql(finding)
    if sql:
        lines += ["", "## Suggested change", "```sql", sql, "```"]

    lines += ["", "## Staging test plan"]
    lines += [f"{i}. {step}" for i, step in enumerate(_staging_plan(finding), 1)]
    lines += ["", f"> {_rollback_note(finding)}"]
    return "\n".join(lines)


def tasks_markdown(result: AnalysisResult, ai_texts: dict[str, str] | None = None) -> str:
    """All top findings as one tasks.md document."""
    from app.vendor.dbdoctor.report.ai_explain import finding_key

    ai_texts = ai_texts or {}
    findings = result.findings[:TOP_N_TICKETS]
    header = (
        f"# Database audit tasks — {result.host_alias} ({result.engine})\n\n"
        f"Generated from {len(findings)} findings. Each section below is one "
        f"paste-ready ticket.\n\n---\n\n"
    )
    return header + "\n\n---\n\n".join(
        ticket_markdown(f, ai_texts.get(finding_key(f))) for f in findings
    )
