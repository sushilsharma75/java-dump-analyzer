"""AnalysisResult + Snapshot → self-contained HTML report."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.vendor.dbdoctor.engine.models import Snapshot
from app.vendor.dbdoctor.engine.rules.base import SEVERITY_RANK, fmt_bytes
from app.vendor.dbdoctor.engine.run import AnalysisResult
from app.vendor.dbdoctor.report.ai_explain import finding_key
from app.vendor.dbdoctor.report.tasks import ticket_markdown

_TEMPLATE_DIR = Path(__file__).parent / "template"

_ENGINE_LABELS = {"postgres": "PostgreSQL", "mysql": "MySQL", "mariadb": "MariaDB"}


def _score_color(score: int | None) -> str:
    if score is None:
        return "#6a6a6a"
    if score >= 85:
        return "#4a6741"
    if score >= 60:
        return "#a07400"
    return "#b3261e"


def _summary_bullets(result: AnalysisResult) -> list[str]:
    """Five plain-English bullets, derived deterministically from findings."""
    n = len(result.findings)
    worst = result.findings[0] if result.findings else None
    by_sev: dict[str, int] = {}
    for f in result.findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

    bullets = [
        (
            "Health score unavailable: insufficient evidence. Query and table observations "
            "are required; missing observations do not establish database health."
            if result.score.score is None
            else f"Health score for captured evidence: {result.score.score}/100. "
            "This score covers only the observations and checks listed in this report."
        ),
        f"{n} findings in total: "
        + ", ".join(
            f"{count} {sev.lower()}"
            for sev, count in sorted(by_sev.items(), key=lambda x: SEVERITY_RANK[x[0]])
        )
        + "."
        if n
        else "No problems detected among the captured statistics.",
    ]
    if worst:
        bullets.append(f"Biggest issue: {worst.title.lower()} ({worst.affected_object}).")
    index_count = sum(1 for f in result.findings if f.category == "indexes")
    if index_count:
        bullets.append(
            f"{index_count} index finding{'s' if index_count != 1 else ''} — usually the "
            "cheapest wins in this report."
        )
    config_count = sum(1 for f in result.findings if f.category == "config")
    if config_count:
        bullets.append(
            f"{config_count} configuration setting{'s' if config_count != 1 else ''} worth "
            "reviewing; each cites its current value and a recommended range."
        )
    bullets.append(
        "Nothing in this report was applied automatically; every change ships with a "
        "staging-first test plan."
    )
    return bullets[:5]


def _action_plan(result: AnalysisResult) -> list[str]:
    plan = [
        f"[Top issue {i}] {f.title} — {f.affected_object}. {f.suggested_action.split('. ')[0]}."
        for i, f in enumerate(result.score.top_findings, 1)
    ]
    remaining = [
        f
        for f in result.findings
        if f.severity in ("CRITICAL", "HIGH", "MEDIUM") and f not in result.score.top_findings
    ]
    if remaining:
        plan.append(
            "Then work through the remaining findings in severity order: "
            + "; ".join(f"{f.rule_id} on {f.affected_object}" for f in remaining[:5])
            + ("…" if len(remaining) > 5 else ".")
        )
    plan.append("Re-run the collector after each change to verify the effect before the next one.")
    return plan


def render_report(
    result: AnalysisResult,
    snapshot: Snapshot,
    *,
    client_alias: str,
    ai_texts: dict[str, str] | None = None,
    integration: dict | None = None,
) -> str:
    """Render the customer-facing HTML report."""
    ai_texts = ai_texts or {}
    env = Environment(
        loader=FileSystemLoader(_TEMPLATE_DIR),
        autoescape=select_autoescape(["html", "j2"]),
    )
    template = env.get_template("report.html.j2")

    top = result.score.top_findings
    total_ms = sum(q.total_time_ms for q in snapshot.queries) or 1.0
    slow_queries = [
        {
            "sql": q.normalized_sql,
            "calls": q.calls,
            "total_ms": q.total_time_ms,
            "mean_ms": q.mean_time_ms,
            "pct": q.total_time_ms / total_ms * 100,
        }
        for q in sorted(snapshot.queries, key=lambda q: -q.total_time_ms)[:10]
    ]

    if snapshot.meta.engine == "postgres":
        engine_health_rows = [
            {
                "name": f"{t.schema_name}.{t.name}",
                "size": fmt_bytes(t.size_bytes),
                "dead_pct": f"{(t.dead_tuple_ratio or 0) * 100:.1f}",
                "last_autovacuum": t.last_autovacuum.strftime("%d %b %Y")
                if t.last_autovacuum
                else "not recorded",
            }
            for t in snapshot.tables[:15]
        ]
    else:
        engine_health_rows = [
            {
                "name": f"{t.schema_name}.{t.name}",
                "size": fmt_bytes(t.size_bytes),
                "data_free": fmt_bytes(t.data_free_bytes or 0),
                "rows": f"{t.row_estimate:,}" if t.row_estimate is not None else "n/a",
            }
            for t in snapshot.tables[:15]
        ]

    return template.render(
        integration=integration,
        client_alias=client_alias,
        engine=result.engine,
        engine_label=_ENGINE_LABELS.get(result.engine, result.engine),
        server_version=snapshot.meta.server_version,
        collected_at=result.collected_at,
        db_size=fmt_bytes(snapshot.meta.db_size_bytes) if snapshot.meta.db_size_bytes else None,
        score=result.score.score,
        score_color=_score_color(result.score.score),
        deductions=result.score.category_deductions,
        summary_bullets=_summary_bullets(result),
        top_findings=top,
        finding_keys=[finding_key(f) for f in top],
        ai_texts=ai_texts,
        tickets={finding_key(f): ticket_markdown(f, ai_texts.get(finding_key(f))) for f in top},
        slow_queries=slow_queries,
        index_findings=[f for f in result.findings if f.category == "indexes"],
        ops_findings=[f for f in result.findings if f.category == "ops"],
        config_findings=[f for f in result.findings if f.category == "config"],
        connections=snapshot.connections,
        engine_health_rows=engine_health_rows,
        action_plan=_action_plan(result),
        routine_stats=snapshot.routine_stats,
        schema_catalog=result.schema_catalog,
        coverage=result.coverage,
        capabilities=result.capabilities,
        capability_notes=snapshot.meta.capability_notes,
    )
