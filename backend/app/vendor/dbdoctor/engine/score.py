"""Deterministic 0-100 health score from findings.

Rubric:
  * Start at 100.
  * Deduct per finding by severity: CRITICAL 15, HIGH 8, MEDIUM 3, LOW 1,
    INFO 0.
  * Deductions are capped per category so one noisy category can never zero
    the score alone: queries -30, indexes -25, ops -25, config -20,
    maintenance -15, other -10.
  * Floor at 5 (a live database is never a 0).

Properties (tested): adding a finding never raises the score (monotonic),
the score is always within [5, 100], and ordering of findings does not
change the result.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from app.vendor.dbdoctor.engine.rules.base import SEVERITY_RANK, Finding

SEVERITY_DEDUCTION: dict[str, int] = {
    "CRITICAL": 15,
    "HIGH": 8,
    "MEDIUM": 3,
    "LOW": 1,
    "INFO": 0,
}

CATEGORY_CAP: dict[str, int] = {
    "queries": 30,
    "indexes": 25,
    "ops": 25,
    "config": 20,
    "maintenance": 15,
    "procedures": 20,
    "other": 10,
}

FLOOR = 5
TOP_N = 5


class HealthScore(BaseModel):
    score: int
    category_deductions: dict[str, int] = Field(
        default_factory=dict, description="points deducted per category, post-cap"
    )
    top_findings: list[Finding] = Field(
        default_factory=list, description="top findings by (severity, impact)"
    )


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Severity first, then impact, then stable tie-breakers."""
    return sorted(
        findings,
        key=lambda f: (SEVERITY_RANK[f.severity], -f.impact, f.rule_id, f.affected_object),
    )


def compute_score(findings: list[Finding]) -> HealthScore:
    raw: dict[str, int] = {}
    for f in findings:
        raw[f.category] = raw.get(f.category, 0) + SEVERITY_DEDUCTION[f.severity]

    deductions = {
        cat: min(points, CATEGORY_CAP.get(cat, CATEGORY_CAP["other"]))
        for cat, points in raw.items()
    }
    score = max(FLOOR, 100 - sum(deductions.values()))
    return HealthScore(
        score=score,
        category_deductions=deductions,
        top_findings=sort_findings(findings)[:TOP_N],
    )
