"""Rule chassis: the Finding model, the Rule ABC, and the registry.

Rules are pure functions from Snapshot to findings — no I/O, no network,
no DB. That keeps them unit-testable against golden fixtures, reorderable,
and safe to run anywhere.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar, Literal

from pydantic import BaseModel, Field

from app.vendor.dbdoctor.engine.models import EngineName, Snapshot

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
Confidence = Literal["high", "medium", "low"]
Category = Literal["queries", "indexes", "ops", "maintenance", "config", "procedures", "other"]

SEVERITY_RANK: dict[str, int] = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

ALL_ENGINES: frozenset[str] = frozenset({"postgres", "mysql", "mariadb"})


class Finding(BaseModel):
    """One evidence-backed problem statement. Evidence is the audit's
    credibility: named numeric facts only, never prose claims."""

    rule_id: str
    severity: Severity
    title: str
    evidence: dict[str, float | int | str] = Field(default_factory=dict)
    affected_object: str
    suggested_action: str
    confidence: Confidence = "high"
    engine: EngineName
    category: Category = "other"
    impact: float = 0.0  # sort key within a severity band; not rendered


class Rule(ABC):
    """One deterministic check. Subclasses set the class metadata and
    implement evaluate(); they must call self.finding() so category/engine
    metadata stays consistent."""

    id: ClassVar[str]
    title: ClassVar[str]
    engines: ClassVar[frozenset[str]] = ALL_ENGINES
    category: ClassVar[Category] = "other"

    @abstractmethod
    def evaluate(self, snapshot: Snapshot) -> list[Finding]: ...

    def finding(
        self,
        snapshot: Snapshot,
        *,
        severity: Severity,
        affected_object: str,
        suggested_action: str,
        evidence: dict[str, float | int | str],
        confidence: Confidence = "high",
        impact: float = 0.0,
        title: str | None = None,
    ) -> Finding:
        return Finding(
            rule_id=self.id,
            severity=severity,
            title=title or self.title,
            evidence=evidence,
            affected_object=affected_object,
            suggested_action=suggested_action,
            confidence=confidence,
            engine=snapshot.meta.engine,
            category=self.category,
            impact=impact,
        )


REGISTRY: list[type[Rule]] = []


def register(cls: type[Rule]) -> type[Rule]:
    """Explicit registration decorator for concrete rules."""
    REGISTRY.append(cls)
    return cls


# --------------------------------------------------------------------------
# Shared helpers for rules that inspect normalized SQL
# --------------------------------------------------------------------------


def table_of(normalized_sql: str) -> str | None:
    from app.vendor.dbdoctor.engine.sql_analysis import filter_candidates

    candidates = filter_candidates(normalized_sql)
    return candidates[0][0] if len(candidates) == 1 else None


def equality_filter_columns(normalized_sql: str) -> list[str]:
    from app.vendor.dbdoctor.engine.sql_analysis import filter_candidates

    return list(dict.fromkeys(c for _, cols in filter_candidates(normalized_sql) for c in cols))


def fmt_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:.1f} TB"
