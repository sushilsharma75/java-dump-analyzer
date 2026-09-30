"""run_all(Snapshot) -> AnalysisResult: the engine's single entry point.

Pure: no I/O beyond importing rule modules. Rule modules in engine/rules/
are auto-discovered, so adding a rule is one new file with @register classes.
"""

from __future__ import annotations

import importlib
import pkgutil
from datetime import datetime

from pydantic import BaseModel, Field

import app.vendor.dbdoctor.engine.rules as _rules_pkg
from app.vendor.dbdoctor.engine.models import EngineName, Snapshot
from app.vendor.dbdoctor.engine.rules.base import REGISTRY, Finding, Rule
from app.vendor.dbdoctor.engine.schema import SchemaCatalog
from app.vendor.dbdoctor.engine.score import HealthScore, compute_score, sort_findings

_discovered = False


def discover_rules() -> list[type[Rule]]:
    """Import every module in engine.rules once; return registered rules."""
    global _discovered
    if not _discovered:
        for mod in pkgutil.iter_modules(_rules_pkg.__path__):
            if mod.name != "base":
                importlib.import_module(f"app.vendor.dbdoctor.engine.rules.{mod.name}")
        _discovered = True
    return list(REGISTRY)


class AnalysisResult(BaseModel):
    """Everything downstream (report, AI, storage) consumes only this."""

    engine: EngineName
    host_alias: str
    collected_at: datetime
    is_delta: bool = False
    capabilities: list[str] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    schema_catalog: SchemaCatalog | None = None
    coverage: dict[str, str] = Field(default_factory=dict)
    score: HealthScore


def run_all(snapshot: Snapshot) -> AnalysisResult:
    findings: list[Finding] = []
    for rule_cls in discover_rules():
        if snapshot.meta.engine not in rule_cls.engines:
            continue
        findings.extend(rule_cls().evaluate(snapshot))

    findings = sort_findings(findings)
    coverage = {
        "queries": "observed" if snapshot.queries else "no observations",
        "tables": "observed" if snapshot.tables else "no observations",
        "indexes": "observed" if snapshot.indexes else "no observations",
        "settings": "observed" if snapshot.settings else "no observations",
        "operations": "observed"
        if snapshot.connections or snapshot.sessions or snapshot.lock_waits
        else "no observations",
    }
    score = compute_score(findings)
    if not snapshot.queries or not snapshot.tables:
        score.score = None
    return AnalysisResult(
        engine=snapshot.meta.engine,
        host_alias=snapshot.meta.host_alias,
        collected_at=snapshot.meta.collected_at,
        is_delta=snapshot.meta.is_delta,
        capabilities=snapshot.meta.capabilities,
        findings=findings,
        schema_catalog=snapshot.schema_catalog,
        coverage=coverage,
        score=score,
    )
