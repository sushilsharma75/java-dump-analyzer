"""Offline DBDoctor integration. Never opens a connection to a customer database."""
from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel, ValidationError

from . import artifacts
from .vendor.dbdoctor.engine.models import Snapshot
from .vendor.dbdoctor.engine.run import run_all
from .vendor.dbdoctor.collector.delta import apply_delta
from .vendor.dbdoctor.engine.ddl import MAX_DDL_BYTES, MAX_DDL_FILES, ingest_ddl
from .vendor.dbdoctor.engine.sql_lexer import redact_sql

router = APIRouter(prefix="/api", tags=["database"])
MAX_SNAPSHOT_BYTES = 10 * 1024 * 1024
UPSTREAM_REVISION = "476fa2dd87f4299066599f9c93d67d169902468e"


def analyze_snapshot(document: dict, baseline: dict | None = None,
                     ddl_sources: list[str] | None = None, client_alias: str = "") -> dict:
    recorded_sections = set(document)
    snapshot = Snapshot.model_validate(document)
    if snapshot.meta.collected_at.utcoffset() is None:
        raise ValueError("Database capture timestamp must include a timezone")
    if not snapshot.meta.host_alias.strip():
        raise ValueError("Database host_alias is required")
    if baseline is not None:
        previous = Snapshot.model_validate(baseline)
        document = apply_delta(snapshot.model_dump(mode="json"), previous.model_dump(mode="json"))
        snapshot = Snapshot.model_validate(document)
    # Catalogs are derived from the optional SQL files, never trusted from JSON.
    snapshot.schema_catalog = None
    for query in snapshot.queries:
        query.normalized_sql = redact_sql(query.normalized_sql, mysql=snapshot.meta.engine != "postgres")
    for index in snapshot.indexes:
        index.definition = redact_sql(index.definition, mysql=snapshot.meta.engine != "postgres")
    if ddl_sources:
        schemas = {table.schema_name for table in snapshot.tables}
        snapshot.schema_catalog = ingest_ddl(ddl_sources, snapshot.meta.engine,
                                            next(iter(schemas)) if len(schemas) == 1 else None)
    result = run_all(snapshot).model_dump(mode="json")
    coverage = []
    for section in ("queries", "tables", "indexes", "sessions", "lock_waits", "connections", "settings", "procedures", "columns"):
        value = getattr(snapshot, section)
        recorded = section in recorded_sections and document.get(section) is not None
        status = "available" if value else "empty" if recorded else "missing"
        if section == "queries" and "query_stats" not in snapshot.meta.capabilities:
            status = "unverified" if value else "missing"
        if section == "procedures" and value and any(
            not p.definition or p.language.lower() not in {"sql", "plpgsql"} for p in value
        ):
            status = "partial"
        if section in {"procedures", "columns"} and recorded and any(
            "truncated" in note.lower() or "omitted" in note.lower()
            for note in snapshot.meta.capability_notes
        ):
            status = "partial"
        coverage.append({"section": section, "status": status,
                         "count": len(value) if isinstance(value, list) else int(value is not None)})
    coverage.append({"section": "routine_stats",
                     "status": "available" if snapshot.routine_stats else "empty" if "routine_stats" in recorded_sections else "missing",
                     "count": len(snapshot.routine_stats)})
    catalog = snapshot.schema_catalog
    coverage.append({"section": "schema_catalog",
                     "status": "partial" if catalog and catalog.warnings else "available" if catalog else "missing",
                     "count": len(catalog.tables) + len(catalog.routines) + len(catalog.indexes) if catalog else 0})
    limitations = list(snapshot.meta.capability_notes)
    limitations.extend([
        "Stored procedure checks are static heuristics for SQL/PLpgSQL bodies, not compilation or measured performance. Dynamic SQL, quoted identifiers, nested query scopes, search_path, collation and control flow are not resolved. Datatype checks require captured column metadata; missing findings do not establish correctness.",
        "Scores rank observed findings; they are not a health guarantee. Empty or missing sections cannot rule out problems.",
        "Query shares use captured top statements, not all database activity. Index suggestions require execution-plan validation.",
        "SQL is supplied by the collector. Review sanitization before sharing exports; this endpoint does not redact uploaded text.",
    ])
    if catalog:
        limitations.extend(catalog.limitations)
        limitations.extend(catalog.warnings)
    if not snapshot.meta.is_delta:
        limitations.append("Single-snapshot counters have an unknown observation window; they do not establish a per-day rate.")
    else:
        limitations.append("Database alias/version matches do not establish uninterrupted counters. Resets or digest eviction can invalidate rates.")
    findings = result["findings"]
    for i, finding in enumerate(findings):
        finding["evidence_id"] = f"db-{i + 1:04d}"
    return {
        **result, "analysis_id": uuid.uuid4().hex,
        "client_alias": client_alias.strip() or snapshot.meta.host_alias,
        "summary": f"{snapshot.meta.engine} · {snapshot.meta.host_alias} · {len(findings)} findings",
        "coverage": coverage, "engine_coverage": result["coverage"], "limitations": limitations,
        "status": "static" if "ddl_static" in snapshot.meta.capabilities else "partial" if any(c["status"] in ("missing", "unverified", "partial") for c in coverage) else "analyzed",
        "score_label": "Observed findings score (not a health certification)",
        "snapshot": snapshot.model_dump(mode="json"),
        "upstream_revision": UPSTREAM_REVISION,
    }


async def _read_snapshot(file: UploadFile) -> dict:
    raw = await file.read(MAX_SNAPSHOT_BYTES + 1)
    if len(raw) > MAX_SNAPSHOT_BYTES:
        raise HTTPException(413, "Database snapshot exceeds 10 MiB")
    try:
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("Expected a JSON object")
        return data
    except (ValueError, UnicodeError, RecursionError):
        raise HTTPException(422, "Invalid snapshot JSON; expected a DBDoctor Snapshot object")


@router.post("/analyze/database")
async def analyze_database(file: UploadFile | None = File(None),
                           baseline: UploadFile | None = File(None),
                           ddl: list[UploadFile] | None = File(None),
                           engine: Literal["postgres", "mysql", "mariadb"] = Form("postgres"),
                           client_alias: str = Form("", max_length=120)):
    if file is None and (not ddl or baseline is not None):
        raise HTTPException(422, "Upload a snapshot or SQL definitions. A baseline requires a current snapshot.")
    document = await _read_snapshot(file) if file is not None else {
        "meta": {"engine": engine, "version": "ddl-static", "server_version": "not captured",
                 "host_alias": client_alias.strip() or "DDL analysis",
                 "collected_at": datetime.now(timezone.utc).isoformat(),
                 "capabilities": ["ddl_static"],
                 "capability_notes": ["DDL-only inspection: the timestamp records analysis time; no live database measurements were captured."]}}
    previous = await _read_snapshot(baseline) if baseline is not None else None
    sources = []
    if ddl:
        if len(ddl) > MAX_DDL_FILES:
            raise HTTPException(413, "At most 20 SQL files are supported")
        remaining = MAX_DDL_BYTES
        for source in ddl:
            raw = await source.read(remaining + 1)
            remaining -= len(raw)
            if remaining < 0:
                raise HTTPException(413, "SQL definitions exceed the 5 MiB combined limit")
            try:
                text = raw.decode("utf-8-sig")
            except UnicodeDecodeError:
                raise HTTPException(422, "SQL definitions must be UTF-8 text") from None
            if not text.strip():
                raise HTTPException(422, "SQL definition files must not be empty")
            sources.append(text)
    try:
        result = await asyncio.to_thread(analyze_snapshot, document, previous, sources, client_alias)
    except ValidationError as exc:
        # Do not echo uploaded SQL or connection details in validation errors.
        errors = [{"field": ".".join(map(str, e["loc"])), "type": e["type"]} for e in exc.errors()]
        raise HTTPException(422, {"message": "Invalid database measurements", "errors": errors})
    except (ValueError, OverflowError) as exc:
        raise HTTPException(422, str(exc))
    return artifacts.save(result, "database")


@router.get("/database/{identifier}/report")
def database_report(identifier: str, fmt: Literal["html", "tasks", "schema", "json"] = "html"):
    try:
        saved = artifacts.read(identifier)
    except (ValueError, FileNotFoundError):
        raise HTTPException(404, "Saved database analysis not found") from None
    if saved["kind"] != "database":
        raise HTTPException(422, "Expected a database analysis")
    analysis = saved["analysis"]
    if fmt == "json":
        content = json.dumps(analysis, indent=2, ensure_ascii=False)
        media, extension = "application/json", "json"
    elif fmt == "schema":
        if not analysis.get("schema_catalog"):
            raise HTTPException(404, "This analysis has no uploaded schema catalog")
        content = json.dumps(analysis["schema_catalog"], indent=2, ensure_ascii=False)
        media, extension = "application/json", "schema.json"
    else:
        from .vendor.dbdoctor.engine.run import AnalysisResult
        from .vendor.dbdoctor.report.render import render_report
        from .vendor.dbdoctor.report.tasks import tasks_markdown
        result = AnalysisResult.model_validate({**analysis, "coverage": analysis.get("engine_coverage", {})})
        if fmt == "tasks":
            content = tasks_markdown(result)
            media, extension = "text/markdown", "tasks.md"
        else:
            content = render_report(result, Snapshot.model_validate(analysis["snapshot"]),
                                    client_alias=analysis.get("client_alias", analysis["host_alias"]),
                                    integration=analysis)
            media, extension = "text/html", "html"
    return Response(content, media_type=media,
                    headers={"Content-Disposition": f'attachment; filename="database-{identifier}.{extension}"'})


@router.get("/database/collectors/{name}")
def collector_download(name: str):
    if name not in {"pg_collect.py", "mysql_collect.py", "delta.py"}:
        raise HTTPException(404, "Collector not found")
    return FileResponse(Path(__file__).parent / "vendor/dbdoctor/collector" / name,
                        filename=name, media_type="text/plain")


class CorrelationInput(BaseModel):
    database_id: str
    thread_id: str
    same_incident_confirmed: bool = False


def correlate_database(database: dict, thread: dict, confirmed: bool) -> dict:
    limitations = ["No shared request/query ID links these captures; this is temporal and stack-pattern evidence, not proven causality."]
    if not confirmed:
        return {"status": "blocked", "leads": [], "limitations": ["Confirm that the JVM connects to this database in the same incident."]}
    try:
        db_time = datetime.fromisoformat(database["collected_at"].replace("Z", "+00:00"))
        thread_time = datetime.fromisoformat(thread["capture"]["captured_at"].replace("Z", "+00:00"))
        if db_time.utcoffset() is None or thread_time.utcoffset() is None:
            raise ValueError()
        gap = abs((db_time - thread_time).total_seconds())
    except (KeyError, ValueError, TypeError, AttributeError):
        return {"status": "blocked", "leads": [], "limitations": ["Both captures need timezone-aware capture timestamps."]}
    if gap > 300:
        return {"status": "blocked", "leads": [], "limitations": ["Captures are more than five minutes apart."]}
    leads = []
    patterns = ("com.zaxxer.hikari.", "org.postgresql.", "com.mysql.", "org.mariadb.jdbc.", "org.apache.commons.dbcp")
    for t in thread.get("threads", []):
        matching = [f for f in t.get("stack", []) if f.get("class_name", "").startswith(patterns)]
        if matching:
            leads.append({"thread": t["name"], "state": t["state"], "frames": matching,
                          "interpretation": "Database driver/pool frames observed; inspect stack and database findings together."})
    return {"status": "leads" if leads else "no_match", "capture_gap_seconds": gap,
            "leads": leads, "database_evidence_ids": [f["evidence_id"] for f in database.get("findings", []) if f["category"] in ("queries", "ops")],
            "limitations": limitations}


@router.post("/correlate/database")
def correlation(request: CorrelationInput):
    try:
        db = artifacts.read(request.database_id)
        thread = artifacts.read(request.thread_id)
    except (ValueError, FileNotFoundError):
        raise HTTPException(404, "Saved analysis not found")
    if db["kind"] != "database" or thread["kind"] != "thread":
        raise HTTPException(422, "Expected a database analysis and a thread analysis")
    return correlate_database(db["analysis"], thread["analysis"], request.same_incident_confirmed)
