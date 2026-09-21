"""Offline DBDoctor integration. Never opens a connection to a customer database."""
from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel, ValidationError

from . import artifacts
from .vendor.dbdoctor.engine.models import Snapshot
from .vendor.dbdoctor.engine.run import run_all
from .vendor.dbdoctor.collector.delta import apply_delta

router = APIRouter(prefix="/api", tags=["database"])
MAX_SNAPSHOT_BYTES = 10 * 1024 * 1024
UPSTREAM_REVISION = "59160ccb1878c8c3f3d355ed64abda2335dc4aa9"


def analyze_snapshot(document: dict, baseline: dict | None = None) -> dict:
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
    result = run_all(snapshot).model_dump(mode="json")
    coverage = []
    for section in ("queries", "tables", "indexes", "sessions", "lock_waits", "connections", "settings"):
        value = getattr(snapshot, section)
        recorded = section in recorded_sections and document.get(section) is not None
        status = "available" if value else "empty" if recorded else "missing"
        if section == "queries" and "query_stats" not in snapshot.meta.capabilities:
            status = "unverified" if value else "missing"
        coverage.append({"section": section, "status": status,
                         "count": len(value) if isinstance(value, list) else int(value is not None)})
    limitations = list(snapshot.meta.capability_notes)
    limitations.extend([
        "Scores rank observed findings; they are not a health guarantee. Empty or missing sections cannot rule out problems.",
        "Query shares use captured top statements, not all database activity. Index suggestions require execution-plan validation.",
        "SQL is supplied by the collector. Review sanitization before sharing exports; this endpoint does not redact uploaded text.",
    ])
    if not snapshot.meta.is_delta:
        limitations.append("Single-snapshot counters have an unknown observation window; they do not establish a per-day rate.")
    else:
        limitations.append("Database alias/version matches do not establish uninterrupted counters. Resets or digest eviction can invalidate rates.")
    findings = result["findings"]
    for i, finding in enumerate(findings):
        finding["evidence_id"] = f"db-{i + 1:04d}"
    return {
        **result, "analysis_id": uuid.uuid4().hex,
        "summary": f"{snapshot.meta.engine} · {snapshot.meta.host_alias} · {len(findings)} findings",
        "coverage": coverage, "limitations": limitations,
        "status": "partial" if any(c["status"] in ("missing", "unverified") for c in coverage) else "analyzed",
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
async def analyze_database(file: UploadFile = File(...), baseline: UploadFile | None = File(None)):
    document = await _read_snapshot(file)
    previous = await _read_snapshot(baseline) if baseline is not None else None
    try:
        result = await asyncio.to_thread(analyze_snapshot, document, previous)
    except ValidationError as exc:
        # Do not echo uploaded SQL or connection details in validation errors.
        errors = [{"field": ".".join(map(str, e["loc"])), "type": e["type"]} for e in exc.errors()]
        raise HTTPException(422, {"message": "Invalid database measurements", "errors": errors})
    except (ValueError, OverflowError) as exc:
        raise HTTPException(422, str(exc))
    return artifacts.save(result, "database")


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
