"""Heap investigation API. Query failures never turn unavailable data into zero."""
import csv
import io
from typing import Literal

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel, Field

from . import artifacts
from .analyzers import heap_queries as q

router = APIRouter(prefix="/api/heap")


def analysis(identifier):
    try:
        item = artifacts.read(identifier)
    except (ValueError, FileNotFoundError):
        raise HTTPException(404, "Analysis not found")
    if item["kind"] != "heap":
        raise HTTPException(409, "A heap analysis is required")
    return item["analysis"]


def index(identifier):
    data = analysis(identifier)
    if data.get("object_index_id") != identifier:
        raise HTTPException(409, "Object indexing unavailable; check the coverage panel for the skipped or failed stage")
    return artifacts.path_for(identifier, ".sqlite")


def run(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except q.Unavailable as exc:
        raise HTTPException(409, str(exc))
    except ValueError as exc:
        raise HTTPException(422, str(exc))


@router.get("/{identifier}/histogram")
def histogram(identifier: str, query: str = "", sort: Literal["class_name", "instance_count", "shallow_size_bytes"] = "shallow_size_bytes",
              descending: bool = True, group: Literal["class", "package"] = "class",
              offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=200)):
    return q.histogram(analysis(identifier), query, sort, descending, group, offset, limit)


@router.get("/{identifier}/histogram.csv")
def histogram_csv(identifier: str, query: str = "", group: Literal["class", "package"] = "class"):
    data = analysis(identifier)
    result = q.histogram(data, query=query, group=group, limit=10**9)
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["class_name", "instance_count", "shallow_size_bytes"])
    for row in result["rows"]:
        name = row["class_name"]
        # Spreadsheet formula injection is possible even through class names.
        if name.startswith(("=", "+", "-", "@", "\t", "\r")):
            name = "'" + name
        writer.writerow([name, row["instance_count"], row["shallow_size_bytes"]])
    return Response(output.getvalue(), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": 'attachment; filename="heap-histogram.csv"',
                             "X-Histogram-Complete": str(result["complete"]).lower()})


@router.get("/{identifier}/dominators")
def dominators(identifier: str, parent: str = "0x0", offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=200), group: Literal["object", "class", "loader"] = "object"):
    return run(q.dominators, index(identifier), parent, offset, limit, group)


class Selection(BaseModel):
    objects: list[str] = Field(min_length=1, max_length=200)
    view: Literal["histogram", "objects"] = "histogram"
    offset: int = Field(0, ge=0)
    limit: int = Field(50, ge=1, le=200)
    source_session: str | None = None


@router.post("/{identifier}/retained-set")
def retained_set(identifier: str, req: Selection):
    return run(q.retained_set, index(identifier), req.objects, req.offset, req.limit, req.view)


@router.post("/{identifier}/merged-paths")
def merged_paths(identifier: str, req: Selection):
    from .main import _resolve_source
    source = _resolve_source(req.source_session)
    build = (analysis(identifier).get("capture") or {}).get("build_id")
    matched = bool(source and source.provenance.get("manifest_valid") and build and build == source.provenance.get("build_id"))
    return run(q.merged_paths, index(identifier), req.objects, source, matched)


@router.get("/{identifier}/roots")
def roots(identifier: str, offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=200), kind: str = ""):
    return run(q.root_browser, index(identifier), offset, limit, kind)


@router.get("/{identifier}/unreachable")
def unreachable(identifier: str, offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=200)):
    return run(q.unreachable, index(identifier), offset, limit)


@router.get("/{identifier}/loaders")
def loaders(identifier: str, offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=200)):
    return run(q.loaders, index(identifier), offset, limit)


@router.get("/{identifier}/suspects")
def suspects(identifier: str, threshold: float = Query(10, ge=0, le=100), min_bytes: int = Query(1048576, ge=0), offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=200)):
    return run(q.suspects, index(identifier), threshold, min_bytes, offset, limit)


@router.get("/{identifier}/waste")
def waste(identifier: str, query: Literal["duplicate_arrays", "empty_arrays", "sparse_arrays", "constant_arrays", "duplicate_strings", "threadlocals", "references", "collections"] = "duplicate_arrays", offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=200)):
    return run(q.waste, index(identifier), query, offset, limit)


@router.get("/{identifier}/objects/{oid}/collection")
def collection(identifier: str, oid: str, offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=200)):
    return run(q.collection_entries, index(identifier), oid, offset, limit)


class Notes(BaseModel):
    text: str = Field("", max_length=20000)
    bookmarks: list[str] = Field(default_factory=list, max_length=100)


@router.put("/{identifier}/notes")
def notes(identifier: str, req: Notes):
    with artifacts.LOCK:
        data = analysis(identifier)
        data["investigation_notes"] = req.model_dump()
        artifacts.save(data, "heap")
    return req


@router.get("/{identifier}/diagnostics")
def diagnostics(identifier: str):
    data = analysis(identifier)
    keys = ("analysis_id", "engine", "input_format", "stages", "skipped_analyses", "sizing_model", "sizing_assumptions", "histogram_complete", "file_size_bytes", "analyzed_bytes", "object_index_id")
    return {k: data.get(k) for k in keys}
