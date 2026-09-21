"""Retention reports over the disk-backed strong-reference graph.

Graph sums are exact under the selected size model; JVM layout and reference policy
remain explicit assumptions. No external-tool byte parity is claimed.
"""

from __future__ import annotations
import os
from dataclasses import dataclass, field
from typing import List
from ..schemas import DominatorEntry, Finding, Severity


def dominator_max_bytes() -> int:
    """File-size ceiling for exact retained-size computation (see module docstring)."""
    if os.environ.get("HEAP_DOMINATOR", "1") in ("0", "", "false", "False"):
        return 0
    try:
        return int(os.environ.get("HEAP_DOMINATOR_MAX_BYTES", str(512 * 1024 * 1024)))
    except ValueError:
        return 512 * 1024 * 1024


@dataclass
class RetainedResult:
    entries: List[DominatorEntry] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    reachable_bytes: int = 0
    unreachable_count: int = 0
    unreachable_bytes: int = 0
    object_count: int = 0


def compute_retained(fp, top_n=25, model=None, index_path=None, source=None):
    """Compute graph retention with explicit root and reference-strength semantics."""
    import tempfile
    from pathlib import Path
    from .heap_index import build_index, retained, root_paths, object_detail

    def run(path):
        r = retained(path, top_n)
        entries = [DominatorEntry(**e) for e in r["entries"]]
        findings = []
        for e in entries[:3]:
            e.root_paths = root_paths(
                path, e.accumulation_object_id or e.object_id, max_nodes=5000
            )
            locations = []
            if source:
                from ..schemas import SourceLocation

                seen = set()
                for root_path in e.root_paths["paths"]:
                    for edge in root_path["edges"]:
                        field = edge["field"]
                        if field.startswith("static:"):
                            owner = object_detail(path, edge["src"], limit=1)
                            cls, name = (
                                (owner.get("name") if owner else None),
                                field[7:],
                            )
                        elif "." in field:
                            cls, name = field.rsplit(".", 1)
                        else:
                            continue
                        if not cls or (cls, name) in seen:
                            continue
                        seen.add((cls, name))
                        loc = source.find_field(cls, name)
                        if loc:
                            locations.append(
                                SourceLocation(
                                    class_name=cls,
                                    method="",
                                    line=loc["line"],
                                    repo_path=loc["repo_path"],
                                    snippet=loc["snippet"],
                                    is_user_code=True,
                                    role="retaining_field",
                                    resolution="declared_field",
                                )
                            )

            if e.retained_bytes < max(1 << 20, r["reachable_bytes"] * 0.2):
                continue
            findings.append(
                Finding(
                    severity=Severity.WARNING,
                    category="memory",
                    title=f"Leak suspect: `{e.class_name}` retains {_fmt_bytes(e.retained_bytes)} under the selected layout",
                    description="This is an ownership observation in the strong-reference graph, not evidence that the retained set grows without bound.",
                    confidence="medium",
                    conclusion="observation",
                    source_locations=locations,
                    evidence=[
                        f"object {e.object_id}",
                        f"retained bytes: {e.retained_bytes}",
                        " → ".join([e.class_name] + e.chain),
                    ]
                    + [
                        f"{edge['src']} --{edge['field']}--> {edge['dst']}"
                        for p in e.root_paths["paths"][:1]
                        for edge in p["edges"]
                    ],
                    limitations=[
                        "Shallow sizes use an assumed JVM object layout; class object shallow sizes are not modeled.",
                        "Reference.referent edges are excluded; inspect all-reference paths separately.",
                    ],
                    remediation="Inspect incoming references and root paths for this object, then compare compatible captures.",
                )
            )
        return RetainedResult(
            entries=entries,
            findings=findings,
            reachable_bytes=r["reachable_bytes"],
            unreachable_count=r["unreachable_count"],
            unreachable_bytes=r["unreachable_bytes"],
        )

    if index_path:
        return run(index_path)
    with tempfile.TemporaryDirectory(prefix="postmortem-dom-") as temp:
        path = Path(temp) / "graph.sqlite"
        build_index(fp, path, model=model)
        return run(path)


def _fmt_bytes(n: int) -> str:
    v = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(v) < 1024:
            return f"{v:.1f} {unit}" if unit != "B" else f"{int(v)} B"
        v /= 1024
    return f"{v:.1f} PB"
