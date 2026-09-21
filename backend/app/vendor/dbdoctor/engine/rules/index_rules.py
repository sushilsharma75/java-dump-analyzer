"""Index rules R-I1..R-I3 — the headline findings of every audit."""

from __future__ import annotations

import re

from app.vendor.dbdoctor.engine.models import Snapshot
from app.vendor.dbdoctor.engine.rules.base import (
    Finding,
    Rule,
    equality_filter_columns,
    fmt_bytes,
    register,
)
from app.vendor.dbdoctor.engine.thresholds import THRESHOLDS as T

STAGING_NOTE = "Test in staging first: measure the query with EXPLAIN before and after."


@register
class MissingIndexCandidate(Rule):
    id = "R-I1"
    title = "Table is scanned in full by frequent queries (missing index candidate)"
    category = "indexes"

    def evaluate(self, snapshot: Snapshot) -> list[Finding]:
        if snapshot.meta.engine == "postgres":
            return self._evaluate_pg(snapshot)
        return self._evaluate_mysql(snapshot)

    def _evaluate_pg(self, snapshot: Snapshot) -> list[Finding]:
        findings = []
        for t in snapshot.tables:
            if (t.seq_scans or 0) < T.i1_min_seq_scans:
                continue
            if t.size_bytes < T.i1_min_table_size_bytes:
                continue
            columns = self._filter_columns_for(snapshot, f"{t.schema_name}.{t.name}")
            if not columns:
                continue
            findings.append(
                self._make(snapshot, t.name, t.size_bytes, columns, seq_scans=t.seq_scans)
            )
        return findings

    def _evaluate_mysql(self, snapshot: Snapshot) -> list[Finding]:
        sizes = {f"{t.schema_name}.{t.name}".lower(): t.size_bytes for t in snapshot.tables}
        findings = []
        seen: set[str] = set()
        for q in snapshot.queries:
            if not q.full_scan_flag or q.calls < T.i1_min_calls:
                continue
            if not q.rows_examined or not q.normalized_sql.lower().startswith("select"):
                continue
            selectivity = q.rows_examined / max(q.rows_returned, 1)
            if selectivity < T.i1_scan_selectivity:
                continue
            table = _resolved_table(snapshot, q.normalized_sql)
            if not table or table in seen:
                continue
            size = sizes.get(table, 0)
            if size < T.i1_min_table_size_bytes:
                continue
            columns = equality_filter_columns(q.normalized_sql)
            if not columns:
                continue
            seen.add(table)
            findings.append(
                self._make(
                    snapshot,
                    table,
                    size,
                    columns,
                    calls=q.calls,
                    rows_examined_per_call=round(q.rows_examined / max(q.calls, 1)),
                    rows_returned_per_call=round(q.rows_returned / max(q.calls, 1), 1),
                )
            )
        return findings

    def _filter_columns_for(self, snapshot: Snapshot, table: str) -> list[str]:
        """Equality-filter columns used by top queries against *table*,
        excluding columns that already lead an existing index."""
        indexed_leading = set()
        for idx in snapshot.indexes:
            if idx.table.lower() != table.lower():
                continue
            cols = _safe_btree_columns(idx.definition)
            if cols:
                indexed_leading.add(cols[0])
        columns: list[str] = []
        for q in snapshot.queries:
            if _resolved_table(snapshot, q.normalized_sql) != table.lower():
                continue
            for col in equality_filter_columns(q.normalized_sql):
                if col not in indexed_leading and col not in columns:
                    columns.append(col)
        return columns

    def _make(self, snapshot, table, size, columns, **extra_evidence) -> Finding:
        col_list = ", ".join(columns)
        return self.finding(
            snapshot,
            severity="HIGH" if size >= T.i1_high_table_size_bytes else "MEDIUM",
            affected_object=table,
            evidence={"table_size": fmt_bytes(size), "candidate_columns": col_list}
            | {k: v for k, v in extra_evidence.items() if v is not None},
            suggested_action=(
                f"Observed scans and filters on {table} suggest investigating ({col_list}). "
                "A scan may be optimal; confirm index suitability with the actual plan. "
                + STAGING_NOTE
            ),
            confidence="medium",  # always: only a plan check can prove it (V1, T5.4)
            impact=float(size),
        )


@register
class UnusedIndex(Rule):
    id = "R-I2"
    title = "Index is never used but costs space and write time"
    category = "indexes"

    def evaluate(self, snapshot: Snapshot) -> list[Finding]:
        findings = []
        for idx in snapshot.indexes:
            if idx.is_primary or idx.is_unique:
                continue  # constraint indexes are never 'unused'
            if snapshot.meta.engine == "postgres":
                if idx.scans is None or idx.scans != 0 or (idx.size_bytes or 0) < T.i2_min_size_bytes:
                    continue
                size = idx.size_bytes or 0
                severity = "MEDIUM" if size >= T.i2_medium_size_bytes else "LOW"
                evidence = {
                    "scans_since_stats_reset": idx.scans or 0,
                    "index_size": fmt_bytes(size),
                }
                impact = float(size)
            else:
                if not idx.is_unused_candidate:
                    continue
                severity = "LOW"  # size unknown on MySQL; stays LOW
                evidence = {"source": "sys.schema_unused_indexes (since server start)"}
                impact = 0.0
            findings.append(
                self.finding(
                    snapshot,
                    severity=severity,
                    affected_object=f"{idx.table}.{idx.name}",
                    evidence=evidence | {"definition": idx.definition},
                    suggested_action=(
                        f"Index {idx.name} shows no reads but is maintained on every "
                        "write. Verify it is not needed by replicas, rare reports, or "
                        "seasonal jobs, then drop it. Keep the definition somewhere "
                        "so it can be recreated."
                    ),
                    confidence="medium",  # usage counters reset with the server
                    impact=impact,
                )
            )
        return findings


@register
class DuplicateIndex(Rule):
    id = "R-I3"
    title = "Redundant index duplicates another index's leading columns"
    category = "indexes"

    def evaluate(self, snapshot: Snapshot) -> list[Finding]:
        findings = []
        if snapshot.meta.engine == "postgres":
            duplicates = self._pg_duplicates(snapshot)
        else:
            duplicates = [
                (idx.table, idx.name, idx.definition, "sys.schema_redundant_indexes")
                for idx in snapshot.indexes
                if idx.is_duplicate_candidate and not idx.is_primary and not idx.is_unique
            ]
        for table, name, definition, dominant in duplicates:
            findings.append(
                self.finding(
                    snapshot,
                    severity="MEDIUM",
                    affected_object=f"{table}.{name}",
                    evidence={"redundant_index": definition, "covered_by": dominant},
                    suggested_action=(
                        f"Index {name} is covered by another index with the same leading "
                        "columns; this is a candidate overlap, not proof of redundancy. "
                        "Verify with usage stats over a full business cycle, then drop "
                        "the redundant one. " + STAGING_NOTE
                    ),
                    confidence="medium",
                    impact=1.0,
                )
            )
        return findings

    def _pg_duplicates(self, snapshot: Snapshot) -> list[tuple[str, str, str, str]]:
        """Leading-column-prefix overlap parsed from indexdef."""
        by_table: dict[str, list] = {}
        for idx in snapshot.indexes:
            cols = _safe_btree_columns(idx.definition)
            if cols:
                by_table.setdefault(idx.table, []).append((idx, cols))
        out = []
        for _table, entries in by_table.items():
            for idx_a, cols_a in entries:
                if idx_a.is_primary or idx_a.is_unique:
                    continue
                for idx_b, cols_b in entries:
                    if idx_a.name == idx_b.name:
                        continue
                    if cols_b[: len(cols_a)] != cols_a:
                        continue
                    # a is a prefix of (or equal to) b: a is redundant.
                    # On exact ties keep one deterministically; prefer
                    # dropping the non-unique one.
                    if cols_a == cols_b:
                        if idx_a.is_unique and not idx_b.is_unique:
                            continue
                        if idx_a.is_unique == idx_b.is_unique and idx_a.name < idx_b.name:
                            continue
                    out.append((idx_a.table, idx_a.name, idx_a.definition, idx_b.name))
                    break
        return out


_INDEXDEF_COLS = re.compile(r"\(([^)]*)\)")


def _index_columns(definition: str) -> list[str]:
    """Column list from a PG indexdef or the MySQL '(col1, col2)' form."""
    m = _INDEXDEF_COLS.search(definition)
    if not m:
        return []
    return [c.strip().strip('`"').split(" ")[0].lower() for c in m.group(1).split(",") if c.strip()]


def _safe_btree_columns(definition: str) -> list[str]:
    """Only plain complete btree definitions support prefix comparisons.

    Partial, expression, INCLUDE, ordering, collation and opclass differences
    require plan/catalog evidence that this snapshot contract cannot provide.
    """
    match = re.fullmatch(
        r'(?:CREATE\s+(?:UNIQUE\s+)?INDEX\s+\S+\s+ON\s+\S+\s+USING\s+btree\s*)?'
        r'\(\s*([a-zA-Z_][a-zA-Z_0-9]*(?:\s*,\s*[a-zA-Z_][a-zA-Z_0-9]*)*)\s*\)',
        definition.strip(), re.IGNORECASE,
    )
    return [c.strip() for c in match.group(1).split(',')] if match else []


def _resolved_table(snapshot: Snapshot, sql: str) -> str | None:
    """Conservative single-table attribution; ambiguous names do not bind."""
    if len(re.findall(r"\bFROM\b", sql, re.I)) != 1 or re.search(r"\bJOIN\b", sql, re.I):
        return None
    match = re.search(r"\bFROM\s+([\w`\".]+)(.*)", sql, re.I | re.S)
    if not match:
        return None
    before_where = re.split(r"\bWHERE\b", match.group(2), flags=re.I)[0]
    if ',' in before_where:
        return None
    name = match.group(1).replace('`', '').replace('"', '').lower()
    candidates = [f"{t.schema_name}.{t.name}".lower() for t in snapshot.tables
                  if name == f"{t.schema_name}.{t.name}".lower()
                  or ('.' not in name and name == t.name.lower())]
    return candidates[0] if len(candidates) == 1 else None
