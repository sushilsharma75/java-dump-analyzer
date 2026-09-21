#!/usr/bin/env python3
"""dbdoctor PostgreSQL collector.

Reads performance statistics and optional routine/schema metadata (pg_stat_statements, pg_stat_activity,
pg_stat_user_tables, pg_stat_user_indexes, pg_settings, pg_locks) and writes a
normalized snapshot.json for analysis by dbdoctor.

PRIVACY — what leaves this machine and what never does:
  * --include-procedures is OPT-IN: routine source retains original literals,
    comments and identifiers, which may contain secrets. Review before sharing.
    The SQL normalization guarantees below apply to query statistics only.
  * SQL text is normalized: every string and numeric literal is replaced
    with '?' BEFORE it is written to the output file. pg_stat_statements
    already stores normalized statements; this script adds a second,
    defense-in-depth stripping pass of its own. No table row data is collected.
  * Host and database names are hashed to a short alias by default
    (pass --keep-names to keep them readable).
  * The session is opened READ-ONLY (default_transaction_read_only=on) and
    this file contains no INSERT/UPDATE/DELETE/DDL statement to find.
  * A statement_timeout of 5s is set so collection can never hang your DB.

Requires: Python 3.10+, psycopg (pip install "psycopg[binary]"). Nothing else.
Recommended DB grant: an account with the pg_monitor role (statistics views
only, no table data).

Usage:
    python pg_collect.py --dsn postgresql://user:pass@host:5432/db --out snapshot.json
    PGDSN=postgresql://... python pg_collect.py --out snapshot.json
    python pg_collect.py --dsn ... --out snap2.json --delta-of snap1.json

Verify what you are executing: this script prints its own SHA256 at startup;
compare it with the published checksum.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import UTC, datetime

COLLECTOR_VERSION = "0.1.0"
TOP_QUERIES = 200
TOP_TABLES = 100
STATEMENT_TIMEOUT_MS = 5000

# Performance-relevant settings captured from pg_settings. Names + values only.
SETTINGS_WHITELIST = (
    "autovacuum",
    "autovacuum_analyze_scale_factor",
    "autovacuum_naptime",
    "autovacuum_vacuum_scale_factor",
    "checkpoint_completion_target",
    "checkpoint_timeout",
    "default_statistics_target",
    "effective_cache_size",
    "effective_io_concurrency",
    "fsync",
    "idle_in_transaction_session_timeout",
    "jit",
    "maintenance_work_mem",
    "max_connections",
    "max_wal_size",
    "min_wal_size",
    "random_page_cost",
    "seq_page_cost",
    "shared_buffers",
    "shared_preload_libraries",
    "statement_timeout",
    "synchronous_commit",
    "temp_buffers",
    "track_io_timing",
    "wal_buffers",
    "work_mem",
)

# --------------------------------------------------------------------------
# SQL normalization (defense in depth — pg_stat_statements is already
# normalized; raw pg_stat_activity text is not). Order matters: strings
# first, then numbers, then parameter markers, then IN-list collapse.
# --------------------------------------------------------------------------

_DOLLAR_QUOTED = re.compile(r"\$(?P<tag>[A-Za-z_]*)\$.*?\$(?P=tag)\$", re.DOTALL)
_ESCAPE_STRING = re.compile(r"[eE]'(?:[^'\\]|\\.|'')*'")
_SINGLE_QUOTED = re.compile(r"'(?:[^']|'')*'")
_NUMBER = re.compile(r"(?<![\w$.])[-+]?\d+(?:\.\d+)?(?:[eE][-+]?\d+)?(?![\w])")
_PARAM_MARKER = re.compile(r"\$\d+\b")
_IN_LIST = re.compile(r"(\b(?:IN|VALUES)\s*)\(\s*\?(?:\s*,\s*\?)*\s*\)", re.IGNORECASE)
_WHITESPACE = re.compile(r"\s+")


def normalize_sql(sql: str) -> str:
    """Replace every literal in *sql* with '?' and collapse whitespace.

    This runs on the customer machine so that no literal value (which may
    contain names, emails, tokens...) ever reaches the snapshot file.
    """
    out = _DOLLAR_QUOTED.sub("?", sql)
    out = _ESCAPE_STRING.sub("?", out)
    out = _SINGLE_QUOTED.sub("?", out)
    out = _NUMBER.sub("?", out)
    out = _PARAM_MARKER.sub("?", out)
    out = _IN_LIST.sub(r"\1(?)", out)
    return _WHITESPACE.sub(" ", out).strip()


def digest_of(sql: str) -> str:
    """Stable 16-hex-char digest of a normalized statement."""
    return hashlib.sha256(normalize_sql(sql).encode()).hexdigest()[:16]


def make_host_alias(host: str, dbname: str, keep_names: bool) -> str:
    if keep_names:
        return f"{host}/{dbname}"
    return hashlib.sha256(f"{host}/{dbname}".encode()).hexdigest()[:12]


# --------------------------------------------------------------------------
# Collection queries (statistics views only)
# --------------------------------------------------------------------------


def collect_queries(cur) -> list[dict]:
    cur.execute(
        """
        SELECT queryid::text, query, calls, total_exec_time, mean_exec_time, rows
        FROM pg_stat_statements
        WHERE dbid = (SELECT oid FROM pg_database WHERE datname = current_database())
        ORDER BY total_exec_time DESC
        LIMIT %s
        """,
        (TOP_QUERIES,),
    )
    return [
        {
            "query_digest": queryid,
            "normalized_sql": normalize_sql(query),
            "calls": calls,
            "total_time_ms": round(total_ms, 3),
            "mean_time_ms": round(mean_ms, 3),
            "rows_returned": rows,
            "rows_examined": None,  # not tracked by PostgreSQL
            "full_scan_flag": None,  # not tracked per-statement by PostgreSQL
            "p95_time_ms": None,
            "p99_time_ms": None,
            "calls_per_day": None,
            "time_per_day_ms": None,
            "delta_low_confidence": None,
        }
        for queryid, query, calls, total_ms, mean_ms, rows in cur.fetchall()
    ]


def collect_tables(cur) -> list[dict]:
    cur.execute(
        """
        SELECT schemaname, relname,
               pg_total_relation_size(relid),
               n_live_tup, seq_scan, n_dead_tup, last_autovacuum
        FROM pg_stat_user_tables
        ORDER BY pg_total_relation_size(relid) DESC
        LIMIT %s
        """,
        (TOP_TABLES,),
    )
    tables = []
    for schema, name, size, live, seq, dead, last_av in cur.fetchall():
        tuples = (live or 0) + (dead or 0)
        tables.append(
            {
                "schema_name": schema,
                "name": name,
                "size_bytes": size,
                "row_estimate": live,
                "seq_scans": seq,
                "full_scan_rows_read": None,  # MySQL-only source
                "dead_tuple_ratio": round(dead / tuples, 4) if tuples else None,
                "last_autovacuum": last_av.isoformat() if last_av else None,
                "data_free_bytes": None,  # MySQL-only source
                "growth_30d_pct": None,
            }
        )
    return tables


def collect_indexes(cur) -> list[dict]:
    cur.execute(
        """
        SELECT ui.schemaname || '.' || ui.relname,
               ui.indexrelname,
               pg_get_indexdef(ui.indexrelid),
               pg_relation_size(ui.indexrelid),
               ui.idx_scan,
               ix.indisprimary, ix.indisunique
        FROM pg_stat_user_indexes ui
        JOIN pg_index ix ON ix.indexrelid = ui.indexrelid
        ORDER BY pg_relation_size(ui.indexrelid) DESC
        LIMIT 500
        """
    )
    return [
        {
            "table": table,
            "name": name,
            "definition": definition,
            "size_bytes": size,
            "scans": scans,
            "is_primary": is_pk,
            "is_unique": is_uq,
            "is_duplicate_candidate": False,  # PG: computed downstream from definitions
            "is_unused_candidate": (scans or 0) == 0 and not is_pk,
        }
        for table, name, definition, size, scans, is_pk, is_uq in cur.fetchall()
    ]


def collect_sessions(cur) -> list[dict]:
    cur.execute(
        """
        SELECT pid, state, query,
               extract(epoch FROM clock_timestamp() - COALESCE(xact_start, query_start))
        FROM pg_stat_activity
        WHERE datname = current_database() AND pid <> pg_backend_pid()
        """
    )
    return [
        {
            "session_id": str(pid),
            "state": state,
            "query_digest": digest_of(query) if query else None,
            # extract(epoch ...) arrives as Decimal; snapshots are plain JSON floats
            "age_seconds": round(float(age), 3) if age is not None else None,
        }
        for pid, state, query, age in cur.fetchall()
    ]


def collect_lock_waits(cur) -> list[dict]:
    cur.execute(
        """
        SELECT w.query, b.query,
               extract(epoch FROM clock_timestamp() - w.query_start) * 1000
        FROM pg_stat_activity w
        JOIN LATERAL unnest(pg_blocking_pids(w.pid)) AS blocking(pid) ON true
        JOIN pg_stat_activity b ON b.pid = blocking.pid
        WHERE w.datname = current_database()
        """
    )
    return [
        {
            "blocker_digest": digest_of(blocker_q) if blocker_q else None,
            "blocked_digest": digest_of(blocked_q) if blocked_q else None,
            "wait_ms": round(float(wait_ms), 1) if wait_ms is not None else 0.0,
        }
        for blocked_q, blocker_q, wait_ms in cur.fetchall()
    ]


def collect_connections(cur) -> dict:
    cur.execute(
        """
        SELECT (SELECT count(*) FROM pg_stat_activity),
               current_setting('max_connections')::int
        """
    )
    current, max_limit = cur.fetchone()
    return {"current": current, "peak": None, "max_limit": max_limit}


def collect_settings(cur) -> list[dict]:
    cur.execute(
        "SELECT name, setting, unit FROM pg_settings WHERE name = ANY(%s) ORDER BY name",
        (list(SETTINGS_WHITELIST),),
    )
    return [{"name": n, "value": v, "unit": u} for n, v, u in cur.fetchall()]


# --------------------------------------------------------------------------
# Capability self-check + enablement guidance (missing extension is a
# degraded run, never a crash)
# --------------------------------------------------------------------------

ENABLEMENT_GUIDE = """\
+----------------------------------------------------------------------------+
| pg_stat_statements is not enabled on this database.                        |
|                                                                            |
| The snapshot was still written, but WITHOUT per-query statistics — the     |
| most valuable part of the audit. Enabling it takes a few minutes and one   |
| restart, and is safe for production (it ships with PostgreSQL):            |
|                                                                            |
| Amazon RDS / Aurora:                                                       |
|   1. In the DB parameter group set:                                        |
|        shared_preload_libraries = 'pg_stat_statements'                     |
|   2. Reboot the instance, then run once in your database:                  |
|        CREATE EXTENSION pg_stat_statements;                                |
|                                                                            |
| Google Cloud SQL:                                                          |
|   1. gcloud sql instances patch <instance> \\                              |
|        --database-flags=shared_preload_libraries=pg_stat_statements        |
|   2. After the restart:  CREATE EXTENSION pg_stat_statements;              |
|                                                                            |
| Self-hosted:                                                               |
|   1. postgresql.conf:  shared_preload_libraries = 'pg_stat_statements'     |
|   2. Restart PostgreSQL, then:  CREATE EXTENSION pg_stat_statements;       |
|                                                                            |
| Then let the workload run for a day and re-run this collector.             |
+----------------------------------------------------------------------------+
"""


def check_capabilities(cur) -> tuple[list[str], list[str]]:
    """Return (capabilities, notes) for what this server can actually provide."""
    caps = ["table_stats", "index_stats", "lock_waits", "sessions", "config"]
    notes: list[str] = []

    cur.execute("SELECT count(*) FROM pg_extension WHERE extname = 'pg_stat_statements'")
    if cur.fetchone()[0]:
        try:
            cur.execute("SELECT 1 FROM pg_stat_statements LIMIT 1")
            cur.fetchall()
            caps.append("query_stats")
        except Exception:
            notes.append(
                "pg_stat_statements extension exists but is not readable by this "
                "account; grant the pg_monitor role."
            )
    else:
        notes.append("pg_stat_statements not installed; per-query statistics unavailable.")

    cur.execute("SELECT current_setting('track_io_timing')")
    if cur.fetchone()[0] == "on":
        caps.append("io_timing")
    else:
        notes.append("track_io_timing is off; I/O timing evidence unavailable (optional).")
    return caps, notes


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------


def collect_procedures(cur, notes, db=None):
    """Opt-in source capture: bodies retain literals; never run routine SQL."""
    cur.execute("""
        SELECT n.nspname, p.proname, p.proname || '_' || p.oid,
               p.oid::regprocedure::text, l.lanname, p.prosrc
        FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
        JOIN pg_language l ON l.oid = p.prolang
        WHERE p.prokind IN ('p', 'f') AND n.nspname NOT IN ('pg_catalog', 'information_schema')
          AND n.nspname NOT LIKE 'pg_toast%%'
        ORDER BY n.nspname, p.proname, p.oid LIMIT 1001
    """)
    rows = cur.fetchall()
    cur.execute("""
        SELECT specific_schema, specific_name, parameter_name, udt_name
        FROM information_schema.parameters
        WHERE specific_schema NOT IN ('pg_catalog', 'information_schema')
          AND parameter_name IS NOT NULL ORDER BY specific_schema, specific_name, ordinal_position
        LIMIT 20001
    """)
    parameters = cur.fetchall()
    cur.execute("""
        SELECT n.nspname, c.relname, a.attname, format_type(a.atttypid, a.atttypmod)
        FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE a.attnum > 0 AND NOT a.attisdropped AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
          AND n.nspname NOT IN ('pg_catalog', 'information_schema')
          AND n.nspname NOT LIKE 'pg_toast%%'
        ORDER BY n.nspname, c.relname, a.attnum LIMIT 20001
    """)
    column_rows = cur.fetchall()
    if len(rows) > 1000 or len(parameters) > 20000 or len(column_rows) > 20000:
        notes.append("Procedure/column collection was truncated by record limits; coverage is partial.")
    params = {}
    for schema, specific, name, dtype in parameters[:20000]:
        params.setdefault((schema, specific), []).append({"name": name, "data_type": dtype})
    procedures = []
    for schema, name, specific, identity, language, definition in rows[:1000]:
        if definition and len(definition) > 200000:
            definition = None
            notes.append("A procedure body exceeded 200000 characters and was omitted.")
        if not definition:
            notes.append("A procedure definition is unavailable; check source visibility/permissions.")
        routine_params = params.get((schema, specific), [])
        if len(routine_params) > 1000:
            routine_params = []
            notes.append("Procedure parameters omitted because the parameter limit was exceeded.")
        procedures.append(dict(schema_name=schema, name=name, identity=identity,
                               language=language, definition=definition, parameters=routine_params))
    notes.append("Procedure source is opt-in and retains literals/comments; review for secrets before sharing. Catalog visibility may hide routines or columns.")
    return {"procedures": procedures, "columns": [
        dict(schema_name=schema, table=table, name=name, data_type=dtype)
        for schema, table, name, dtype in column_rows[:20000]
    ]}


def collect(dsn: str, keep_names: bool, include_procedures: bool = False) -> dict:
    import psycopg

    conn = psycopg.connect(
        dsn,
        autocommit=True,
        application_name="dbdoctor_collector",
        options=f"-c default_transaction_read_only=on -c statement_timeout={STATEMENT_TIMEOUT_MS}",
    )
    with conn, conn.cursor() as cur:
        # belt and braces: verify the session really is read-only
        cur.execute("SHOW default_transaction_read_only")
        if cur.fetchone()[0] != "on":
            raise RuntimeError("session is not read-only; refusing to continue")

        capabilities, notes = check_capabilities(cur)

        cur.execute(
            "SELECT current_setting('server_version'), current_database(),"
            " inet_server_addr()::text, pg_database_size(current_database())"
        )
        server_version, dbname, host_addr, db_size = cur.fetchone()

        snapshot = {
            "meta": {
                "engine": "postgres",
                "version": COLLECTOR_VERSION,
                "server_version": server_version,
                "collected_at": datetime.now(UTC).isoformat(),
                "host_alias": make_host_alias(host_addr or "local", dbname, keep_names),
                "is_delta": False,
                "delta_interval_seconds": None,
                "db_size_bytes": db_size,
                "capabilities": capabilities,
                "capability_notes": notes,
            },
            "queries": collect_queries(cur) if "query_stats" in capabilities else [],
            "tables": collect_tables(cur),
            "indexes": collect_indexes(cur),
            "sessions": collect_sessions(cur),
            "lock_waits": collect_lock_waits(cur),
            "connections": collect_connections(cur),
            "settings": collect_settings(cur),
        }
        if include_procedures:
            try:
                snapshot.update(collect_procedures(cur, notes))
                capabilities.extend(["procedure_source", "column_types"])
            except Exception:
                notes.append("Procedure/column collection failed; source analysis is unavailable. Check catalog permissions and server support.")
    conn.close()
    return snapshot


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--dsn",
        default=os.environ.get("PGDSN"),
        help="PostgreSQL DSN (or set env PGDSN). Credentials are used for the "
        "connection only and never written anywhere.",
    )
    parser.add_argument("--include-procedures", action="store_true", help="include routine bodies and column types; source may contain sensitive literals")
    parser.add_argument("--out", default="snapshot.json", help="output file path")
    parser.add_argument(
        "--delta-of",
        metavar="PREV.json",
        help="previous snapshot to diff against (adds growth/rate fields)",
    )
    parser.add_argument(
        "--keep-names",
        action="store_true",
        help="keep readable host/db names instead of hashing them to an alias",
    )
    args = parser.parse_args(argv)

    with open(os.path.abspath(__file__), "rb") as f:
        self_hash = hashlib.sha256(f.read()).hexdigest()
    print(f"dbdoctor pg_collect {COLLECTOR_VERSION}  sha256={self_hash}")

    if not args.dsn:
        parser.error("--dsn or env PGDSN is required")

    try:
        snapshot = collect(args.dsn, args.keep_names, args.include_procedures)
    except Exception as exc:  # connection/permission problems: fail with a clear message
        print(f"error: collection failed: {exc}", file=sys.stderr)
        return 1

    if args.delta_of:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        try:
            from delta import apply_delta
        except ImportError:
            print("error: --delta-of requires delta.py next to this script", file=sys.stderr)
            return 1
        with open(args.delta_of, encoding="utf-8") as f:
            snapshot = apply_delta(snapshot, json.load(f))

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(snapshot, f, indent=2)
        f.write("\n")

    caps = snapshot["meta"]["capabilities"]
    n_q, n_t = len(snapshot["queries"]), len(snapshot["tables"])
    print(f"wrote {args.out}  (queries={n_q}, tables={n_t}, capabilities={','.join(caps)})")
    if "query_stats" not in caps:
        print()
        print(ENABLEMENT_GUIDE)
        print("warning: snapshot written with reduced capabilities (see guide above)")
    for note in snapshot["meta"]["capability_notes"]:
        print(f"note: {note}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
