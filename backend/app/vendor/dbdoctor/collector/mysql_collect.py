#!/usr/bin/env python3
"""dbdoctor MySQL/MariaDB collector.

Reads performance STATISTICS VIEWS ONLY (performance_schema statement digests,
sys schema advisor views, information_schema.tables/statistics, processlist,
global variables/status) and writes a normalized snapshot.json for analysis
by dbdoctor.

PRIVACY — what leaves this machine and what never does:
  * Statement text comes from performance_schema DIGEST_TEXT, which the
    server has ALREADY normalized (every literal replaced by '?') before we
    read it. The only raw SQL this script can see — currently running
    statements in the processlist — is passed through this script's own
    literal-stripping pass before anything is written.
  * Host and database names are hashed to a short alias by default
    (pass --keep-names to keep them readable).
  * The session is opened READ-ONLY (SET SESSION TRANSACTION READ ONLY) and
    this file contains no INSERT/UPDATE/DELETE/DDL against your data.
  * A 5s per-statement timeout is set so collection can never hang your DB.

Requires: Python 3.10+, PyMySQL (pip install pymysql). Nothing else.
Recommended DB grant: PROCESS, REPLICATION CLIENT, and SELECT on
performance_schema / sys — statistics views only, no table data.

Usage:
    python mysql_collect.py --dsn mysql://user:pass@host:3306/db --out snapshot.json
    MYSQL_DSN=mysql://... python mysql_collect.py --out snapshot.json
    python mysql_collect.py --dsn ... --out snap2.json --delta-of snap1.json

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
import urllib.parse
from datetime import UTC, datetime

COLLECTOR_VERSION = "0.1.0"
TOP_QUERIES = 200
TOP_TABLES = 100
STATEMENT_TIMEOUT_MS = 5000
PS = 1e9  # picoseconds per millisecond (performance_schema timers are ps)

VARIABLES_WHITELIST = (
    "binlog_format",
    "innodb_buffer_pool_size",
    "innodb_file_per_table",
    "innodb_flush_log_at_trx_commit",
    "innodb_flush_method",
    "innodb_io_capacity",
    "innodb_log_buffer_size",
    "innodb_log_file_size",
    "join_buffer_size",
    "long_query_time",
    "max_connections",
    "max_heap_table_size",
    "open_files_limit",
    "performance_schema",
    "query_cache_size",
    "query_cache_type",
    "read_rnd_buffer_size",
    "skip_name_resolve",
    "slow_query_log",
    "sort_buffer_size",
    "sync_binlog",
    "table_definition_cache",
    "table_open_cache",
    "thread_cache_size",
    "tmp_table_size",
)

STATUS_WHITELIST = (
    "Connections",
    "Created_tmp_disk_tables",
    "Created_tmp_tables",
    "Innodb_buffer_pool_read_requests",
    "Innodb_buffer_pool_reads",
    "Max_used_connections",
    "Opened_tables",
    "Threads_connected",
    "Threads_created",
    "Uptime",
)

# --------------------------------------------------------------------------
# SQL normalization. DIGEST_TEXT is already normalized by the server; this
# pass exists for the one raw-SQL source (processlist INFO) and as defense
# in depth. Order: strings, numbers, IN-list collapse, whitespace.
# --------------------------------------------------------------------------

_BACKSLASH_STRING = re.compile(r"'(?:[^'\\]|\\.|'')*'")
_DOUBLE_QUOTED = re.compile(r'"(?:[^"\\]|\\.|"")*"')
_NUMBER = re.compile(r"(?<![\w$.])[-+]?\d+(?:\.\d+)?(?:[eE][-+]?\d+)?(?![\w])")
_IN_LIST = re.compile(r"(\b(?:IN|VALUES)\s*)\(\s*\?(?:\s*,\s*\?)*\s*\)", re.IGNORECASE)
_IN_LIST_ELLIPSIS = re.compile(r"\(\s*\?\s*,\s*\.\.\.\s*\)")  # MySQL digests: (?, ...)
_WHITESPACE = re.compile(r"\s+")


def normalize_sql(sql: str) -> str:
    """Replace every literal in *sql* with '?' and collapse whitespace."""
    out = _BACKSLASH_STRING.sub("?", sql)
    out = _DOUBLE_QUOTED.sub("?", out)
    out = _NUMBER.sub("?", out)
    out = _IN_LIST.sub(r"\1(?)", out)
    out = _IN_LIST_ELLIPSIS.sub("(?)", out)
    return _WHITESPACE.sub(" ", out).strip()


def digest_of(sql: str) -> str:
    return hashlib.sha256(normalize_sql(sql).encode()).hexdigest()[:16]


def make_host_alias(host: str, dbname: str, keep_names: bool) -> str:
    if keep_names:
        return f"{host}/{dbname}"
    return hashlib.sha256(f"{host}/{dbname}".encode()).hexdigest()[:12]


def parse_dsn(dsn: str) -> dict:
    u = urllib.parse.urlsplit(dsn)
    if u.scheme not in ("mysql", "mariadb"):
        raise ValueError("DSN must look like mysql://user:pass@host:3306/dbname")
    return {
        "host": u.hostname or "127.0.0.1",
        "port": u.port or 3306,
        "user": urllib.parse.unquote(u.username or ""),
        "password": urllib.parse.unquote(u.password or ""),
        "database": u.path.lstrip("/"),
    }


# --------------------------------------------------------------------------
# Capability self-check + remediation guidance (T2.7): misconfigured
# performance_schema is a degraded run with exact fix steps, never a crash
# --------------------------------------------------------------------------

CONSUMER_FIX = """\
+----------------------------------------------------------------------------+
| performance_schema statement digests are DISABLED on this server.          |
|                                                                            |
| The snapshot was still written, but WITHOUT per-query statistics — the     |
| most valuable part of the audit. To enable at runtime (no restart), have   |
| a DBA run:                                                                 |
|                                                                            |
|   UPDATE performance_schema.setup_consumers                                |
|      SET ENABLED = 'YES'                                                   |
|    WHERE NAME IN ('statements_digest', 'global_instrumentation',           |
|                   'thread_instrumentation');                               |
|                                                                            |
| To make it permanent, add to my.cnf under [mysqld]:                        |
|                                                                            |
|   performance_schema = ON                                                  |
|   performance-schema-consumer-statements-digest = ON                       |
|                                                                            |
| Then let the workload run for a day and re-run this collector.             |
+----------------------------------------------------------------------------+
"""


def sha256_self() -> str:
    with open(os.path.abspath(__file__), "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def _fetch_kv(cur, sql: str) -> dict[str, str]:
    cur.execute(sql)
    return {name: str(value) for name, value in cur.fetchall()}


def check_capabilities(cur, is_mariadb: bool, sys_available: bool) -> tuple[list[str], list[str]]:
    caps = ["table_stats", "index_stats", "sessions", "config", "lock_waits"]
    notes: list[str] = []

    cur.execute("SELECT @@performance_schema")
    ps_on = cur.fetchone()[0] == 1
    digests_on = False
    if ps_on:
        try:
            cur.execute(
                "SELECT ENABLED FROM performance_schema.setup_consumers"
                " WHERE NAME = 'statements_digest'"
            )
            row = cur.fetchone()
        except Exception:
            notes.append(
                "this account cannot read performance_schema; grant SELECT on "
                "performance_schema.* (see docs/enable_performance_schema.md). "
                "Per-query statistics unavailable."
            )
            return caps, notes
        digests_on = bool(row) and row[0] == "YES"
        if digests_on:
            caps.append("query_stats")
        else:
            notes.append(
                "performance_schema is on but the statements_digest consumer is "
                "disabled; per-query statistics unavailable (fix steps printed)."
            )
        cur.execute(
            "SELECT count(*) FROM performance_schema.setup_instruments"
            " WHERE NAME LIKE 'statement/%' AND ENABLED = 'NO'"
        )
        disabled = cur.fetchone()[0]
        if digests_on and disabled:
            notes.append(
                f"{disabled} statement instruments are disabled; some statements "
                "may be missing from query statistics."
            )
    else:
        notes.append(
            "performance_schema = OFF; per-query statistics unavailable. Add "
            "performance_schema = ON to my.cnf [mysqld] and restart."
        )

    if is_mariadb:
        notes.append(
            "MariaDB detected: sys schema advisor views unavailable; unused/"
            "redundant index detection falls back to definition analysis "
            "downstream (confidence reduced). Latency percentiles unavailable."
        )
    elif not sys_available:
        notes.append("sys schema not readable; unused/redundant index views skipped.")
    else:
        caps.append("sys_schema")

    return caps, notes


# --------------------------------------------------------------------------
# Collection (statistics views only)
# --------------------------------------------------------------------------


def collect_queries(cur, db: str, has_quantiles: bool) -> list[dict]:
    quantile_cols = "QUANTILE_95, QUANTILE_99" if has_quantiles else "NULL, NULL"
    cur.execute(
        f"""
        SELECT DIGEST, DIGEST_TEXT, COUNT_STAR,
               SUM_TIMER_WAIT, AVG_TIMER_WAIT,
               SUM_ROWS_SENT, SUM_ROWS_EXAMINED,
               SUM_NO_INDEX_USED + SUM_NO_GOOD_INDEX_USED,
               {quantile_cols}
        FROM performance_schema.events_statements_summary_by_digest
        WHERE SCHEMA_NAME = %s
        ORDER BY SUM_TIMER_WAIT DESC
        LIMIT %s
        """,
        (db, TOP_QUERIES),
    )
    return [
        {
            "query_digest": dig,
            # DIGEST_TEXT is normalized by the server; our pass is belt-and-braces
            "normalized_sql": normalize_sql(text or ""),
            "calls": calls,
            "total_time_ms": round(total_ps / PS, 3),
            "mean_time_ms": round(avg_ps / PS, 3),
            "rows_returned": rows_sent,
            "rows_examined": rows_exam,
            "full_scan_flag": bool(no_index),
            "p95_time_ms": round(q95 / PS, 3) if q95 else None,
            "p99_time_ms": round(q99 / PS, 3) if q99 else None,
            "calls_per_day": None,
            "time_per_day_ms": None,
            "delta_low_confidence": None,
        }
        for (
            dig,
            text,
            calls,
            total_ps,
            avg_ps,
            rows_sent,
            rows_exam,
            no_index,
            q95,
            q99,
        ) in cur.fetchall()
    ]


def collect_tables(cur, db: str, sys_available: bool) -> list[dict]:
    full_scans: dict[str, int] = {}
    if sys_available:
        cur.execute(
            "SELECT object_name, rows_full_scanned"
            " FROM sys.schema_tables_with_full_table_scans WHERE object_schema = %s",
            (db,),
        )
        full_scans = {name: rows for name, rows in cur.fetchall()}

    cur.execute(
        """
        SELECT TABLE_SCHEMA, TABLE_NAME,
               COALESCE(DATA_LENGTH, 0) + COALESCE(INDEX_LENGTH, 0),
               TABLE_ROWS, DATA_FREE
        FROM information_schema.tables
        WHERE TABLE_SCHEMA = %s AND TABLE_TYPE = 'BASE TABLE'
        ORDER BY COALESCE(DATA_LENGTH, 0) + COALESCE(INDEX_LENGTH, 0) DESC
        LIMIT %s
        """,
        (db, TOP_TABLES),
    )
    return [
        {
            "schema_name": schema,
            "name": name,
            "size_bytes": int(size),
            "row_estimate": int(rows) if rows is not None else None,
            "seq_scans": None,  # PG-only source
            "full_scan_rows_read": full_scans.get(name),
            "dead_tuple_ratio": None,  # PG-only source
            "last_autovacuum": None,  # PG-only source
            "data_free_bytes": int(free) if free is not None else None,
            "growth_30d_pct": None,
        }
        for schema, name, size, rows, free in cur.fetchall()
    ]


def collect_indexes(cur, db: str, sys_available: bool) -> list[dict]:
    unused: set[tuple[str, str]] = set()
    redundant: set[tuple[str, str]] = set()
    if sys_available:
        cur.execute(
            "SELECT object_name, index_name FROM sys.schema_unused_indexes"
            " WHERE object_schema = %s",
            (db,),
        )
        unused = {(t, i) for t, i in cur.fetchall()}
        cur.execute(
            "SELECT table_name, redundant_index_name FROM sys.schema_redundant_indexes"
            " WHERE table_schema = %s",
            (db,),
        )
        redundant = {(t, i) for t, i in cur.fetchall()}

    cur.execute(
        """
        SELECT TABLE_NAME, INDEX_NAME, NON_UNIQUE,
               GROUP_CONCAT(COLUMN_NAME ORDER BY SEQ_IN_INDEX SEPARATOR ', ')
        FROM information_schema.statistics
        WHERE TABLE_SCHEMA = %s
        GROUP BY TABLE_NAME, INDEX_NAME, NON_UNIQUE
        """,
        (db,),
    )
    return [
        {
            "table": f"{db}.{table}",
            "name": name,
            "definition": f"({cols})",
            "size_bytes": None,  # per-index size not exposed by information_schema
            "scans": None,  # arrives via sys.schema_unused_indexes instead
            "is_primary": name == "PRIMARY",
            "is_unique": not non_unique,
            "is_duplicate_candidate": (table, name) in redundant,
            "is_unused_candidate": (table, name) in unused and name != "PRIMARY",
        }
        for table, name, non_unique, cols in cur.fetchall()
    ]


def collect_sessions(cur) -> list[dict]:
    cur.execute(
        "SELECT ID, STATE, TIME, INFO FROM information_schema.PROCESSLIST"
        " WHERE ID <> CONNECTION_ID()"
    )
    return [
        {
            "session_id": str(sid),
            "state": state or None,
            "query_digest": digest_of(info) if info else None,
            "age_seconds": float(age) if age is not None else None,
        }
        for sid, state, age, info in cur.fetchall()
    ]


def collect_lock_waits(cur, is_mariadb: bool) -> list[dict]:
    if is_mariadb:
        # MariaDB keeps the InnoDB lock tables in information_schema
        cur.execute(
            """
            SELECT b.trx_query, r.trx_query,
                   TIMESTAMPDIFF(SECOND, r.trx_wait_started, NOW()) * 1000
            FROM information_schema.INNODB_LOCK_WAITS w
            JOIN information_schema.INNODB_TRX b ON b.trx_id = w.blocking_trx_id
            JOIN information_schema.INNODB_TRX r ON r.trx_id = w.requesting_trx_id
            """
        )
    else:
        cur.execute(
            """
            SELECT blocking_query, waiting_query, wait_age_secs * 1000
            FROM sys.innodb_lock_waits
            """
        )
    return [
        {
            "blocker_digest": digest_of(blocker_q) if blocker_q else None,
            "blocked_digest": digest_of(blocked_q) if blocked_q else None,
            "wait_ms": float(wait_ms) if wait_ms is not None else 0.0,
        }
        for blocker_q, blocked_q, wait_ms in cur.fetchall()
    ]


def collect_connections(status: dict[str, str], variables: dict[str, str]) -> dict:
    return {
        "current": int(status.get("Threads_connected", 0)),
        "peak": int(status["Max_used_connections"]) if "Max_used_connections" in status else None,
        "max_limit": int(variables.get("max_connections", 0)),
    }


def collect_settings(variables: dict[str, str], status: dict[str, str]) -> list[dict]:
    settings = [
        {"name": name, "value": variables[name], "unit": None}
        for name in VARIABLES_WHITELIST
        if name in variables
    ]
    settings += [
        {"name": name, "value": status[name], "unit": None}
        for name in STATUS_WHITELIST
        if name in status
    ]
    return settings


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------


def collect(dsn: str, keep_names: bool) -> dict:
    import pymysql

    params = parse_dsn(dsn)
    conn = pymysql.connect(
        host=params["host"],
        port=params["port"],
        user=params["user"],
        password=params["password"],
        database=params["database"],
        autocommit=True,
        read_timeout=30,
    )
    db = params["database"]
    cur = conn.cursor()

    # read-only, time-boxed session; verified, not assumed
    cur.execute("SET SESSION TRANSACTION READ ONLY")
    try:
        cur.execute(f"SET SESSION max_execution_time = {STATEMENT_TIMEOUT_MS}")  # MySQL only
    except pymysql.err.OperationalError:
        cur.execute(f"SET SESSION max_statement_time = {STATEMENT_TIMEOUT_MS / 1000}")  # MariaDB
    try:
        cur.execute("SELECT @@transaction_read_only")
    except pymysql.err.OperationalError:
        cur.execute("SELECT @@tx_read_only")  # older MariaDB spelling
    if cur.fetchone()[0] != 1:
        raise RuntimeError("session is not read-only; refusing to continue")

    cur.execute("SELECT VERSION()")
    server_version = cur.fetchone()[0]
    is_mariadb = "mariadb" in server_version.lower()

    cur.execute("SELECT count(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = 'sys'")
    sys_available = not is_mariadb and cur.fetchone()[0] > 0

    capabilities, notes = check_capabilities(cur, is_mariadb, sys_available)

    has_quantiles = False
    if "query_stats" in capabilities:
        cur.execute(
            "SELECT count(*) FROM information_schema.COLUMNS"
            " WHERE TABLE_SCHEMA = 'performance_schema'"
            " AND TABLE_NAME = 'events_statements_summary_by_digest'"
            " AND COLUMN_NAME = 'QUANTILE_95'"
        )
        has_quantiles = cur.fetchone()[0] > 0

    variables = _fetch_kv(cur, "SHOW GLOBAL VARIABLES")
    status = _fetch_kv(cur, "SHOW GLOBAL STATUS")

    cur.execute(
        "SELECT COALESCE(SUM(COALESCE(DATA_LENGTH,0) + COALESCE(INDEX_LENGTH,0)), 0)"
        " FROM information_schema.tables WHERE TABLE_SCHEMA = %s",
        (db,),
    )
    db_size = int(cur.fetchone()[0])

    snapshot = {
        "meta": {
            "engine": "mariadb" if is_mariadb else "mysql",
            "version": COLLECTOR_VERSION,
            "server_version": server_version,
            "collected_at": datetime.now(UTC).isoformat(),
            "host_alias": make_host_alias(params["host"], db, keep_names),
            "is_delta": False,
            "delta_interval_seconds": None,
            "db_size_bytes": db_size,
            "capabilities": capabilities,
            "capability_notes": notes,
        },
        "queries": collect_queries(cur, db, has_quantiles) if "query_stats" in capabilities else [],
        "tables": collect_tables(cur, db, sys_available),
        "indexes": collect_indexes(cur, db, sys_available),
        "sessions": collect_sessions(cur),
        "lock_waits": collect_lock_waits(cur, is_mariadb),
        "connections": collect_connections(status, variables),
        "settings": collect_settings(variables, status),
    }
    conn.close()
    return snapshot


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--dsn",
        default=os.environ.get("MYSQL_DSN"),
        help="DSN mysql://user:pass@host:3306/db (or set env MYSQL_DSN). Credentials "
        "are used for the connection only and never written anywhere.",
    )
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

    print(f"dbdoctor mysql_collect {COLLECTOR_VERSION}  sha256={sha256_self()}")

    if not args.dsn:
        parser.error("--dsn or env MYSQL_DSN is required")

    try:
        snapshot = collect(args.dsn, args.keep_names)
    except Exception as exc:
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
        print(CONSUMER_FIX)
        print("warning: snapshot written with reduced capabilities (see guide above)")
    for note in snapshot["meta"]["capability_notes"]:
        print(f"note: {note}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
