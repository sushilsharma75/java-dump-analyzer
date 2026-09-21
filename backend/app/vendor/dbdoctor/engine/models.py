"""The normalized Snapshot schema — the system's central contract.

Both collectors (pg_collect.py, mysql_collect.py) emit JSON conforming to
``Snapshot``. Everything downstream (rules, scoring, AI, reports, storage) is
engine-agnostic and consumes only this schema. Fields not available on one
engine are nullable; rules declare which fields they require and skip
gracefully.

Every field's ``description`` states which PostgreSQL view and MySQL table it
maps from. Export the JSON schema with ``export_json_schema()`` or
``python -m engine.models``.
"""

from __future__ import annotations

import json
import math
from datetime import datetime
from typing import Literal

from pydantic import BaseModel as PydanticBaseModel, Field, ConfigDict, model_validator

class BaseModel(PydanticBaseModel):
    model_config = ConfigDict(allow_inf_nan=False)

    @model_validator(mode="after")
    def validate_measurements(self):
        for name, value in self.__dict__.items():
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                if name != "growth_30d_pct" and value < 0:
                    raise ValueError(f"{name} must be nonnegative")
        if hasattr(self, "dead_tuple_ratio") and self.dead_tuple_ratio is not None:
            if self.dead_tuple_ratio > 1:
                raise ValueError("dead_tuple_ratio must be between zero and one")
        if self.__class__.__name__ == "ConfigSetting":
            try:
                numeric = float(self.value)
            except ValueError:
                pass
            else:
                if not math.isfinite(numeric):
                    raise ValueError("Setting must not be a nonfinite number")
        return self


EngineName = Literal["postgres", "mysql", "mariadb"]


class SnapshotMeta(BaseModel):
    """Provenance and capability information for one collection run."""

    engine: EngineName = Field(
        description="Source engine. PG: 'postgres'. MySQL: 'mysql' or 'mariadb' (detected from version string)."
    )
    version: str = Field(
        description="Collector script version that produced this snapshot. Both engines: embedded constant in the collector."
    )
    server_version: str | None = Field(
        default=None,
        description="Database server version. PG: SHOW server_version. MySQL: SELECT VERSION().",
    )
    collected_at: datetime = Field(
        description="UTC timestamp of collection. Both engines: collector clock at run start."
    )
    host_alias: str = Field(
        description="Hashed host/dbname identifier (sha256 prefix) unless --keep-names. Both engines: derived from DSN, never the raw hostname by default."
    )
    is_delta: bool = Field(
        default=False,
        description="True when counters were diffed against a previous snapshot (--delta-of). Both engines: set by collector/delta.py.",
    )
    delta_interval_seconds: float | None = Field(
        default=None,
        description="Seconds between the two snapshots when is_delta. Both engines: difference of collected_at values.",
    )
    db_size_bytes: int | None = Field(
        default=None,
        description="Total database size. PG: pg_database_size(current_database()). MySQL: SUM(data_length+index_length) FROM information_schema.tables.",
    )
    capabilities: list[str] = Field(
        default_factory=list,
        description="Data sources actually available on this run (e.g. 'query_stats', 'io_timing', 'lock_waits'). Both engines: collector self-check; rules skip when a required capability is absent.",
    )
    capability_notes: list[str] = Field(
        default_factory=list,
        description="Human-readable notes on degraded capabilities (e.g. MariaDB fallbacks, disabled consumers). Both engines: collector self-check.",
    )


class QueryStat(BaseModel):
    """One normalized statement's cumulative statistics."""

    query_digest: str = Field(
        description="Stable identifier of the normalized statement. PG: pg_stat_statements.queryid (text). MySQL: events_statements_summary_by_digest.DIGEST."
    )
    normalized_sql: str = Field(
        description="Statement text with all literals stripped. PG: pg_stat_statements.query plus a defense-in-depth regex pass. MySQL: DIGEST_TEXT (pre-normalized by the server)."
    )
    calls: int = Field(
        description="Cumulative execution count. PG: pg_stat_statements.calls. MySQL: COUNT_STAR."
    )
    total_time_ms: float = Field(
        description="Cumulative execution time in ms. PG: pg_stat_statements.total_exec_time. MySQL: SUM_TIMER_WAIT / 1e9."
    )
    mean_time_ms: float = Field(
        description="Mean execution time in ms. PG: pg_stat_statements.mean_exec_time. MySQL: AVG_TIMER_WAIT / 1e9."
    )
    rows_returned: int = Field(
        description="Cumulative rows sent to the client. PG: pg_stat_statements.rows. MySQL: SUM_ROWS_SENT."
    )
    rows_examined: int | None = Field(
        default=None,
        description="Cumulative rows read while executing. PG: not available (null). MySQL: SUM_ROWS_EXAMINED.",
    )
    full_scan_flag: bool | None = Field(
        default=None,
        description="Statement used a full scan. PG: not available (null). MySQL: SUM_NO_INDEX_USED + SUM_NO_GOOD_INDEX_USED > 0.",
    )
    p95_time_ms: float | None = Field(
        default=None,
        description="95th percentile latency in ms. PG: not available (null). MySQL 8: QUANTILE_95 / 1e9.",
    )
    p99_time_ms: float | None = Field(
        default=None,
        description="99th percentile latency in ms. PG: not available (null). MySQL 8: QUANTILE_99 / 1e9.",
    )
    calls_per_day: float | None = Field(
        default=None,
        description="Call rate extrapolated from a two-snapshot diff. Both engines: computed by collector/delta.py, null on single snapshots.",
    )
    time_per_day_ms: float | None = Field(
        default=None,
        description="Execution-time rate extrapolated from a two-snapshot diff. Both engines: computed by collector/delta.py, null on single snapshots.",
    )
    delta_low_confidence: bool | None = Field(
        default=None,
        description="True when a counter reset was detected while diffing. Both engines: collector/delta.py.",
    )


class TableStat(BaseModel):
    """One user table's size and access statistics."""

    schema_name: str = Field(
        description="Schema/database the table lives in. PG: pg_stat_user_tables.schemaname. MySQL: information_schema.tables.TABLE_SCHEMA."
    )
    name: str = Field(
        description="Table name. PG: pg_stat_user_tables.relname. MySQL: information_schema.tables.TABLE_NAME."
    )
    size_bytes: int = Field(
        description="Total on-disk size incl. indexes. PG: pg_total_relation_size(relid). MySQL: data_length + index_length."
    )
    row_estimate: int | None = Field(
        default=None,
        description="Approximate live row count. PG: pg_stat_user_tables.n_live_tup. MySQL: information_schema.tables.TABLE_ROWS.",
    )
    seq_scans: int | None = Field(
        default=None,
        description="Cumulative full-table scans. PG: pg_stat_user_tables.seq_scan. MySQL: null (full scans surface per-statement via sys.schema_tables_with_full_table_scans / full_scan_flag).",
    )
    full_scan_rows_read: int | None = Field(
        default=None,
        description="Rows read via full scans. PG: null. MySQL: sys.schema_tables_with_full_table_scans.rows_full_scanned.",
    )
    dead_tuple_ratio: float | None = Field(
        default=None,
        description="Dead tuples / (live + dead), 0..1. PG: pg_stat_user_tables.n_dead_tup vs n_live_tup. MySQL: null (see data_free_bytes for fragmentation).",
    )
    last_autovacuum: datetime | None = Field(
        default=None,
        description="Last autovacuum time. PG: pg_stat_user_tables.last_autovacuum. MySQL: null.",
    )
    data_free_bytes: int | None = Field(
        default=None,
        description="Reclaimable/fragmented space. PG: null (bloat is estimated from dead tuples). MySQL: information_schema.tables.DATA_FREE.",
    )
    growth_30d_pct: float | None = Field(
        default=None,
        description="30-day size growth percentage extrapolated from a two-snapshot diff. Both engines: computed by collector/delta.py, null on single snapshots.",
    )


class IndexStat(BaseModel):
    """One index's definition and usage statistics."""

    table: str = Field(
        description="Qualified table the index belongs to (schema.table). PG: pg_stat_user_indexes. MySQL: information_schema.statistics / sys schema views."
    )
    name: str = Field(
        description="Index name. PG: pg_stat_user_indexes.indexrelname. MySQL: INDEX_NAME."
    )
    definition: str = Field(
        description="Index definition or column list. PG: pg_indexes.indexdef. MySQL: column list reconstructed from information_schema.statistics."
    )
    size_bytes: int | None = Field(
        default=None,
        description="On-disk index size. PG: pg_relation_size(indexrelid). MySQL: null (per-index size needs innodb_index_stats, not always readable).",
    )
    scans: int | None = Field(
        default=None,
        description="Cumulative index scans. PG: pg_stat_user_indexes.idx_scan. MySQL: null; unused indexes arrive via sys.schema_unused_indexes (is_unused_candidate).",
    )
    is_primary: bool = Field(
        default=False,
        description="Index backs the primary key. PG: pg_index.indisprimary. MySQL: INDEX_NAME = 'PRIMARY'.",
    )
    is_unique: bool = Field(
        default=False,
        description="Unique index/constraint. PG: pg_index.indisunique. MySQL: NON_UNIQUE = 0.",
    )
    is_duplicate_candidate: bool = Field(
        default=False,
        description="Flagged as redundant. PG: leading-column-prefix overlap parsed from indexdef. MySQL: sys.schema_redundant_indexes.",
    )
    is_unused_candidate: bool = Field(
        default=False,
        description="Flagged as unused. PG: idx_scan = 0 (rules add size/PK filters). MySQL: sys.schema_unused_indexes.",
    )


class SessionInfo(BaseModel):
    """One active/idle database session at collection time."""

    session_id: str = Field(
        description="Backend/thread identifier. PG: pg_stat_activity.pid. MySQL: performance_schema.threads.PROCESSLIST_ID."
    )
    state: str | None = Field(
        default=None,
        description="Session state. PG: pg_stat_activity.state. MySQL: PROCESSLIST_STATE / COMMAND.",
    )
    query_digest: str | None = Field(
        default=None,
        description="Digest of the running/last statement (never raw SQL). PG: hashed normalized pg_stat_activity.query. MySQL: events_statements_current DIGEST.",
    )
    age_seconds: float | None = Field(
        default=None,
        description="Seconds since the transaction/query started. PG: clock_timestamp() - xact_start/query_start. MySQL: PROCESSLIST_TIME.",
    )


class LockWait(BaseModel):
    """One observed blocked/blocking session pair at collection time."""

    blocker_digest: str | None = Field(
        default=None,
        description="Digest of the blocking session's statement (never raw SQL). PG: pg_blocking_pids() joined to pg_stat_activity, query hashed. MySQL: sys.innodb_lock_waits.blocking_query digested.",
    )
    blocked_digest: str | None = Field(
        default=None,
        description="Digest of the waiting session's statement. PG: pg_stat_activity of the blocked pid, query hashed. MySQL: sys.innodb_lock_waits.waiting_query digested.",
    )
    wait_ms: float = Field(
        description="How long the waiter has been blocked, ms. PG: clock_timestamp() - waiting backend's query_start. MySQL: sys.innodb_lock_waits.wait_age (converted)."
    )


class ConnectionInfo(BaseModel):
    """Connection headroom at collection time."""

    current: int = Field(
        description="Connections open now. PG: count(*) FROM pg_stat_activity. MySQL: GLOBAL STATUS Threads_connected."
    )
    peak: int | None = Field(
        default=None,
        description="Peak connections since server start. PG: not tracked (null). MySQL: GLOBAL STATUS Max_used_connections.",
    )
    max_limit: int = Field(
        description="Configured connection ceiling. PG: SHOW max_connections. MySQL: GLOBAL VARIABLES max_connections."
    )


class ConfigSetting(BaseModel):
    """One whitelisted, performance-relevant server setting."""

    name: str = Field(
        description="Setting name. PG: pg_settings.name (whitelist ~25). MySQL: SHOW GLOBAL VARIABLES / GLOBAL STATUS names (whitelist ~25)."
    )
    value: str = Field(
        description="Current value as text. PG: pg_settings.setting. MySQL: variable/status value."
    )
    unit: str | None = Field(
        default=None,
        description="Value unit when known. PG: pg_settings.unit (e.g. 8kB, ms). MySQL: null (values already absolute).",
    )


class ColumnDefinition(BaseModel):
    schema_name: str
    table: str
    name: str
    data_type: str = Field(min_length=1, max_length=256)


class RoutineParameter(BaseModel):
    name: str
    data_type: str = Field(min_length=1, max_length=256)


class StoredProcedure(BaseModel):
    schema_name: str
    name: str
    identity: str | None = None
    language: str = "sql"
    definition: str | None = Field(default=None, max_length=200000)
    parameters: list[RoutineParameter] = Field(default_factory=list, max_length=1000)


class Snapshot(BaseModel):
    """Root document: one normalized collection run from one database."""

    procedures: list[StoredProcedure] = Field(default_factory=list, max_length=1000)
    columns: list[ColumnDefinition] = Field(default_factory=list, max_length=20000)
    meta: SnapshotMeta = Field(description="Provenance + capabilities. Both engines.")
    queries: list[QueryStat] = Field(
        default_factory=list, max_length=1000,
        description="Top statements by total time (max 200). PG: pg_stat_statements. MySQL: events_statements_summary_by_digest.",
    )
    tables: list[TableStat] = Field(
        default_factory=list, max_length=1000,
        description="Top relations by size (max 100). PG: pg_stat_user_tables + pg_total_relation_size. MySQL: information_schema.tables + sys full-scan views.",
    )
    indexes: list[IndexStat] = Field(
        default_factory=list, max_length=5000,
        description="Indexes of the captured tables. PG: pg_stat_user_indexes + pg_indexes. MySQL: information_schema.statistics + sys unused/redundant views.",
    )
    sessions: list[SessionInfo] = Field(
        default_factory=list, max_length=10000,
        description="Sessions at collection time. PG: pg_stat_activity. MySQL: performance_schema.threads/processlist.",
    )
    lock_waits: list[LockWait] = Field(
        default_factory=list, max_length=10000,
        description="Blocked/blocking pairs at collection time. PG: pg_locks + pg_blocking_pids. MySQL: sys.innodb_lock_waits.",
    )
    connections: ConnectionInfo | None = Field(
        default=None,
        description="Connection headroom. PG: pg_stat_activity vs max_connections. MySQL: status vars vs max_connections.",
    )
    settings: list[ConfigSetting] = Field(
        default_factory=list, max_length=1000,
        description="Whitelisted perf-relevant settings. PG: pg_settings. MySQL: SHOW GLOBAL VARIABLES/STATUS.",
    )


def export_json_schema() -> dict:
    """JSON Schema for the Snapshot document (draft 2020-12)."""
    return Snapshot.model_json_schema()


if __name__ == "__main__":
    print(json.dumps(export_json_schema(), indent=2))
