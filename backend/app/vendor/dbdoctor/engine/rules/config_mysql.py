"""MySQL/MariaDB config sanity checks (R-CFG-MY), data-driven.

Same pattern as config_pg: each check cites current value vs a recommended
range with a plain-English rationale. Durability settings are only ever
NOTED — we never recommend loosening them silently."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from app.vendor.dbdoctor.engine.models import Snapshot
from app.vendor.dbdoctor.engine.rules.base import Finding, Rule, Severity, fmt_bytes, register
from app.vendor.dbdoctor.engine.thresholds import THRESHOLDS as T


class Ctx:
    def __init__(self, snapshot: Snapshot):
        self.snapshot = snapshot
        self._vals = {s.name: s.value for s in snapshot.settings}

    def raw(self, name: str) -> str | None:
        return self._vals.get(name)

    def num(self, name: str) -> float | None:
        raw = self._vals.get(name)
        if raw is None:
            return None
        try:
            return float(raw)
        except ValueError:
            return None

    @property
    def db_size(self) -> int | None:
        return self.snapshot.meta.db_size_bytes


@dataclass(frozen=True)
class ConfigCheck:
    setting: str
    severity: Severity
    check: Callable[[Ctx], dict | None]
    rationale: str
    action: str


def _buffer_pool(ctx: Ctx) -> dict | None:
    """Fires on hit-ratio evidence, never on size alone."""
    pool = ctx.num("innodb_buffer_pool_size")
    reads = ctx.num("Innodb_buffer_pool_reads")
    reqs = ctx.num("Innodb_buffer_pool_read_requests")
    if pool is None or ctx.db_size is None or not reqs:
        return None
    hit_ratio = 1.0 - (reads or 0) / reqs
    if (
        pool < ctx.db_size * T.my_buffer_pool_db_fraction
        and hit_ratio < T.my_buffer_pool_hit_ratio_min
    ):
        return {
            "innodb_buffer_pool_size": fmt_bytes(pool),
            "data_size": fmt_bytes(ctx.db_size),
            "buffer_pool_hit_ratio_pct": round(hit_ratio * 100, 2),
        }
    return None


def _log_file_size(ctx: Ctx) -> dict | None:
    size = ctx.num("innodb_log_file_size")
    if size is not None and size < T.my_log_file_min_bytes:
        return {"innodb_log_file_size": fmt_bytes(size)}
    return None


def _tmp_table_mismatch(ctx: Ctx) -> dict | None:
    tmp, heap = ctx.num("tmp_table_size"), ctx.num("max_heap_table_size")
    if tmp is None or heap is None or tmp == heap:
        return None
    evidence = {"tmp_table_size": fmt_bytes(tmp), "max_heap_table_size": fmt_bytes(heap)}
    disk = ctx.num("Created_tmp_disk_tables")
    total = ctx.num("Created_tmp_tables")
    if disk is not None and total:
        evidence["tmp_tables_on_disk_pct"] = round(disk / total * 100, 1)
    return evidence


def _table_open_cache(ctx: Ctx) -> dict | None:
    opened, uptime = ctx.num("Opened_tables"), ctx.num("Uptime")
    if opened is None or not uptime or uptime < T.my_min_uptime_s:
        return None
    rate = opened / uptime
    if rate > T.my_opened_tables_per_sec:
        return {
            "opened_tables_per_second": round(rate, 2),
            "table_open_cache": ctx.raw("table_open_cache") or "unknown",
        }
    return None


def _thread_cache(ctx: Ctx) -> dict | None:
    created, conns = ctx.num("Threads_created"), ctx.num("Connections")
    if created is None or not conns or conns < T.my_min_connections_sample:
        return None
    ratio = created / conns
    if ratio > T.my_thread_created_ratio:
        return {
            "threads_created_per_connection": round(ratio, 3),
            "thread_cache_size": ctx.raw("thread_cache_size") or "unknown",
        }
    return None


def _max_connections(ctx: Ctx) -> dict | None:
    mc = ctx.num("max_connections")
    if mc is not None and mc >= T.my_max_connections_high:
        return {"max_connections": int(mc)}
    return None


def _durability_tradeoff(ctx: Ctx) -> dict | None:
    sync_binlog = ctx.raw("sync_binlog")
    flush = ctx.raw("innodb_flush_log_at_trx_commit")
    loosened = {}
    if sync_binlog is not None and sync_binlog != "1":
        loosened["sync_binlog"] = sync_binlog
    if flush is not None and flush != "1":
        loosened["innodb_flush_log_at_trx_commit"] = flush
    return loosened or None


def _query_cache(ctx: Ctx) -> dict | None:
    qc_type = ctx.raw("query_cache_type")
    qc_size = ctx.num("query_cache_size")
    if qc_type in ("ON", "1", "DEMAND", "2") and qc_size:
        return {"query_cache_type": qc_type, "query_cache_size": fmt_bytes(qc_size)}
    return None


def _slow_query_log(ctx: Ctx) -> dict | None:
    if ctx.raw("slow_query_log") in ("OFF", "0"):
        return {"slow_query_log": "OFF"}
    return None


def _performance_schema_off(ctx: Ctx) -> dict | None:
    if ctx.raw("performance_schema") in ("OFF", "0"):
        return {"performance_schema": "OFF"}
    return None


CONFIG_CHECKS: tuple[ConfigCheck, ...] = (
    ConfigCheck(
        "innodb_buffer_pool_size",
        "HIGH",
        _buffer_pool,
        "The buffer pool is InnoDB's main cache. Yours is well below the data size AND "
        "the measured hit ratio shows real reads going to disk — queries pay disk "
        "latency that memory would absorb. Aim for a pool that holds the hot data; on a "
        "dedicated server that's typically 60-75% of RAM (verify RAM before changing).",
        "Raise innodb_buffer_pool_size toward the hot-data size.",
    ),
    ConfigCheck(
        "innodb_log_file_size",
        "LOW",
        _log_file_size,
        "Small redo logs force frequent checkpoints; on write-heavy workloads that shows "
        "up as periodic stalls. Typical modern values are 512MB-2GB.",
        "Raise innodb_log_file_size (requires restart; on 8.0.30+ use innodb_redo_log_capacity).",
    ),
    ConfigCheck(
        "tmp_table_size",
        "LOW",
        _tmp_table_mismatch,
        "In-memory temp tables are capped by the SMALLER of tmp_table_size and "
        "max_heap_table_size — setting only one of them is a common misconfiguration; "
        "the extra headroom silently never applies.",
        "Set both to the same value.",
    ),
    ConfigCheck(
        "table_open_cache",
        "MEDIUM",
        _table_open_cache,
        "Tables are being re-opened at a high rate, which means the table cache is "
        "thrashing — each re-open costs filesystem work on every query touching the table.",
        "Raise table_open_cache (watch open_files_limit).",
    ),
    ConfigCheck(
        "thread_cache_size",
        "LOW",
        _thread_cache,
        "A new OS thread is being created for a noticeable share of connections instead "
        "of reusing a cached one — cheap to fix and saves connection latency.",
        "Raise thread_cache_size (e.g. 16-64) and re-measure Threads_created.",
    ),
    ConfigCheck(
        "max_connections",
        "INFO",
        _max_connections,
        "Very high max_connections invites memory exhaustion under load: every connection "
        "can allocate sort/join buffers. A pool in front of the database provides the "
        "same headroom safely.",
        "Add ProxySQL or an application-side pool; then lower max_connections.",
    ),
    ConfigCheck(
        "sync_binlog / innodb_flush_log_at_trx_commit",
        "INFO",
        _durability_tradeoff,
        "Durability settings are loosened from their safe defaults: on a crash the last "
        "moments of committed transactions can be lost. This may be a deliberate "
        "throughput tradeoff — we flag it so it stays a DECISION, not an accident.",
        "Confirm this tradeoff is intentional and documented; if not, restore both to 1.",
    ),
    ConfigCheck(
        "query_cache_type",
        "MEDIUM",
        _query_cache,
        "The query cache serializes writes through a single mutex and was removed from "
        "MySQL 8 for that reason; on older MySQL/MariaDB it commonly hurts more than it "
        "helps under concurrency.",
        "Disable it (query_cache_type=OFF, query_cache_size=0) and rely on app-level caching.",
    ),
    ConfigCheck(
        "slow_query_log",
        "INFO",
        _slow_query_log,
        "The slow query log is off. performance_schema covers aggregate statistics, but "
        "the log captures concrete worst-case executions — useful corroborating evidence "
        "when chasing intermittent slowness.",
        "Enable slow_query_log with long_query_time ~1s; rotate the file.",
    ),
    ConfigCheck(
        "performance_schema",
        "LOW",
        _performance_schema_off,
        "performance_schema is disabled, so per-query statistics are not being recorded "
        "at all — this audit is running partially blind and future ones will too.",
        "Set performance_schema = ON in my.cnf and restart "
        "(see docs/enable_performance_schema.md).",
    ),
)


@register
class MySQLConfigSanity(Rule):
    id = "R-CFG-MY"
    title = "MySQL configuration check"
    category = "config"
    engines = frozenset({"mysql", "mariadb"})

    def evaluate(self, snapshot: Snapshot) -> list[Finding]:
        ctx = Ctx(snapshot)
        findings = []
        for chk in CONFIG_CHECKS:
            evidence = chk.check(ctx)
            if evidence is None:
                continue
            findings.append(
                self.finding(
                    snapshot,
                    severity=chk.severity,
                    title=f"Configuration: {chk.setting}",
                    affected_object=chk.setting,
                    evidence=evidence,
                    suggested_action=f"{chk.rationale} Suggested change: {chk.action}",
                )
            )
        return findings
