"""PostgreSQL config sanity checks (R-CFG-PG), data-driven.

Each check cites the current value against a recommended RANGE with a
rationale a non-DBA can read — never a single magic number. We do not see
the machine's RAM, so memory advice is phrased relative to what we can see
and asks the customer to verify."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from app.vendor.dbdoctor.engine.models import Snapshot
from app.vendor.dbdoctor.engine.rules.base import Finding, Rule, Severity, fmt_bytes, register
from app.vendor.dbdoctor.engine.thresholds import THRESHOLDS as T

_UNIT_BYTES = {"B": 1, "kB": 1024, "8kB": 8192, "MB": 1024**2, "GB": 1024**3, "16MB": 16 * 1024**2}


class Ctx:
    """What a config check can look at."""

    def __init__(self, snapshot: Snapshot):
        self.snapshot = snapshot
        self._settings = {s.name: s for s in snapshot.settings}

    def raw(self, name: str) -> str | None:
        s = self._settings.get(name)
        return s.value if s else None

    def num(self, name: str) -> float | None:
        raw = self.raw(name)
        if raw is None:
            return None
        try:
            return float(raw)
        except ValueError:
            return None

    def bytes(self, name: str) -> float | None:
        s = self._settings.get(name)
        if s is None:
            return None
        try:
            value = float(s.value)
        except ValueError:
            return None
        return value * _UNIT_BYTES.get(s.unit or "B", 1)

    @property
    def db_size(self) -> int | None:
        return self.snapshot.meta.db_size_bytes

    def has_table_larger_than(self, size: int) -> bool:
        return any(t.size_bytes >= size for t in self.snapshot.tables)


@dataclass(frozen=True)
class ConfigCheck:
    setting: str
    severity: Severity
    check: Callable[[Ctx], dict | None]  # evidence dict when the check fires
    rationale: str
    action: str


def _shared_buffers(ctx: Ctx) -> dict | None:
    sb = ctx.bytes("shared_buffers")
    if sb is None or ctx.db_size is None:
        return None
    if sb < ctx.db_size * T.pg_shared_buffers_db_fraction and sb <= T.pg_shared_buffers_cap_bytes:
        return {"shared_buffers": fmt_bytes(sb), "database_size": fmt_bytes(ctx.db_size)}
    return None


def _work_mem_product(ctx: Ctx) -> dict | None:
    wm, mc = ctx.bytes("work_mem"), ctx.num("max_connections")
    if wm is None or mc is None:
        return None
    worst = wm * mc
    if worst > T.pg_workmem_product_bytes:
        return {
            "work_mem": fmt_bytes(wm),
            "max_connections": int(mc),
            "worst_case_memory": fmt_bytes(worst),
        }
    return None


def _effective_cache_size(ctx: Ctx) -> dict | None:
    raw = ctx.num("effective_cache_size")
    if raw is not None and int(raw) == T.pg_effective_cache_size_default:
        return {"effective_cache_size": "4 GB (compiled default)"}
    return None


def _autovac_scale(ctx: Ctx) -> dict | None:
    sf = ctx.num("autovacuum_vacuum_scale_factor")
    if sf is None or sf <= T.pg_autovac_scale_factor_max:
        return None
    if not ctx.has_table_larger_than(T.pg_autovac_scale_table_bytes):
        return None
    return {
        "autovacuum_vacuum_scale_factor": sf,
        "largest_tables_over": fmt_bytes(T.pg_autovac_scale_table_bytes),
    }


def _wal_buffers(ctx: Ctx) -> dict | None:
    raw = ctx.num("wal_buffers")
    if raw is None or raw <= 0:  # -1 = auto-tuned, fine
        return None
    wb = ctx.bytes("wal_buffers")
    if wb is not None and wb < 1024**2:
        return {"wal_buffers": fmt_bytes(wb)}
    return None


def _random_page_cost(ctx: Ctx) -> dict | None:
    rpc = ctx.num("random_page_cost")
    if rpc is not None and rpc >= 4:
        return {"random_page_cost": rpc}
    return None


def _max_connections(ctx: Ctx) -> dict | None:
    mc = ctx.num("max_connections")
    if mc is not None and mc >= T.pg_max_connections_high:
        return {"max_connections": int(mc)}
    return None


def _checkpoint_target(ctx: Ctx) -> dict | None:
    cct = ctx.num("checkpoint_completion_target")
    if cct is not None and cct < T.pg_checkpoint_target_min:
        return {"checkpoint_completion_target": cct}
    return None


def _autovacuum_off(ctx: Ctx) -> dict | None:
    if ctx.raw("autovacuum") == "off":
        return {"autovacuum": "off"}
    return None


def _track_io_timing(ctx: Ctx) -> dict | None:
    if ctx.raw("track_io_timing") == "off":
        return {"track_io_timing": "off"}
    return None


CONFIG_CHECKS: tuple[ConfigCheck, ...] = (
    ConfigCheck(
        "shared_buffers",
        "LOW",
        _shared_buffers,
        "shared_buffers is PostgreSQL's own data cache. Yours is small relative to the "
        "database, so reads lean on the OS cache alone. The usual starting point is "
        "about 25% of system RAM (we can't see RAM from here — check before changing).",
        "Raise shared_buffers toward 25% of RAM in steps; restart required.",
    ),
    ConfigCheck(
        "work_mem",
        "MEDIUM",
        _work_mem_product,
        "Every sort/hash in every connection may use up to work_mem. With your "
        "max_connections, the worst case exceeds what a typical server holds — a busy "
        "moment can push the machine into swap or OOM.",
        "Lower work_mem or max_connections (add a pooler); size worst case to fit RAM.",
    ),
    ConfigCheck(
        "effective_cache_size",
        "INFO",
        _effective_cache_size,
        "effective_cache_size is still the compiled default (4 GB). It costs nothing at "
        "runtime — it only tells the planner how much cache the OS likely has. Left too "
        "low, the planner avoids indexes it should use.",
        "Set it to 50-75% of the machine's RAM; reload is enough.",
    ),
    ConfigCheck(
        "autovacuum",
        "HIGH",
        _autovacuum_off,
        "Autovacuum is off server-wide. Dead rows accumulate unbounded and transaction-ID "
        "age keeps climbing, which eventually forces an emergency shutdown vacuum.",
        "Turn autovacuum back on; tune per-table settings instead of disabling globally.",
    ),
    ConfigCheck(
        "autovacuum_vacuum_scale_factor",
        "MEDIUM",
        _autovac_scale,
        "Vacuum triggers when this fraction of a table changes. On your large tables the "
        "current factor means many millions of dead rows accumulate before vacuum starts.",
        "Set a lower per-table scale factor (e.g. 0.02) on the largest tables via "
        "ALTER TABLE ... SET.",
    ),
    ConfigCheck(
        "wal_buffers",
        "LOW",
        _wal_buffers,
        "wal_buffers has been set explicitly to a very small value; commit bursts then "
        "wait on WAL writes. The auto-tuned default (-1) is usually right.",
        "Remove the explicit setting (back to -1/auto) or raise it to 16MB.",
    ),
    ConfigCheck(
        "random_page_cost",
        "INFO",
        _random_page_cost,
        "random_page_cost=4 models spinning disks. On SSD/NVMe storage random reads are "
        "nearly as cheap as sequential — with the old value the planner avoids index "
        "scans it should choose.",
        "If storage is SSD, set random_page_cost between 1.1 and 1.5; reload is enough.",
    ),
    ConfigCheck(
        "max_connections",
        "LOW",
        _max_connections,
        "Very high max_connections trades memory and scheduler overhead for headroom that "
        "a connection pooler provides far more cheaply — each connection is a process.",
        "Put PgBouncer (or an app-side pool) in front and lower max_connections.",
    ),
    ConfigCheck(
        "checkpoint_completion_target",
        "INFO",
        _checkpoint_target,
        "Checkpoints are being rushed into a short window, causing I/O spikes. Modern "
        "PostgreSQL defaults to 0.9 to spread checkpoint writes smoothly.",
        "Set checkpoint_completion_target = 0.9.",
    ),
    ConfigCheck(
        "track_io_timing",
        "INFO",
        _track_io_timing,
        "track_io_timing is off, so per-query I/O time isn't recorded. Enabling it makes "
        "future audits sharper (measurable overhead is small on modern hardware).",
        "SET track_io_timing = on (ALTER SYSTEM + reload).",
    ),
)


@register
class PgConfigSanity(Rule):
    id = "R-CFG-PG"
    title = "PostgreSQL configuration check"
    category = "config"
    engines = frozenset({"postgres"})

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
