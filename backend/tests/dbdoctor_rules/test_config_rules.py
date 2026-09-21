from app.vendor.dbdoctor.engine.models import ConfigSetting
from app.vendor.dbdoctor.engine.rules.config_mysql import CONFIG_CHECKS as MY_CHECKS
from app.vendor.dbdoctor.engine.rules.config_pg import CONFIG_CHECKS as PG_CHECKS
from app.vendor.dbdoctor.engine.run import run_all
from .conftest import GB, MB, make_snapshot, make_table


def _fired(result, setting):
    return [
        f for f in result.findings if f.rule_id.startswith("R-CFG") and f.affected_object == setting
    ]


def _pg(settings: dict[str, tuple[str, str | None]], **kw):
    return make_snapshot(
        settings=[ConfigSetting(name=n, value=v, unit=u) for n, (v, u) in settings.items()],
        **kw,
    )


def _my(settings: dict[str, str], **kw):
    return make_snapshot(
        engine="mysql",
        settings=[ConfigSetting(name=n, value=v) for n, v in settings.items()],
        **kw,
    )


def test_ten_checks_each_with_readable_rationale():
    assert len(PG_CHECKS) == 10
    assert len(MY_CHECKS) == 10
    for chk in (*PG_CHECKS, *MY_CHECKS):
        assert len(chk.rationale) > 60, chk.setting  # a sentence, not a code
        assert chk.action, chk.setting


# --- PG --------------------------------------------------------------------


def test_pg_shared_buffers_small_vs_db_size():
    snap = _pg(
        {"shared_buffers": ("16384", "8kB")},  # 128MB
        meta={"db_size_bytes": 20 * GB},
    )
    f = _fired(run_all(snap), "shared_buffers")
    assert f and f[0].severity == "LOW"
    assert "25%" in f[0].suggested_action  # cites a range, not a magic number


def test_pg_work_mem_product():
    snap = _pg({"work_mem": ("65536", "kB"), "max_connections": ("512", None)})  # 64MB * 512 = 32GB
    f = _fired(run_all(snap), "work_mem")
    assert f and f[0].evidence["worst_case_memory"] == "32.0 GB"


def test_pg_defaults_detected():
    snap = _pg(
        {
            "effective_cache_size": ("524288", "8kB"),
            "random_page_cost": ("4", None),
            "track_io_timing": ("off", None),
            "checkpoint_completion_target": ("0.5", None),
        }
    )
    result = run_all(snap)
    for setting in (
        "effective_cache_size",
        "random_page_cost",
        "track_io_timing",
        "checkpoint_completion_target",
    ):
        assert _fired(result, setting), setting


def test_pg_autovac_scale_needs_a_large_table():
    settings = {"autovacuum_vacuum_scale_factor": ("0.2", None)}
    no_big = run_all(_pg(settings, tables=[make_table(size_bytes=100 * MB)]))
    assert not _fired(no_big, "autovacuum_vacuum_scale_factor")
    with_big = run_all(_pg(settings, tables=[make_table(size_bytes=10 * GB)]))
    assert _fired(with_big, "autovacuum_vacuum_scale_factor")


def test_pg_healthy_config_is_silent():
    snap = _pg(
        {
            "shared_buffers": ("1048576", "8kB"),  # 8GB
            "effective_cache_size": ("3145728", "8kB"),
            "random_page_cost": ("1.1", None),
            "track_io_timing": ("on", None),
            "autovacuum": ("on", None),
            "checkpoint_completion_target": ("0.9", None),
            "max_connections": ("100", None),
            "work_mem": ("4096", "kB"),
        },
        meta={"db_size_bytes": 5 * GB},
    )
    assert not [f for f in run_all(snap).findings if f.rule_id == "R-CFG-PG"]


# --- MySQL -----------------------------------------------------------------


def test_my_buffer_pool_needs_hit_ratio_evidence_not_size_alone():
    small_pool = {
        "innodb_buffer_pool_size": str(128 * MB),
        "Innodb_buffer_pool_read_requests": "1000000",
    }
    # tiny pool but 99.99% hit ratio: no finding
    good = _my(
        small_pool | {"Innodb_buffer_pool_reads": "100"},
        meta={"db_size_bytes": 10 * GB},
    )
    assert not _fired(run_all(good), "innodb_buffer_pool_size")
    # same pool, 90% hit ratio: HIGH with the ratio in evidence
    bad = _my(
        small_pool | {"Innodb_buffer_pool_reads": "100000"},
        meta={"db_size_bytes": 10 * GB},
    )
    f = _fired(run_all(bad), "innodb_buffer_pool_size")
    assert f and f[0].severity == "HIGH"
    assert f[0].evidence["buffer_pool_hit_ratio_pct"] == 90.0


def test_my_durability_noted_never_recommended_loosened():
    snap = _my({"sync_binlog": "0", "innodb_flush_log_at_trx_commit": "2"})
    f = _fired(run_all(snap), "sync_binlog / innodb_flush_log_at_trx_commit")
    assert f and f[0].severity == "INFO"
    assert "intentional" in f[0].suggested_action
    # safe defaults: silent
    assert not _fired(
        run_all(_my({"sync_binlog": "1", "innodb_flush_log_at_trx_commit": "1"})),
        "sync_binlog / innodb_flush_log_at_trx_commit",
    )


def test_my_assorted_checks():
    snap = _my(
        {
            "innodb_log_file_size": str(48 * MB),
            "tmp_table_size": str(16 * MB),
            "max_heap_table_size": str(64 * MB),
            "Opened_tables": "50000",
            "Uptime": "10000",
            "table_open_cache": "431",
            "Threads_created": "5000",
            "Connections": "20000",
            "thread_cache_size": "4",
            "query_cache_type": "ON",
            "query_cache_size": str(64 * MB),
            "slow_query_log": "OFF",
            "performance_schema": "OFF",
        }
    )
    result = run_all(snap)
    for setting in (
        "innodb_log_file_size",
        "tmp_table_size",
        "table_open_cache",
        "thread_cache_size",
        "query_cache_type",
        "slow_query_log",
        "performance_schema",
    ):
        assert _fired(result, setting), setting
