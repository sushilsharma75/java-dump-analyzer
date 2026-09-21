"""Every tunable number in the rule engine, in one place.

False positives erode trust faster than anything else in this product —
when real-audit feedback says a rule is too eager or too timid, the fix
must be a one-line change here, never a code hunt.
"""

from dataclasses import dataclass

KB = 1024
MB = 1024 * KB
GB = 1024 * MB


@dataclass(frozen=True)
class Thresholds:
    # --- query rules -------------------------------------------------------
    q1_pct_of_db_time: float = 0.20  # R-Q1 fires at this share of total time
    q1_critical_pct: float = 0.40  # ...and escalates to CRITICAL here
    q2_mean_ms: float = 1000.0  # R-Q2: mean latency considered slow
    q2_high_calls: int = 10_000  # R-Q2 severity scales with call volume
    q2_medium_calls: int = 100
    q3_calls_per_day: float = 50_000  # R-Q3 high-frequency threshold
    q3_high_calls_per_day: float = 500_000

    # --- index rules -------------------------------------------------------
    i1_min_table_size_bytes: int = 100 * MB  # R-I1: ignore small tables
    i1_high_table_size_bytes: int = 1 * GB  # ...HIGH severity above this
    i1_min_seq_scans: int = 500  # PG: seq scans to call it a pattern
    i1_scan_selectivity: float = 100.0  # MySQL: rows_examined / rows_sent
    i1_min_calls: int = 10  # ignore one-off scans
    i2_min_size_bytes: int = 20 * MB  # R-I2: unused index worth flagging
    i2_medium_size_bytes: int = 100 * MB

    # --- ops rules ---------------------------------------------------------
    l1_wait_ms: float = 5000.0  # R-L1 lock wait threshold
    c1_high_pct: float = 0.80  # R-C1 connection usage HIGH
    c1_critical_pct: float = 0.90  # ...CRITICAL
    g1_growth_30d_pct: float = 25.0  # R-G1 table growth threshold
    g1_min_size_bytes: int = 500 * MB

    # --- maintenance rules -------------------------------------------------
    m1_dead_tuple_ratio: float = 0.20  # R-M1 vacuum lag
    m1_min_size_bytes: int = 100 * MB
    m2_dead_tuple_ratio: float = 0.05  # R-M2 never-vacuumed active table
    m2_min_size_bytes: int = 100 * MB
    m3_dead_tuple_ratio: float = 0.10  # R-M3 bloat estimate input
    m3_min_size_bytes: int = 500 * MB
    m4_fragmentation_ratio: float = 0.30  # R-M4 data_free / size
    m4_min_size_bytes: int = 500 * MB

    # --- config rules (PG) -------------------------------------------------
    pg_shared_buffers_db_fraction: float = 0.10  # flag if buffers < db/10
    pg_shared_buffers_cap_bytes: int = 2 * GB  # ...and below this cap
    pg_workmem_product_bytes: int = 16 * GB  # work_mem * max_connections
    pg_effective_cache_size_default: int = 524_288  # 4GB in 8kB pages
    pg_autovac_scale_factor_max: float = 0.15
    pg_autovac_scale_table_bytes: int = 5 * GB
    pg_max_connections_high: int = 500
    pg_checkpoint_target_min: float = 0.9

    # --- config rules (MySQL) ----------------------------------------------
    my_buffer_pool_db_fraction: float = 0.5  # pool below half of data size
    my_buffer_pool_hit_ratio_min: float = 0.99
    my_log_file_min_bytes: int = 64 * MB
    my_opened_tables_per_sec: float = 1.0
    my_min_uptime_s: int = 3600
    my_thread_created_ratio: float = 0.10
    my_min_connections_sample: int = 1000
    my_max_connections_high: int = 1000


THRESHOLDS = Thresholds()
