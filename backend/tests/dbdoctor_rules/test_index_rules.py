from app.vendor.dbdoctor.engine.run import run_all
from .conftest import GB, MB, make_index, make_query, make_snapshot, make_table


def _fired(result, rule_id):
    return [f for f in result.findings if f.rule_id == rule_id]


def _pg_missing_index_snap(size=200 * MB, seq_scans=5000):
    return make_snapshot(
        tables=[make_table(name="orders", size_bytes=size, seq_scans=seq_scans)],
        queries=[
            make_query(
                normalized_sql="SELECT id, status FROM orders WHERE customer_id = ?",
                calls=4000,
                total_time_ms=6000.0,
            )
        ],
        indexes=[
            make_index(
                table="public.orders", name="orders_pkey", definition="(id)", is_primary=True
            )
        ],
    )


def test_i1_pg_suggests_filter_column():
    f = _fired(run_all(_pg_missing_index_snap()), "R-I1")
    assert len(f) == 1
    assert f[0].affected_object == "orders"
    assert f[0].evidence["candidate_columns"] == "customer_id"
    assert f[0].confidence == "medium"
    assert "staging" in f[0].suggested_action.lower()
    assert f[0].severity == "MEDIUM"


def test_i1_pg_multi_column_and_high_severity_when_large():
    snap = make_snapshot(
        tables=[make_table(name="events", size_bytes=2 * GB, seq_scans=9000)],
        queries=[
            make_query(
                normalized_sql="SELECT * FROM events WHERE user_id = ? AND kind = ?",
                calls=500,
            )
        ],
    )
    f = _fired(run_all(snap), "R-I1")[0]
    assert f.evidence["candidate_columns"] == "user_id, kind"
    assert f.severity == "HIGH"


def test_i1_pg_skips_small_tables_and_indexed_columns():
    # small table: no finding
    assert not _fired(run_all(_pg_missing_index_snap(size=10 * MB)), "R-I1")
    # filter column already leads an index: no finding
    snap = _pg_missing_index_snap()
    snap.indexes.append(
        make_index(table="public.orders", name="orders_cust_idx", definition="(customer_id)")
    )
    assert not _fired(run_all(snap), "R-I1")


def test_i1_mysql_uses_full_scan_selectivity():
    snap = make_snapshot(
        engine="mysql",
        tables=[make_table(name="orders", size_bytes=300 * MB)],
        queries=[
            make_query(
                normalized_sql="SELECT `id` FROM `orders` WHERE `customer_id` = ?",
                calls=2000,
                rows_returned=4000,
                rows_examined=4_000_000,
                full_scan_flag=True,
            )
        ],
    )
    f = _fired(run_all(snap), "R-I1")
    assert len(f) == 1
    assert f[0].affected_object == "public.orders"
    assert f[0].evidence["candidate_columns"] == "customer_id"


def test_i1_mysql_ignores_selective_scans():
    snap = make_snapshot(
        engine="mysql",
        tables=[make_table(name="orders", size_bytes=300 * MB)],
        queries=[
            make_query(
                normalized_sql="SELECT `id` FROM `orders` WHERE `customer_id` = ?",
                calls=2000,
                rows_returned=100_000,
                rows_examined=110_000,  # examined ≈ returned: index wouldn't help much
                full_scan_flag=True,
            )
        ],
    )
    assert not _fired(run_all(snap), "R-I1")


def test_i2_pg_unused_and_never_flags_pk_or_unique():
    snap = make_snapshot(
        indexes=[
            make_index(name="t_pkey", is_primary=True, scans=0, size_bytes=500 * MB),
            make_index(name="t_email_uq", is_unique=True, scans=0, size_bytes=500 * MB),
            make_index(name="t_old_idx", scans=0, size_bytes=150 * MB),
            make_index(name="t_hot_idx", scans=9000, size_bytes=150 * MB),
            make_index(name="t_tiny_idx", scans=0, size_bytes=1 * MB),
        ]
    )
    f = _fired(run_all(snap), "R-I2")
    assert [x.affected_object for x in f] == ["public.t.t_old_idx"]
    assert f[0].severity == "MEDIUM"  # >= 100MB
    assert f[0].confidence == "medium"


def test_i2_mysql_uses_sys_view_flag():
    snap = make_snapshot(
        engine="mysql",
        indexes=[
            make_index(name="idx_a", is_unused_candidate=True),
            make_index(name="PRIMARY", is_primary=True, is_unused_candidate=False),
            make_index(name="idx_b", is_unused_candidate=False),
        ],
    )
    f = _fired(run_all(snap), "R-I2")
    assert [x.affected_object for x in f] == ["public.t.idx_a"]


def test_i3_pg_prefix_and_exact_duplicates():
    snap = make_snapshot(
        indexes=[
            make_index(
                name="users_email_idx",
                definition="CREATE INDEX users_email_idx ON public.users USING btree (email)",
                table="public.users",
            ),
            make_index(
                name="users_email_dup_idx",
                definition="CREATE INDEX users_email_dup_idx ON public.users USING btree (email)",
                table="public.users",
            ),
            make_index(
                name="users_email_name_idx",
                definition=(
                    "CREATE INDEX users_email_name_idx ON public.users USING btree (email, name)"
                ),
                table="public.users",
            ),
            make_index(
                name="users_name_idx",
                definition="CREATE INDEX users_name_idx ON public.users USING btree (name)",
                table="public.users",
            ),
        ]
    )
    f = _fired(run_all(snap), "R-I3")
    flagged = {x.affected_object for x in f}
    # both single-column email indexes are covered by (email, name);
    # (name) alone is NOT a leading prefix of anything -> never flagged
    assert "public.users.users_email_idx" in flagged
    assert "public.users.users_email_dup_idx" in flagged
    assert "public.users.users_name_idx" not in flagged


def test_i3_pg_never_flags_unique_over_plain_duplicate():
    snap = make_snapshot(
        indexes=[
            make_index(name="a_uq", definition="(email)", is_unique=True),
            make_index(name="b_plain", definition="(email)"),
        ]
    )
    f = _fired(run_all(snap), "R-I3")
    assert [x.affected_object for x in f] == ["public.t.b_plain"]


def test_i3_mysql_uses_redundant_view():
    snap = make_snapshot(
        engine="mysql",
        indexes=[
            make_index(name="dup", is_duplicate_candidate=True),
            make_index(name="keep", is_duplicate_candidate=False),
        ],
    )
    f = _fired(run_all(snap), "R-I3")
    assert [x.affected_object for x in f] == ["public.t.dup"]
