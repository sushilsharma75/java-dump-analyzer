"""Builders for synthetic snapshots used by rule unit tests."""

import pytest

from app.vendor.dbdoctor.engine.models import (
    IndexStat,
    QueryStat,
    Snapshot,
    SnapshotMeta,
    TableStat,
)

MB = 1024 * 1024
GB = 1024 * MB


def make_query(**kw) -> QueryStat:
    base = dict(
        query_digest="q-" + kw.get("normalized_sql", "x")[:20],
        normalized_sql="SELECT * FROM t WHERE x = ?",
        calls=100,
        total_time_ms=100.0,
        mean_time_ms=1.0,
        rows_returned=100,
    )
    base.update(kw)
    return QueryStat(**base)


def make_table(**kw) -> TableStat:
    base = dict(schema_name="public", name="t", size_bytes=10 * MB)
    base.update(kw)
    return TableStat(**base)


def make_index(**kw) -> IndexStat:
    base = dict(table="public.t", name="t_x_idx", definition="(x)")
    base.update(kw)
    return IndexStat(**base)


def make_snapshot(engine: str = "postgres", **kw) -> Snapshot:
    meta = SnapshotMeta(
        engine=engine,
        version="0.1.0",
        collected_at="2026-07-05T12:00:00Z",
        host_alias="testhost",
        capabilities=["query_stats", "table_stats", "index_stats", "lock_waits", "config"],
        **kw.pop("meta", {}),
    )
    return Snapshot(meta=meta, **kw)


@pytest.fixture
def snap():
    return make_snapshot
