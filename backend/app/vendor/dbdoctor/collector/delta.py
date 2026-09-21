"""Two-snapshot diffing: turn cumulative counters into growth and rates.

Used by both collectors via ``--delta-of previous.json``. Operates on plain
Snapshot-shaped dicts (never on live databases) so it stays dependency-free
and auditable alongside the collector scripts.

Counter-reset handling: statistics counters drop after a server restart or a
stats reset. Whenever a current counter is LOWER than the previous one, the
diff for that entry is treated as a reset — rates are computed from the
current (post-reset) counters alone and flagged ``delta_low_confidence`` so
downstream rules can soften their claims.
"""

from __future__ import annotations

from datetime import datetime

SECONDS_PER_DAY = 86_400.0


def _parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def apply_delta(current: dict, previous: dict) -> dict:
    """Enrich *current* (in place) with rates/growth diffed against *previous*.

    Returns *current* with meta.is_delta set, per-query calls_per_day /
    time_per_day_ms, and per-table growth_30d_pct extrapolated from the
    actual interval between the two snapshots.
    """
    for key in ("engine", "host_alias", "server_version"):
        if current["meta"].get(key) != previous["meta"].get(key):
            raise ValueError(f"Cannot compare different database {key} values")
    if not current["meta"].get("host_alias"):
        raise ValueError("Database identity is required for comparison")
    if current["meta"].get("is_delta") or previous["meta"].get("is_delta"):
        raise ValueError("Comparison requires original cumulative snapshots")
    for snapshot in (current, previous):
        if _parse_ts(snapshot["meta"]["collected_at"]).utcoffset() is None:
            raise ValueError("Capture timestamps must include a timezone")
    for snapshot in (current, previous):
        digests = [q["query_digest"] for q in snapshot.get("queries", [])]
        if len(digests) != len(set(digests)):
            raise ValueError("Ambiguous duplicate query digests prevent comparison")
    interval_s = (
        _parse_ts(current["meta"]["collected_at"]) - _parse_ts(previous["meta"]["collected_at"])
    ).total_seconds()
    if interval_s <= 0:
        raise ValueError(
            "previous snapshot is not older than the current one "
            f"(interval {interval_s:.0f}s); pass the older file to --delta-of"
        )
    days = interval_s / SECONDS_PER_DAY

    prev_queries = {q["query_digest"]: q for q in previous.get("queries", [])}
    for q in current.get("queries", []):
        prev = prev_queries.get(q["query_digest"])
        if prev is None:
            # first time we see this statement: rate from its own counters,
            # capped at the observation interval, marked low-confidence
            q["calls_per_day"] = round(q["calls"] / days, 3)
            q["time_per_day_ms"] = round(q["total_time_ms"] / days, 3)
            q["delta_low_confidence"] = True
            continue
        d_calls = q["calls"] - prev["calls"]
        d_time = q["total_time_ms"] - prev["total_time_ms"]
        if d_calls < 0 or d_time < 0:
            # counter reset: previous baseline is unusable
            d_calls, d_time = q["calls"], q["total_time_ms"]
            q["delta_low_confidence"] = True
        else:
            q["delta_low_confidence"] = False
        q["calls_per_day"] = round(d_calls / days, 3)
        q["time_per_day_ms"] = round(d_time / days, 3)

    prev_tables = {(t["schema_name"], t["name"]): t for t in previous.get("tables", [])}
    for t in current.get("tables", []):
        prev = prev_tables.get((t["schema_name"], t["name"]))
        if prev is None or not prev.get("size_bytes"):
            continue  # new table (or empty before): no growth baseline
        growth = (t["size_bytes"] - prev["size_bytes"]) / prev["size_bytes"]
        t["growth_30d_pct"] = round(growth * (30.0 / days) * 100.0, 2)

    current["meta"]["is_delta"] = True
    current["meta"]["delta_interval_seconds"] = round(interval_s, 1)
    return current
