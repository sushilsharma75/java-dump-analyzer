"""Consensus baseline per cluster, over collapsed sequences. Port of
`tfa.baseline`. Deterministic (ties broken lexicographically)."""
from __future__ import annotations

import math
from typing import Optional

from .config import BaselineConfig
from .ingest import epoch_millis
from .model import (Baseline, Episode, FlowCluster, PositionOption, SequenceShare,
                    TransitionTiming)


def percentile(sorted_asc: list[int], p: float) -> float:
    if not sorted_asc:
        return 0.0
    n = len(sorted_asc)
    rank = math.ceil(p / 100.0 * n)
    rank = max(1, min(rank, n))
    return float(sorted_asc[rank - 1])


def build_baseline(cluster: FlowCluster, config: BaselineConfig) -> Optional[Baseline]:
    used = [e for e in cluster.episodes
            if config.in_baseline_window(e.start) and e.collapsed_sequence()]
    if not used:
        return None

    # 1. modal sequence + alternatives
    seq_counts: dict[tuple[str, ...], int] = {}
    for e in used:
        key = tuple(e.collapsed_sequence())
        seq_counts[key] = seq_counts.get(key, 0) + 1
    ranked = sorted(seq_counts.items(), key=lambda kv: (-kv[1], "".join(kv[0])))

    modal_sequence = list(ranked[0][0])
    modal_count = ranked[0][1]
    modal_share = modal_count / len(used)

    alternatives: list[SequenceShare] = []
    for seq, c in ranked[1:]:
        if len(alternatives) >= config.alternatives_to_report:
            break
        alternatives.append(SequenceShare(seq, c, c / len(used)))

    # 2. positional distribution
    positional: list[list[PositionOption]] = []
    for pos in range(len(modal_sequence)):
        at_pos: dict[str, int] = {}
        reached = 0
        for e in used:
            seq = e.collapsed_sequence()
            if pos < len(seq):
                reached += 1
                at_pos[seq[pos]] = at_pos.get(seq[pos], 0) + 1
        opts = [PositionOption(cs, n, (n / reached) if reached else 0.0)
                for cs, n in at_pos.items()]
        opts.sort(key=lambda o: (-o.count, o.call_site))
        positional.append(opts)

    # 3. transition counts + 4. timing samples
    transition_counts: dict[str, dict[str, int]] = {}
    timing_samples: dict[tuple[str, str], list[int]] = {}
    for e in used:
        runs = e.collapsed_runs()
        for i in range(len(runs) - 1):
            a, b = runs[i], runs[i + 1]
            transition_counts.setdefault(a.call_site, {})
            transition_counts[a.call_site][b.call_site] = \
                transition_counts[a.call_site].get(b.call_site, 0) + 1
            if a.first_timestamp is not None and b.first_timestamp is not None:
                ms = max(0, epoch_millis(b.first_timestamp) - epoch_millis(a.first_timestamp))
                timing_samples.setdefault((a.call_site, b.call_site), []).append(ms)

    timings: list[TransitionTiming] = []
    for (frm, to), samples in timing_samples.items():
        samples.sort()
        timings.append(TransitionTiming(frm, to, len(samples),
                                        percentile(samples, 50), percentile(samples, 95)))
    timings.sort(key=lambda t: (t.frm, t.to))

    return Baseline(cluster.signature, len(used), modal_sequence, modal_share,
                    modal_count, alternatives, positional, transition_counts, timings)
