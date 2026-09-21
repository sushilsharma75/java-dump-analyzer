"""Flow clustering by signature (first K call sites). Port of `tfa.cluster`."""
from __future__ import annotations

from .model import Episode, FlowCluster

_SEP = " > "


class SignatureClusterer:
    def __init__(self, k: int):
        if k < 1:
            raise ValueError(f"signature K must be >= 1, got {k}")
        self.k = k
        self._by_signature: dict[str, FlowCluster] = {}

    @staticmethod
    def signature(episode: Episode, k: int) -> str:
        seq = episode.call_site_sequence()
        return _SEP.join(seq[:min(k, len(seq))])

    def add(self, episode: Episode) -> None:
        sig = self.signature(episode, self.k)
        cluster = self._by_signature.get(sig)
        if cluster is None:
            cluster = FlowCluster(sig)
            self._by_signature[sig] = cluster
        cluster.add(episode)

    def finish(self, min_size: int) -> list[FlowCluster]:
        clusters = list(self._by_signature.values())
        for c in clusters:
            c.under_sampled = c.size() < min_size
        clusters.sort(key=lambda c: (-c.size(), c.signature))
        return clusters
