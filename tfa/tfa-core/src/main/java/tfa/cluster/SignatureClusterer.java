package tfa.cluster;

import tfa.model.Episode;
import tfa.model.FlowCluster;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Groups episodes into {@link FlowCluster}s by SIGNATURE: the first K call sites
 * of the episode's call-site sequence (K configurable, default 3). Episodes that
 * begin identically are the same kind of work.
 *
 * <p>Fed incrementally so it composes with the streaming segmenter. Signatures
 * are a bounded set (one per distinct flow shape), so the map itself is small;
 * episodes are retained per cluster for downstream baselining and detection.
 */
public final class SignatureClusterer {

    /** Delimiter between call sites in a signature. Chosen not to occur in a call site. */
    private static final String SEP = " > ";

    private final int k;
    private final Map<String, FlowCluster> bySignature = new LinkedHashMap<>();

    public SignatureClusterer(int k) {
        if (k < 1) {
            throw new IllegalArgumentException("signature K must be >= 1, got " + k);
        }
        this.k = k;
    }

    /** The signature of an episode: its first K call sites (or all, if shorter). */
    public static String signature(Episode episode, int k) {
        List<String> seq = episode.callSiteSequence();
        int n = Math.min(k, seq.size());
        return String.join(SEP, seq.subList(0, n));
    }

    /** Accumulate one episode into its cluster. */
    public void add(Episode episode) {
        String sig = signature(episode, k);
        bySignature.computeIfAbsent(sig, FlowCluster::new).add(episode);
    }

    /**
     * Finalise clustering: mark clusters below {@code minSize} as UNDER_SAMPLED
     * and return them sorted by size descending (largest first).
     */
    public List<FlowCluster> finish(int minSize) {
        List<FlowCluster> clusters = new ArrayList<>(bySignature.values());
        for (FlowCluster c : clusters) {
            c.setUnderSampled(c.size() < minSize);
        }
        clusters.sort(Comparator.comparingInt(FlowCluster::size).reversed()
                .thenComparing(FlowCluster::signature));
        return clusters;
    }

    public int k() { return k; }
}
