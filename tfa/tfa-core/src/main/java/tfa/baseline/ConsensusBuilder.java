package tfa.baseline;

import tfa.config.BaselineConfig;
import tfa.model.Baseline;
import tfa.model.Episode;
import tfa.model.FlowCluster;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Derives a {@link Baseline} — the consensus for a cluster — over collapsed
 * call-site sequences (loops and retries collapsed, so a retry storm does not
 * swamp the comparison). Everything is computed deterministically: ties are
 * broken by lexicographic order so the same input yields the same baseline.
 *
 * <p>Honors baseline windowing: only episodes whose start falls in the baseline
 * window contribute, so a defect present throughout the baseline window does not
 * quietly become "normal".
 */
public final class ConsensusBuilder {

    private ConsensusBuilder() {}

    /**
     * Build the baseline for a cluster, or {@code null} if no episodes fall in
     * the baseline window (nothing to derive a consensus from).
     */
    public static Baseline build(FlowCluster cluster, BaselineConfig config) {
        List<Episode> used = new ArrayList<>();
        for (Episode e : cluster.episodes()) {
            if (config.inBaselineWindow(e.start()) && !e.collapsedSequence().isEmpty()) {
                used.add(e);
            }
        }
        if (used.isEmpty()) {
            return null;
        }

        // 1. MODAL SEQUENCE + alternatives (exact collapsed sequence frequencies)
        Map<List<String>, Long> seqCounts = new LinkedHashMap<>();
        for (Episode e : used) {
            seqCounts.merge(e.collapsedSequence(), 1L, Long::sum);
        }
        List<Map.Entry<List<String>, Long>> ranked = new ArrayList<>(seqCounts.entrySet());
        ranked.sort(Comparator
                .comparingLong((Map.Entry<List<String>, Long> en) -> en.getValue()).reversed()
                .thenComparing(en -> String.join("", en.getKey())));

        List<String> modalSequence = ranked.get(0).getKey();
        long modalCount = ranked.get(0).getValue();
        double modalShare = (double) modalCount / used.size();

        List<Baseline.SequenceShare> alternatives = new ArrayList<>();
        for (int i = 1; i < ranked.size() && alternatives.size() < config.alternativesToReport(); i++) {
            long c = ranked.get(i).getValue();
            alternatives.add(new Baseline.SequenceShare(
                    ranked.get(i).getKey(), c, (double) c / used.size()));
        }

        // 2. POSITIONAL DISTRIBUTION over the modal sequence positions
        List<List<Baseline.PositionOption>> positional = new ArrayList<>();
        for (int pos = 0; pos < modalSequence.size(); pos++) {
            Map<String, Long> atPos = new HashMap<>();
            long reached = 0;
            for (Episode e : used) {
                List<String> seq = e.collapsedSequence();
                if (pos < seq.size()) {
                    reached++;
                    atPos.merge(seq.get(pos), 1L, Long::sum);
                }
            }
            positional.add(toOptions(atPos, reached));
        }

        // 3. TRANSITION PROBABILITIES (collapsed adjacent pairs)
        Map<String, Map<String, Long>> transitionCounts = new HashMap<>();
        // 4. TRANSITION TIMING samples per (from,to)
        Map<String, List<Long>> timingSamples = new LinkedHashMap<>();
        for (Episode e : used) {
            List<Episode.Run> runs = e.collapsedRuns();
            for (int i = 0; i + 1 < runs.size(); i++) {
                Episode.Run a = runs.get(i);
                Episode.Run b = runs.get(i + 1);
                transitionCounts
                        .computeIfAbsent(a.callSite(), k -> new HashMap<>())
                        .merge(b.callSite(), 1L, Long::sum);
                Instant from = a.firstTimestamp();
                Instant to = b.firstTimestamp();
                if (from != null && to != null) {
                    long ms = Math.max(0L, to.toEpochMilli() - from.toEpochMilli());
                    timingSamples.computeIfAbsent(key(a.callSite(), b.callSite()),
                            k -> new ArrayList<>()).add(ms);
                }
            }
        }

        List<Baseline.TransitionTiming> timings = new ArrayList<>();
        for (Map.Entry<String, List<Long>> en : timingSamples.entrySet()) {
            String[] fromTo = en.getKey().split("", 2);
            List<Long> samples = en.getValue();
            samples.sort(Long::compareTo);
            timings.add(new Baseline.TransitionTiming(
                    fromTo[0], fromTo[1], samples.size(),
                    percentile(samples, 50), percentile(samples, 95)));
        }
        timings.sort(Comparator.comparing(Baseline.TransitionTiming::from)
                .thenComparing(Baseline.TransitionTiming::to));

        return new Baseline(cluster.signature(), used.size(), modalSequence, modalShare,
                modalCount, alternatives, positional, transitionCounts, timings);
    }

    private static List<Baseline.PositionOption> toOptions(Map<String, Long> counts, long reached) {
        List<Baseline.PositionOption> opts = new ArrayList<>();
        for (Map.Entry<String, Long> en : counts.entrySet()) {
            opts.add(new Baseline.PositionOption(en.getKey(), en.getValue(),
                    reached == 0 ? 0.0 : (double) en.getValue() / reached));
        }
        opts.sort(Comparator.comparingLong(Baseline.PositionOption::count).reversed()
                .thenComparing(Baseline.PositionOption::callSite));
        return opts;
    }

    private static String key(String from, String to) {
        return from + "" + to;
    }

    /** Nearest-rank percentile over a sorted ascending list. {@code p} in [0,100]. */
    static double percentile(List<Long> sortedAscending, double p) {
        if (sortedAscending.isEmpty()) {
            return 0.0;
        }
        int n = sortedAscending.size();
        int rank = (int) Math.ceil(p / 100.0 * n);
        rank = Math.max(1, Math.min(rank, n));
        return sortedAscending.get(rank - 1);
    }
}
