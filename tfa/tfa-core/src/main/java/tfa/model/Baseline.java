package tfa.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

/**
 * The consensus (what "normal" looks like) for one {@link FlowCluster}, computed
 * over collapsed call-site sequences. The population is the baseline — no golden
 * path is authored.
 */
public final class Baseline {

    /** A distinct sequence shape and the share of episodes matching it exactly. */
    public record SequenceShare(List<String> sequence, long count, double share) {}

    /** A call site observed at a modal position, with how often and its share. */
    public record PositionOption(String callSite, long count, double share) {}

    /** Median and p95 elapsed time for one collapsed transition A -> B. */
    public record TransitionTiming(String from, String to, long count,
                                   double medianMillis, double p95Millis) {}

    private final String clusterSignature;
    private final int episodesUsed;
    private final List<String> modalSequence;
    private final double modalShare;
    private final long modalCount;
    private final List<SequenceShare> alternatives;
    private final List<List<PositionOption>> positional;       // aligned to modalSequence
    private final Map<String, Map<String, Long>> transitionCounts;
    private final List<TransitionTiming> transitionTimings;

    public Baseline(String clusterSignature, int episodesUsed, List<String> modalSequence,
                    double modalShare, long modalCount, List<SequenceShare> alternatives,
                    List<List<PositionOption>> positional,
                    Map<String, Map<String, Long>> transitionCounts,
                    List<TransitionTiming> transitionTimings) {
        this.clusterSignature = clusterSignature;
        this.episodesUsed = episodesUsed;
        this.modalSequence = List.copyOf(modalSequence);
        this.modalShare = modalShare;
        this.modalCount = modalCount;
        this.alternatives = List.copyOf(alternatives);
        this.positional = List.copyOf(positional);
        this.transitionCounts = Map.copyOf(transitionCounts);
        this.transitionTimings = List.copyOf(transitionTimings);
    }

    public String clusterSignature()          { return clusterSignature; }
    public int episodesUsed()                 { return episodesUsed; }
    public List<String> modalSequence()       { return modalSequence; }
    public double modalShare()                { return modalShare; }
    public long modalCount()                  { return modalCount; }
    public List<SequenceShare> alternatives() { return alternatives; }

    /** Terminal call site of the modal sequence, or null if the modal sequence is empty. */
    public String modalTerminal() {
        return modalSequence.isEmpty() ? null : modalSequence.get(modalSequence.size() - 1);
    }

    /** Options observed at position {@code i} of the modal sequence, most frequent first. */
    public List<PositionOption> positionOptions(int i) {
        return (i < 0 || i >= positional.size()) ? List.of() : positional.get(i);
    }

    /** The majority call site expected at position {@code i}, or null if out of range. */
    public PositionOption expectedAt(int i) {
        List<PositionOption> opts = positionOptions(i);
        return opts.isEmpty() ? null : opts.get(0);
    }

    /** P(B follows A) within this cluster, over collapsed transitions. */
    public double transitionProbability(String from, String to) {
        Map<String, Long> outgoing = transitionCounts.get(from);
        if (outgoing == null || outgoing.isEmpty()) {
            return 0.0;
        }
        long total = outgoing.values().stream().mapToLong(Long::longValue).sum();
        return total == 0 ? 0.0 : (double) outgoing.getOrDefault(to, 0L) / total;
    }

    public List<TransitionTiming> transitionTimings() { return transitionTimings; }

    /** The {@code n} slowest transitions by p95. */
    public List<TransitionTiming> slowestByP95(int n) {
        List<TransitionTiming> sorted = new ArrayList<>(transitionTimings);
        sorted.sort(Comparator.comparingDouble(TransitionTiming::p95Millis).reversed());
        return sorted.subList(0, Math.min(n, sorted.size()));
    }

    /** Timing for a specific transition, or null if never observed with valid timestamps. */
    public TransitionTiming timingFor(String from, String to) {
        for (TransitionTiming t : transitionTimings) {
            if (t.from().equals(from) && t.to().equals(to)) {
                return t;
            }
        }
        return null;
    }
}
