package tfa.rank;

import tfa.config.RankingConfig;
import tfa.detect.DetectionResult;
import tfa.model.Episode;
import tfa.model.Finding;
import tfa.model.FindingType;
import tfa.model.TerminalStatus;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Deduplicates, scores and orders findings. Deduplication collapses many episodes
 * that deviated the same way at the same call site into one finding with an
 * occurrence count. Scoring combines rarity, severity, error presence, timing
 * magnitude and cluster-size trust with configurable weights.
 *
 * <p>The critical guard: a rare path that completes normally is a variant, not a
 * defect — so a DIVERGENCE whose episode completed with no error is damped by the
 * benign-variant penalty. Rarity alone is a false-positive firehose.
 *
 * <p>Output is deterministic: ties break on score, then cluster signature, then
 * call site, then index, then representative thread and timestamp.
 */
public final class FindingRanker {

    private final RankingConfig config;
    private final Suppressions suppressions;

    public FindingRanker(RankingConfig config, Suppressions suppressions) {
        this.config = config;
        this.suppressions = suppressions;
    }

    /** All findings ranked (sorted), the non-suppressed top N, and how many were suppressed. */
    public record RankingResult(List<RankedFinding> ranked, List<RankedFinding> top, int suppressedCount) {}

    private static final class Group {
        final String clusterSignature;
        final int clusterSize;
        final List<Finding> findings = new ArrayList<>();
        Group(String sig, int size) { this.clusterSignature = sig; this.clusterSize = size; }
    }

    public RankingResult rank(DetectionResult detection) {
        // 1. DEDUP by (clusterSignature, type, index, divergence call site, expected call site)
        Map<String, Group> groups = new LinkedHashMap<>();
        for (DetectionResult.ClusterFindings cf : detection.perCluster()) {
            String sig = cf.cluster().signature();
            int size = cf.cluster().size();
            for (Finding f : cf.findings()) {
                groups.computeIfAbsent(f.dedupeKey(sig), k -> new Group(sig, size)).findings.add(f);
            }
        }

        // 2. SCORE each group
        List<RankedFinding> ranked = new ArrayList<>(groups.size());
        for (Group g : groups.values()) {
            Finding rep = representative(g.findings);
            long occurrences = g.findings.size();
            ScoreBreakdown breakdown = score(rep, occurrences, g.clusterSize);
            RankedFinding rf = new RankedFinding(rep, g.clusterSignature, g.clusterSize,
                    occurrences, breakdown.total(), breakdown, false, null);
            String reason = suppressions.reasonFor(rf);
            ranked.add(reason == null ? rf : rf.withSuppression(reason));
        }

        // 3. SORT deterministically
        ranked.sort(RANKING_ORDER);

        // 4. TOP N of the non-suppressed
        List<RankedFinding> top = new ArrayList<>();
        int suppressed = 0;
        for (RankedFinding rf : ranked) {
            if (rf.suppressed()) {
                suppressed++;
            } else if (top.size() < config.topN()) {
                top.add(rf);
            }
        }
        return new RankingResult(ranked, top, suppressed);
    }

    /** Worst (highest rawScore) finding in the group, tie-broken deterministically. */
    private static Finding representative(List<Finding> findings) {
        return findings.stream().min(Comparator
                .comparingDouble((Finding f) -> -f.rawScore())
                .thenComparing(f -> f.episode().threadId(), Comparator.nullsLast(String::compareTo))
                .thenComparing(f -> startOf(f.episode()), Comparator.nullsLast(Instant::compareTo)))
                .orElseThrow();
    }

    private ScoreBreakdown score(Finding rep, long occurrences, int clusterSize) {
        double rarity = clusterSize <= 0 ? 0.0
                : clamp01(1.0 - (double) occurrences / clusterSize);
        double severity = switch (rep.type()) {
            case TRUNCATION -> 1.0;
            case DIVERGENCE -> 0.6;
            case TIMING -> 0.3;
        };
        Episode e = rep.episode();
        double errorPresence = (e.hasErrorRecord() || e.hasStackTrace()) ? 1.0 : 0.0;
        double magnitude = rep.type() == FindingType.TIMING
                ? clamp01(Math.log10(Math.max(1.0, rep.rawScore())) / 2.0) : 0.0;
        double clusterTrust = clamp01(Math.log10(Math.max(1, clusterSize)) / 3.0);

        // benign variant: a wrong branch that still completed cleanly is a variant
        boolean benignVariant = rep.type() == FindingType.DIVERGENCE
                && e.status() == TerminalStatus.COMPLETED
                && !e.hasErrorRecord() && !e.hasStackTrace();
        double variantPenalty = benignVariant ? config.benignVariantPenalty() : 1.0;

        double weighted = config.rarityWeight() * rarity
                + config.severityWeight() * severity
                + config.errorWeight() * errorPresence
                + config.magnitudeWeight() * magnitude
                + config.clusterSizeWeight() * clusterTrust;
        double total = variantPenalty * weighted;

        return new ScoreBreakdown(rarity, severity, errorPresence, magnitude,
                clusterTrust, variantPenalty, total);
    }

    private static final Comparator<RankedFinding> RANKING_ORDER = Comparator
            .comparingDouble((RankedFinding r) -> -r.score())
            .thenComparing(RankedFinding::clusterSignature, Comparator.nullsLast(String::compareTo))
            .thenComparing(r -> nullToEmpty(r.representative().divergenceCallSite()))
            .thenComparingInt(r -> r.representative().divergenceIndex())
            .thenComparing(r -> nullToEmpty(r.representative().episode().threadId()))
            .thenComparing(r -> startOf(r.representative().episode()),
                    Comparator.nullsLast(Instant::compareTo));

    private static Instant startOf(Episode e) {
        return e == null ? null : e.start();
    }

    private static String nullToEmpty(String s) {
        return s == null ? "" : s;
    }

    private static double clamp01(double v) {
        return Math.max(0.0, Math.min(1.0, v));
    }
}
