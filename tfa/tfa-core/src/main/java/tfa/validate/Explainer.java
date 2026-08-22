package tfa.validate;

import tfa.Analysis;
import tfa.baseline.ConsensusBuilder;
import tfa.config.AnalysisConfig;
import tfa.detect.Censor;
import tfa.detect.DivergenceDetector;
import tfa.detect.TimingDetector;
import tfa.detect.TruncationDetector;
import tfa.model.Baseline;
import tfa.model.Episode;
import tfa.model.Finding;
import tfa.model.FlowCluster;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Produces the full reasoning trail for one episode: which cluster it landed in,
 * the baseline modal sequence, its own sequence, where they diverged, what each
 * detector scored, and — if it was not reported — precisely which threshold
 * excluded it. The debugging tool for when validation fails.
 */
public final class Explainer {

    private final Analysis.Result result;
    private final AnalysisConfig config;
    private final Censor censor;
    private final RankIndex rankIndex;

    public Explainer(Analysis.Result result, AnalysisConfig config) {
        this.result = result;
        this.config = config;
        this.censor = new Censor(result.detection().corpusStart(),
                result.detection().corpusEnd(), result.detection().marginMillis());
        this.rankIndex = new RankIndex(result.ranking());
    }

    /** The outcome and the human-readable reasoning trail for a target episode. */
    public record Trace(boolean episodeFound, String outcome, Integer reportedRank, List<String> lines) {}

    /** Locate the episode on {@code threadId} live at {@code at} (containing it, else nearest start). */
    public Optional<Located> locate(String threadId, Instant at) {
        Located best = null;
        long bestDelta = Long.MAX_VALUE;
        for (FlowCluster cluster : result.clusters()) {
            for (Episode e : cluster.episodes()) {
                if (!threadId.equals(e.threadId())) {
                    continue;
                }
                Instant s = e.start();
                Instant en = e.end();
                if (s != null && en != null && !at.isBefore(s) && !at.isAfter(en)) {
                    return Optional.of(new Located(cluster, e));   // exact containment
                }
                if (s != null) {
                    long delta = Math.abs(Duration.between(s, at).toMillis());
                    if (delta < bestDelta) {
                        bestDelta = delta;
                        best = new Located(cluster, e);
                    }
                }
            }
        }
        return Optional.ofNullable(best);
    }

    public record Located(FlowCluster cluster, Episode episode) {}

    public Trace explain(String threadId, Instant at) {
        List<String> lines = new ArrayList<>();
        Optional<Located> located = locate(threadId, at);
        if (located.isEmpty()) {
            String outcome = "no episode found for thread " + threadId + " at " + at;
            lines.add(outcome);
            return new Trace(false, outcome, null, lines);
        }

        FlowCluster cluster = located.get().cluster();
        Episode episode = located.get().episode();

        lines.add("episode           : thread=" + episode.threadId()
                + "  start=" + episode.start() + "  end=" + episode.end()
                + "  status=" + episode.status());
        lines.add("cluster           : " + cluster.signature()
                + "  (size " + cluster.size() + (cluster.isUnderSampled() ? ", UNDER_SAMPLED)" : ")"));
        lines.add("own sequence      : " + String.join(" -> ", episode.collapsedSequence()));

        boolean censored = censor.isCensored(episode);
        boolean inEvalWindow = config.baseline().inEvalWindow(episode.start());

        // gate reasons that stop an episode from ever being a finding
        if (cluster.isUnderSampled()) {
            lines.add("baseline          : none (cluster is UNDER_SAMPLED; excluded from baselining)");
            String outcome = "NOT REPORTED - cluster under-sampled (size " + cluster.size()
                    + " < minClusterSize " + config.clustering().minClusterSize() + ")";
            lines.add(outcome);
            return new Trace(true, outcome, null, lines);
        }

        Baseline baseline = ConsensusBuilder.build(cluster, config.baseline());
        if (baseline == null) {
            String outcome = "NOT REPORTED - no baseline could be built in the baseline window";
            lines.add(outcome);
            return new Trace(true, outcome, null, lines);
        }
        lines.add("baseline modal    : " + String.format("%.0f%%  ", baseline.modalShare() * 100)
                + String.join(" -> ", baseline.modalSequence()));

        // run each detector to show what it scores (independent of the gates)
        List<Finding> fired = new ArrayList<>();
        explainDetector(lines, "truncation", new TruncationDetector().detect(episode, baseline), fired,
                () -> "reached the modal terminal and completed");
        explainDetector(lines, "divergence", new DivergenceDetector().detect(episode, baseline), fired,
                () -> "sequence matches the modal path (or is a prefix, which truncation owns)");
        explainDetector(lines, "timing",
                new TimingDetector(config.detection().timingFactor()).detect(episode, baseline), fired,
                () -> "every transition is within p95 x " + config.detection().timingFactor());

        // now the gates, in the order the engine applies them
        if (!inEvalWindow) {
            String outcome = "NOT REPORTED - episode start is outside the evaluation window";
            lines.add(outcome);
            return new Trace(true, outcome, null, lines);
        }
        if (censored) {
            String outcome = "NOT REPORTED - CENSORED: episode overlaps the "
                    + result.detection().marginMillis() + "ms corpus-boundary margin (section 3.5)";
            lines.add(outcome);
            return new Trace(true, outcome, null, lines);
        }
        if (fired.isEmpty()) {
            String outcome = "NOT REPORTED - no detector fired (this episode matches the consensus)";
            lines.add(outcome);
            return new Trace(true, outcome, null, lines);
        }

        // reported: find the best (lowest) rank among the fired findings
        Integer bestRank = null;
        Finding bestFinding = null;
        for (Finding f : fired) {
            Integer rank = rankIndex.rankOf(f, cluster.signature());
            if (rank != null && (bestRank == null || rank < bestRank)) {
                bestRank = rank;
                bestFinding = f;
            }
        }
        if (bestRank == null) {
            // fired but not in the ranked non-suppressed list -> suppressed
            String reason = rankIndex.suppressionReason(fired.get(0), cluster.signature());
            String outcome = "DETECTED but SUPPRESSED"
                    + (reason == null ? "" : " (" + reason + ")");
            lines.add(outcome);
            return new Trace(true, outcome, null, lines);
        }
        String outcome = "REPORTED at rank #" + bestRank + " as " + bestFinding.type();
        lines.add(outcome);
        return new Trace(true, outcome, bestRank, lines);
    }

    private void explainDetector(List<String> lines, String name, List<Finding> findings,
                                 List<Finding> firedAccumulator, java.util.function.Supplier<String> quietReason) {
        if (findings.isEmpty()) {
            lines.add(String.format("  %-11s: no finding - %s", name, quietReason.get()));
        } else {
            firedAccumulator.addAll(findings);
            for (Finding f : findings) {
                lines.add(String.format("  %-11s: FIRED rawScore=%.3f at %s (expected %s %.0f%%, observed %s)",
                        name, f.rawScore(), f.divergenceCallSite(),
                        f.expectedCallSite(), f.expectedShare() * 100, f.observed()));
            }
        }
    }
}
