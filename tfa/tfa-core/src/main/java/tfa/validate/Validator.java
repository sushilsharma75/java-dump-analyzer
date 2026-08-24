package tfa.validate;

import tfa.Analysis;
import tfa.config.AnalysisConfig;
import tfa.detect.DetectionResult;
import tfa.model.Finding;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Checks the pipeline output against recorded ground truth (§6): for each known
 * defect, does it appear in the findings at all, and at what rank. The success
 * test passes when every defect appears within the top N.
 */
public final class Validator {

    private final Analysis.Result result;
    private final AnalysisConfig config;
    private final RankIndex rankIndex;
    private final Explainer explainer;

    public Validator(Analysis.Result result, AnalysisConfig config) {
        this.result = result;
        this.config = config;
        this.rankIndex = new RankIndex(result.ranking());
        this.explainer = new Explainer(result, config);
    }

    /** Outcome for one defect. {@code rank} is 1-based report rank, null if not found. */
    public record DefectOutcome(String id, String description, boolean found, Integer rank,
                                String type, String note) {
        public boolean withinTop(int topN) {
            return found && rank != null && rank <= topN;
        }
    }

    public record ValidationReport(List<DefectOutcome> outcomes, int topN) {
        public long passed() {
            return outcomes.stream().filter(o -> o.withinTop(topN)).count();
        }

        public boolean allPassed() {
            return !outcomes.isEmpty() && passed() == outcomes.size();
        }
    }

    public ValidationReport validate(GroundTruth truth) {
        List<DefectOutcome> outcomes = new ArrayList<>();
        for (GroundTruth.Defect defect : truth.defects()) {
            outcomes.add(evaluate(defect));
        }
        return new ValidationReport(outcomes, config.ranking().topN());
    }

    private DefectOutcome evaluate(GroundTruth.Defect defect) {
        // gather raw findings whose episode matches the defect's thread + window
        record Candidate(Finding finding, String clusterSignature) {}
        List<Candidate> candidates = new ArrayList<>();
        for (DetectionResult.ClusterFindings cf : result.detection().perCluster()) {
            String sig = cf.cluster().signature();
            for (Finding f : cf.findings()) {
                if (defect.threadId().equals(f.episode().threadId())
                        && defect.contains(f.episode().start())) {
                    candidates.add(new Candidate(f, sig));
                }
            }
        }

        // prefer candidates at the expected divergence call site
        String expected = defect.expectedDivergenceCallSite();
        boolean atDifferentCallSite = false;
        if (expected != null && !candidates.isEmpty()) {
            List<Candidate> matching = candidates.stream()
                    .filter(c -> expected.equals(c.finding().divergenceCallSite()))
                    .toList();
            if (!matching.isEmpty()) {
                candidates = new ArrayList<>(matching);
            } else {
                atDifferentCallSite = true;
            }
        }

        if (candidates.isEmpty()) {
            // not detected at all — explain precisely why
            Instant at = defect.windowStart() != null ? defect.windowStart()
                    : (defect.windowEnd() != null ? defect.windowEnd() : Instant.now());
            Explainer.Trace trace = explainer.explain(defect.threadId(), at);
            return new DefectOutcome(defect.id(), defect.description(), false, null, null,
                    "not detected - " + trace.outcome());
        }

        Integer bestRank = null;
        String type = null;
        boolean anySuppressed = false;
        for (Candidate c : candidates) {
            Integer rank = rankIndex.rankOf(c.finding(), c.clusterSignature());
            if (rank == null) {
                anySuppressed |= rankIndex.isSuppressed(c.finding(), c.clusterSignature());
                continue;
            }
            if (bestRank == null || rank < bestRank) {
                bestRank = rank;
                type = c.finding().type().name();
            }
        }

        if (bestRank == null) {
            String note = anySuppressed ? "detected but suppressed" : "detected but not ranked";
            return new DefectOutcome(defect.id(), defect.description(), false, null, null, note);
        }

        StringBuilder note = new StringBuilder();
        note.append(bestRank <= config.ranking().topN() ? "in top " + config.ranking().topN()
                : "ranked but below top " + config.ranking().topN());
        if (atDifferentCallSite) {
            note.append("; note: found at a different call site than expected");
        }
        return new DefectOutcome(defect.id(), defect.description(), true, bestRank, type, note.toString());
    }
}
