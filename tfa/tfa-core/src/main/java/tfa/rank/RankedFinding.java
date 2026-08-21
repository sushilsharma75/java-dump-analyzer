package tfa.rank;

import tfa.model.Finding;

/**
 * A deduplicated, scored finding: one representative {@link Finding} standing for
 * {@code occurrences} episodes that deviated the same way at the same call site,
 * with its cluster context and score breakdown.
 */
public record RankedFinding(
        Finding representative,
        String clusterSignature,
        int clusterSize,
        long occurrences,
        double score,
        ScoreBreakdown breakdown,
        boolean suppressed,
        String suppressionReason
) {
    public RankedFinding withSuppression(String reason) {
        return new RankedFinding(representative, clusterSignature, clusterSize, occurrences,
                score, breakdown, true, reason);
    }
}
