package tfa.ingest;

import java.util.List;

/**
 * Result of sampling a corpus to decide whether a profile fits it (§3.4,
 * "fail fast on mismatch"). The rate excludes continuation lines, which
 * legitimately do not match the envelope; it is {@code matched / (matched +
 * malformed)}.
 */
public record MatchRateReport(
        long sampledLines,
        long matched,
        long continuation,
        long malformed,
        double rate,
        List<ParseStats.MalformedLine> failures
) {
    public boolean meets(double threshold) {
        return rate >= threshold;
    }
}
