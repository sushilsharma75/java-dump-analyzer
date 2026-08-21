package tfa.ingest;

/**
 * Thrown when a corpus sample falls below the configured match-rate threshold.
 * Carries the report so callers can print the failing lines rather than silently
 * analysing a fraction of the corpus.
 */
public final class MatchRateException extends RuntimeException {

    private final transient MatchRateReport report;
    private final double threshold;

    public MatchRateException(MatchRateReport report, double threshold) {
        super(String.format(
                "match rate %.2f%% is below threshold %.2f%% (matched=%d, malformed=%d of %d sampled lines)",
                report.rate() * 100, threshold * 100,
                report.matched(), report.malformed(), report.sampledLines()));
        this.report = report;
        this.threshold = threshold;
    }

    public MatchRateReport report()   { return report; }
    public double threshold()         { return threshold; }
}
