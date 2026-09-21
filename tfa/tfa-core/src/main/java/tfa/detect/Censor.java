package tfa.detect;

import tfa.model.Episode;
import tfa.model.TerminalStatus;

import java.time.Instant;

/**
 * Corpus-boundary censoring (§3.5). The dump starts and ends mid-traffic:
 * episodes in flight at the corpus end look TRUNCATED but are merely cut off, and
 * episodes whose beginning predates the corpus fail entry-matching. Episodes
 * overlapping a margin (default: one p99 episode duration) of the corpus start or
 * end are CENSORED — usable for baselining up to their cut, never eligible as
 * findings. Without this, a run's top findings would just be the last requests in
 * flight when the dump was taken.
 */
public final class Censor {

    private final Instant corpusStart;
    private final Instant corpusEnd;
    private final long marginMillis;

    public Censor(Instant corpusStart, Instant corpusEnd, long marginMillis) {
        this.corpusStart = corpusStart;
        this.corpusEnd = corpusEnd;
        this.marginMillis = Math.max(0L, marginMillis);
    }

    public long marginMillis() { return marginMillis; }

    public boolean isCensored(Episode episode) {
        // A COMPLETED episode reached its modal terminal, so it is whole — it was
        // not cut off by the dump boundary, even if it sits near the edge. Only
        // potentially-cut-off episodes (not COMPLETED) are censoring candidates.
        // This stops a slow-but-complete flow near the boundary from being hidden,
        // and stops a single slow outlier's inflated p99-duration margin from
        // censoring legitimate flows (§3.5).
        if (episode.status() == TerminalStatus.COMPLETED) {
            return false;
        }
        Instant start = episode.start();
        Instant end = episode.end();
        if (corpusStart != null && start != null
                && !start.isAfter(corpusStart.plusMillis(marginMillis))) {
            return true;   // began within the leading margin
        }
        return corpusEnd != null && end != null
                && !end.isBefore(corpusEnd.minusMillis(marginMillis)); // ended within the trailing margin
    }
}
