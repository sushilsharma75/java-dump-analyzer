package tfa.detect;

import tfa.model.Episode;

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
