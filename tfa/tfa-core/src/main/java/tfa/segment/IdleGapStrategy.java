package tfa.segment;

import tfa.model.Episode;
import tfa.model.LogRecord;
import tfa.model.TerminalStatus;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Segments by idle time (Impl B). A new episode begins when the gap since the
 * previous record on the same thread exceeds a configurable threshold. Boundaries
 * are purely gap-based; a terminal call site does not close an episode, it only
 * decides status: COMPLETED if a configured terminal was reached, otherwise
 * TRUNCATED. An ERROR-level record makes the episode ERRORED.
 *
 * <p>Use when entry markers do not separate cleanly (the Phase 0 verdict). The
 * threshold is chosen from the inter-record gap histogram — the valley between
 * intra-episode gaps and inter-episode idle time.
 */
public final class IdleGapStrategy implements FlowKeyStrategy {

    private final long idleGapMillis;
    private final Set<String> terminalCallSites;

    public IdleGapStrategy(long idleGapMillis, Set<String> terminalCallSites) {
        this.idleGapMillis = idleGapMillis;
        this.terminalCallSites = Set.copyOf(terminalCallSites);
    }

    @Override
    public String name() { return "IDLE_GAP"; }

    @Override
    public ThreadSegmenter newThreadSegmenter(String threadId) {
        return new Segmenter(threadId);
    }

    private boolean isTerminal(String cs) {
        return cs != null && terminalCallSites.contains(cs);
    }

    private final class Segmenter implements ThreadSegmenter {
        private final String threadId;
        private Episode open;
        private Instant lastTs;
        private boolean terminalReached;

        Segmenter(String threadId) { this.threadId = threadId; }

        @Override
        public List<Episode> accept(LogRecord r) {
            List<Episode> out = new ArrayList<>(1);
            Instant ts = r.timestamp();

            if (open == null) {
                startNew(r, ts);
                return out;
            }

            long gapMillis = gap(lastTs, ts);
            if (gapMillis > idleGapMillis) {
                out.add(close(open));
                startNew(r, ts);
            } else {
                open.add(r);
                if (isTerminal(r.callSite())) {
                    terminalReached = true;
                }
                if (ts != null) {
                    lastTs = ts;
                }
            }
            return out;
        }

        @Override
        public Optional<Episode> finish() {
            if (open != null) {
                Episode e = close(open);
                open = null;
                return Optional.of(e);
            }
            return Optional.empty();
        }

        private void startNew(LogRecord r, Instant ts) {
            open = new Episode(threadId);
            open.add(r);
            terminalReached = isTerminal(r.callSite());
            lastTs = ts;
        }

        private Episode close(Episode e) {
            TerminalStatus base = terminalReached ? TerminalStatus.COMPLETED : TerminalStatus.TRUNCATED;
            e.setStatus(e.hasErrorRecord() ? TerminalStatus.ERRORED : base);
            return e;
        }

        /** Gap in millis; 0 when either timestamp is missing (cannot reorder). */
        private long gap(Instant prev, Instant cur) {
            if (prev == null || cur == null) {
                return 0L;
            }
            long ms = cur.toEpochMilli() - prev.toEpochMilli();
            return Math.max(ms, 0L);
        }
    }
}
