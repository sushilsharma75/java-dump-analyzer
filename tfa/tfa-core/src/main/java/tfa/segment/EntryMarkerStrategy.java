package tfa.segment;

import tfa.model.Episode;
import tfa.model.LogRecord;
import tfa.model.TerminalStatus;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Segments by explicit entry/terminal call sites (Impl A). A new episode begins
 * at an entry call site; it ends at a terminal call site (COMPLETED) or when the
 * next entry call site appears (TRUNCATED). An episode containing an ERROR-level
 * record is ERRORED.
 *
 * <p>Records that appear on a thread before its first entry call site belong to
 * no episode and are dropped (they are the tail of an episode whose start
 * predates the corpus — a censoring concern handled downstream, not a new
 * episode).
 */
public final class EntryMarkerStrategy implements FlowKeyStrategy {

    private final Set<String> entryCallSites;
    private final Set<String> terminalCallSites;

    public EntryMarkerStrategy(Set<String> entryCallSites, Set<String> terminalCallSites) {
        this.entryCallSites = Set.copyOf(entryCallSites);
        this.terminalCallSites = Set.copyOf(terminalCallSites);
    }

    @Override
    public String name() { return "ENTRY_MARKER"; }

    @Override
    public ThreadSegmenter newThreadSegmenter(String threadId) {
        return new Segmenter(threadId);
    }

    private boolean isEntry(String cs)    { return cs != null && entryCallSites.contains(cs); }
    private boolean isTerminal(String cs) { return cs != null && terminalCallSites.contains(cs); }

    private final class Segmenter implements ThreadSegmenter {
        private final String threadId;
        private Episode open;

        Segmenter(String threadId) { this.threadId = threadId; }

        @Override
        public List<Episode> accept(LogRecord r) {
            String cs = r.callSite();
            List<Episode> out = new ArrayList<>(2);

            if (open != null && isEntry(cs)) {
                // a new entry cuts off the current episode as TRUNCATED
                out.add(close(open, TerminalStatus.TRUNCATED));
                open = start(r);
                if (isTerminal(cs)) {
                    out.add(close(open, TerminalStatus.COMPLETED));
                    open = null;
                }
                return out;
            }

            if (open != null) {
                open.add(r);
                if (isTerminal(cs)) {
                    out.add(close(open, TerminalStatus.COMPLETED));
                    open = null;
                }
                return out;
            }

            // no open episode
            if (isEntry(cs)) {
                open = start(r);
                if (isTerminal(cs)) {
                    out.add(close(open, TerminalStatus.COMPLETED));
                    open = null;
                }
            }
            // else: leading non-entry record → dropped
            return out;
        }

        @Override
        public Optional<Episode> finish() {
            if (open != null) {
                Episode e = close(open, TerminalStatus.TRUNCATED);
                open = null;
                return Optional.of(e);
            }
            return Optional.empty();
        }

        private Episode start(LogRecord r) {
            Episode e = new Episode(threadId);
            e.add(r);
            return e;
        }

        private Episode close(Episode e, TerminalStatus base) {
            e.setStatus(e.hasErrorRecord() ? TerminalStatus.ERRORED : base);
            return e;
        }
    }
}
