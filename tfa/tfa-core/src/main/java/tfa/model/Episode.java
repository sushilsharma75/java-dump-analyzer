package tfa.model;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * One contiguous execution of one flow on one thread. A pooled thread runs
 * request after request, so {@code exec-7} at 14:32 and {@code exec-7} at 14:35
 * are different episodes — segmenting the per-thread record stream into episodes
 * is what the {@link tfa.segment.FlowKeyStrategy} does.
 *
 * <p>Mutable during construction (records are appended as the stream advances),
 * then read-only in practice. Downstream code must not depend on which strategy
 * produced the episode.
 */
public final class Episode {

    private final String threadId;
    private final List<LogRecord> records = new ArrayList<>();
    private TerminalStatus status = TerminalStatus.TRUNCATED;
    private boolean hasErrorRecord;

    // cached derived views, invalidated on append
    private List<String> callSiteSequenceCache;
    private List<Run> collapsedRunsCache;
    private List<String> collapsedSequenceCache;

    public Episode(String threadId) {
        this.threadId = threadId;
    }

    /** Append a record to this episode, in stream order. */
    public void add(LogRecord record) {
        records.add(record);
        callSiteSequenceCache = null;
        collapsedRunsCache = null;
        collapsedSequenceCache = null;
        if ("ERROR".equalsIgnoreCase(record.level())) {
            hasErrorRecord = true;
        }
    }

    public void setStatus(TerminalStatus status) {
        this.status = status;
    }

    public String threadId() { return threadId; }

    public Instant start() {
        return records.isEmpty() ? null : records.get(0).timestamp();
    }

    public Instant end() {
        return records.isEmpty() ? null : records.get(records.size() - 1).timestamp();
    }

    public List<LogRecord> records() {
        return Collections.unmodifiableList(records);
    }

    public int size() { return records.size(); }

    public boolean isEmpty() { return records.isEmpty(); }

    public TerminalStatus status() { return status; }

    /** True if any record in the episode is ERROR level (a ranking input). */
    public boolean hasErrorRecord() { return hasErrorRecord; }

    /** True if any record carries a stack trace. */
    public boolean hasStackTrace() {
        for (LogRecord r : records) {
            if (r.hasStackTrace()) {
                return true;
            }
        }
        return false;
    }

    /** Ordered {@code callSite()} values. Null call sites (fallback mode) are skipped. */
    public List<String> callSiteSequence() {
        if (callSiteSequenceCache == null) {
            List<String> seq = new ArrayList<>(records.size());
            for (LogRecord r : records) {
                String cs = r.callSite();
                if (cs != null) {
                    seq.add(cs);
                }
            }
            callSiteSequenceCache = Collections.unmodifiableList(seq);
        }
        return callSiteSequenceCache;
    }

    /**
     * One collapsed run: a maximal block of consecutive records at the same call
     * site, carrying the repeat count and the first/last timestamps of the block.
     */
    public record Run(String callSite, int count, Instant firstTimestamp, Instant lastTimestamp) {}

    /**
     * The episode's records with consecutive repeats of the same call site
     * collapsed into a single {@link Run} carrying a repeat count. Without this,
     * a retry loop makes edit distance explode and swamps the ranking (§Phase 4).
     * Null call sites (fallback mode) are skipped.
     */
    public List<Run> collapsedRuns() {
        if (collapsedRunsCache == null) {
            List<Run> runs = new ArrayList<>();
            String curCs = null;
            int count = 0;
            Instant first = null;
            Instant last = null;
            for (LogRecord r : records) {
                String cs = r.callSite();
                if (cs == null) {
                    continue;
                }
                if (cs.equals(curCs)) {
                    count++;
                    last = r.timestamp();
                } else {
                    if (curCs != null) {
                        runs.add(new Run(curCs, count, first, last));
                    }
                    curCs = cs;
                    count = 1;
                    first = r.timestamp();
                    last = r.timestamp();
                }
            }
            if (curCs != null) {
                runs.add(new Run(curCs, count, first, last));
            }
            collapsedRunsCache = Collections.unmodifiableList(runs);
        }
        return collapsedRunsCache;
    }

    /**
     * The collapsed call-site shape: {@link #collapsedRuns()} reduced to the
     * ordered list of call sites (repeat counts dropped). This is what baselining
     * and comparison operate on.
     */
    public List<String> collapsedSequence() {
        if (collapsedSequenceCache == null) {
            List<String> seq = new ArrayList<>();
            for (Run run : collapsedRuns()) {
                seq.add(run.callSite());
            }
            collapsedSequenceCache = Collections.unmodifiableList(seq);
        }
        return collapsedSequenceCache;
    }

    @Override
    public String toString() {
        return "Episode[thread=" + threadId + ", status=" + status
                + ", size=" + records.size() + ", start=" + start() + "]";
    }
}
