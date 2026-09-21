package tfa.segment;

import tfa.model.Episode;
import tfa.model.LogRecord;
import tfa.model.TerminalStatus;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Segments by a correlation id carried in the log (Impl C).
 *
 * <p>One flow = every record sharing a correlation id, regardless of which thread
 * or which service emitted it. This is what makes a cross-service flow
 * (order &rarr; inventory &rarr; payment) a single episode, which per-thread
 * segmentation cannot see.
 *
 * <p>{@code pattern} is a regex applied to each record's message with the id in
 * group 1, e.g. {@code trace_id=([0-9a-f]+)}. Records with no match are dropped.
 *
 * <p>Memory note: one open flow is held per in-flight correlation id until the
 * stream ends, so this is bounded by concurrent flows rather than being fully
 * streaming. Fine for batch analysis; revisit for very large corpora.
 */
public final class CorrelationIdStrategy implements FlowKeyStrategy {

    private final Pattern pattern;
    private final Set<String> terminalCallSites;

    public CorrelationIdStrategy(String pattern, Set<String> terminalCallSites) {
        if (pattern == null || pattern.isBlank()) {
            throw new IllegalArgumentException(
                    "CORRELATION_ID strategy requires segmentation.correlationIdPattern, "
                            + "e.g. 'trace_id=([0-9a-f]+)'");
        }
        this.pattern = Pattern.compile(pattern);
        this.terminalCallSites = Set.copyOf(terminalCallSites);
    }

    @Override
    public String name() { return "CORRELATION_ID"; }

    @Override
    public String groupingKey(LogRecord record) {
        String msg = record.message();
        if (msg == null) {
            return null;
        }
        Matcher m = pattern.matcher(msg);
        if (!m.find()) {
            return null;
        }
        return m.groupCount() >= 1 ? m.group(1) : m.group();
    }

    @Override
    public ThreadSegmenter newThreadSegmenter(String correlationId) {
        return new Segmenter(correlationId);
    }

    /**
     * Accumulates every record carrying one correlation id, across threads and
     * services, and emits a single time-ordered episode at end of stream.
     */
    private final class Segmenter implements ThreadSegmenter {
        private final String correlationId;
        private final List<LogRecord> records = new ArrayList<>();

        Segmenter(String correlationId) { this.correlationId = correlationId; }

        @Override
        public List<Episode> accept(LogRecord record) {
            records.add(record);
            return List.of();      // a correlated flow has no mid-stream boundary
        }

        @Override
        public Optional<Episode> finish() {
            if (records.isEmpty()) {
                return Optional.empty();
            }
            // records arrive per-file, so sort the flow into true time order
            records.sort(Comparator.comparing(LogRecord::timestamp,
                    Comparator.nullsLast(Comparator.naturalOrder())));
            Episode e = new Episode(correlationId);
            boolean reached = false;
            for (LogRecord r : records) {
                e.add(r);
                if (r.callSite() != null && terminalCallSites.contains(r.callSite())) {
                    reached = true;
                }
            }
            TerminalStatus base = reached ? TerminalStatus.COMPLETED : TerminalStatus.TRUNCATED;
            e.setStatus(e.hasErrorRecord() ? TerminalStatus.ERRORED : base);
            return Optional.of(e);
        }
    }
}
