package tfa.segment;

import tfa.model.LogRecord;

import java.time.Instant;
import java.util.List;

/** Helpers for building {@link LogRecord}s inline in segmentation tests. */
final class SegmentTestSupport {

    private SegmentTestSupport() {}

    /** {@code cs} is "Class:line". */
    static LogRecord rec(long epochMillis, String level, String thread, String cs) {
        int colon = cs.lastIndexOf(':');
        String cls = cs.substring(0, colon);
        int line = Integer.parseInt(cs.substring(colon + 1));
        return new LogRecord(Instant.ofEpochMilli(epochMillis), level, thread, cls, line,
                "msg", List.of(), "f", 1);
    }

    static LogRecord rec(long epochMillis, String thread, String cs) {
        return rec(epochMillis, "INFO", thread, cs);
    }

    static List<String> seq(tfa.model.Episode e) {
        return e.callSiteSequence();
    }
}
