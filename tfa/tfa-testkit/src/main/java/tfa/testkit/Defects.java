package tfa.testkit;

import tfa.model.Episode;
import tfa.model.LogRecord;
import tfa.model.TerminalStatus;

import java.time.Instant;
import java.util.List;

/**
 * Builds synthetic episodes with known, injected defects for detector tests. All
 * episodes share the same signature prefix so they land in one cluster and are
 * compared against the same modal baseline.
 *
 * <p>The modal flow is {@code Entry:1 -> Svc:2 -> Proc:3 -> Repo:4 -> Entry:99},
 * one record per call site spaced {@link #STEP_MS} apart.
 */
public final class Defects {

    public static final String ENTRY = "com.acme.Entry:1";
    public static final String TERMINAL = "com.acme.Entry:99";
    public static final List<String> MODAL =
            List.of("com.acme.Entry:1", "com.acme.Svc:2", "com.acme.Proc:3", "com.acme.Repo:4", "com.acme.Entry:99");

    public static final long STEP_MS = 100;

    private Defects() {}

    private static LogRecord record(Instant ts, String level, String threadId, String callSite) {
        int colon = callSite.lastIndexOf(':');
        return new LogRecord(ts, level, threadId, callSite.substring(0, colon),
                Integer.parseInt(callSite.substring(colon + 1)), "m", List.of(), "f", 1);
    }

    /** Build an episode from call sites, each spaced STEP_MS after the previous. */
    private static Episode build(String threadId, Instant start, TerminalStatus status,
                                 String level, List<String> callSites) {
        Episode e = new Episode(threadId);
        long t = start.toEpochMilli();
        for (String cs : callSites) {
            e.add(record(Instant.ofEpochMilli(t), level, threadId, cs));
            t += STEP_MS;
        }
        e.setStatus(status);
        return e;
    }

    /** A clean, complete run of the modal flow. */
    public static Episode clean(String threadId, Instant start) {
        return build(threadId, start, TerminalStatus.COMPLETED, "INFO", MODAL);
    }

    /** DEFECT: the flow broke off after Proc:3 and never reached the terminal. */
    public static Episode truncated(String threadId, Instant start) {
        return build(threadId, start, TerminalStatus.TRUNCATED, "INFO",
                List.of("com.acme.Entry:1", "com.acme.Svc:2", "com.acme.Proc:3"));
    }

    /** DEFECT: a wrong branch at position 3 — Wrong:8 instead of Repo:4. Completes. */
    public static Episode wrongBranch(String threadId, Instant start) {
        return build(threadId, start, TerminalStatus.COMPLETED, "INFO",
                List.of("com.acme.Entry:1", "com.acme.Svc:2", "com.acme.Proc:3",
                        "com.acme.Wrong:8", "com.acme.Entry:99"));
    }

    /** DEFECT: the modal path, but the Proc:3 -> Repo:4 transition is ~100x slow. */
    public static Episode slowTransition(String threadId, Instant start) {
        Episode e = new Episode(threadId);
        long t = start.toEpochMilli();
        e.add(record(Instant.ofEpochMilli(t), "INFO", threadId, "com.acme.Entry:1")); t += STEP_MS;
        e.add(record(Instant.ofEpochMilli(t), "INFO", threadId, "com.acme.Svc:2"));   t += STEP_MS;
        e.add(record(Instant.ofEpochMilli(t), "INFO", threadId, "com.acme.Proc:3"));
        t += STEP_MS * 100;   // the slow step
        e.add(record(Instant.ofEpochMilli(t), "INFO", threadId, "com.acme.Repo:4"));  t += STEP_MS;
        e.add(record(Instant.ofEpochMilli(t), "INFO", threadId, "com.acme.Entry:99"));
        e.setStatus(TerminalStatus.COMPLETED);
        return e;
    }

    /** NOT A DEFECT: a fast retry storm at Repo:4 that must collapse to the modal shape. */
    public static Episode retryStorm(String threadId, Instant start) {
        return build(threadId, start, TerminalStatus.COMPLETED, "INFO",
                List.of("com.acme.Entry:1", "com.acme.Svc:2", "com.acme.Proc:3",
                        "com.acme.Repo:4", "com.acme.Repo:4", "com.acme.Repo:4", "com.acme.Entry:99"));
    }
}
