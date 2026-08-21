package tfa.config;

import java.time.Instant;

/**
 * Baseline windowing (Phase 4). If the defect is present throughout the window
 * used for baselining, the defect becomes "normal" and will never be flagged —
 * so the baseline can be derived from one time-bounded subset (e.g. day 1) and
 * evaluated against another (e.g. day 3).
 *
 * <p>All window bounds are optional (null = unbounded). {@code baselineStart}/
 * {@code baselineEnd} restrict which episodes form the consensus;
 * {@code evalStart}/{@code evalEnd} restrict which episodes detection evaluates
 * (used from Phase 5). An episode is in a window if its start timestamp is in
 * {@code [start, end)}.
 *
 * @param alternativesToReport how many alternative sequences to show per cluster
 */
public record BaselineConfig(
        Instant baselineStart,
        Instant baselineEnd,
        Instant evalStart,
        Instant evalEnd,
        int alternativesToReport
) {
    public static BaselineConfig defaults() {
        return new BaselineConfig(null, null, null, null, 3);
    }

    /** True if {@code start} falls in the baseline window (unbounded ends always pass). */
    public boolean inBaselineWindow(Instant start) {
        return inWindow(start, baselineStart, baselineEnd);
    }

    /** True if {@code start} falls in the evaluation window (unbounded ends always pass). */
    public boolean inEvalWindow(Instant start) {
        return inWindow(start, evalStart, evalEnd);
    }

    private static boolean inWindow(Instant t, Instant start, Instant end) {
        if (t == null) {
            return start == null && end == null;
        }
        if (start != null && t.isBefore(start)) {
            return false;
        }
        return end == null || t.isBefore(end);
    }
}
