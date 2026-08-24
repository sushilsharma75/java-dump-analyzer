package tfa.report;

import tfa.model.Finding;
import tfa.rank.RankedFinding;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.List;

/** Renders a {@link Report} as plain text to an {@link Appendable} (stdout). */
public final class TextReporter {

    private TextReporter() {}

    public static void render(Report report, Appendable out) {
        try {
            write(report, out);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static void write(Report r, Appendable out) throws IOException {
        line(out, "==================================================================");
        line(out, "TFA ANALYSIS REPORT");
        line(out, "==================================================================");
        line(out, "  tool version    : " + r.toolVersion());
        line(out, "  run timestamp   : " + r.runTimestamp());
        line(out, "  config hash     : " + r.configHash());
        line(out, "  corpus hash     : " + r.corpus().hash());
        line(out, "  corpus range    : " + r.corpus().corpusStart() + " -> " + r.corpus().corpusEnd());
        line(out, "  profile/strategy: " + r.profileName() + " / " + r.strategyName());
        line(out, String.format("  episodes        : %,d evaluated, %,d censored (margin %,dms)",
                r.episodesEvaluated(), r.episodesCensored(), r.censorMarginMillis()));
        line(out, String.format("  findings        : %,d total, %,d suppressed, top %d shown",
                r.totalFindings(), r.suppressedCount(), r.top().size()));
        if (r.suppressedCount() > 0) {
            line(out, String.format("  (%d findings suppressed)", r.suppressedCount()));
        }
        line(out, "");

        int rank = 1;
        for (RankedFinding rf : r.top()) {
            Finding f = rf.representative();
            line(out, "------------------------------------------------------------------");
            line(out, String.format("#%d  score=%.3f  %s  x%d occurrence(s)",
                    rank++, rf.score(), f.type(), rf.occurrences()));
            line(out, String.format("    cluster : %s  (size %d)", rf.clusterSignature(), rf.clusterSize()));
            line(out, String.format("    at      : %s  [collapsed index %d]",
                    f.divergenceCallSite(), f.divergenceIndex()));
            line(out, String.format("    majority: %s (%.0f%%);  this: %s",
                    f.expectedCallSite(), f.expectedShare() * 100, f.observed()));
            line(out, String.format("    example : thread=%s  @ %s",
                    f.episode().threadId(), f.episode().start()));
            line(out, "    log context (>> marks the divergence point):");
            List<String> ctx = LogContext.lines(f, 5, 5);
            for (String l : ctx) {
                line(out, "    " + l);
            }
        }
        if (r.top().isEmpty()) {
            for (String l : noFindingsExplanation(r)) {
                line(out, l);
            }
        }
        line(out, "==================================================================");
    }

    /** Say WHY nothing was reported. A zero-episode run is not a clean run. */
    static List<String> noFindingsExplanation(Report r) {
        List<String> l = new java.util.ArrayList<>();
        if (r.episodesEvaluated() > 0) {
            l.add(String.format("No findings. %,d episodes were compared against their baselines "
                    + "and none deviated - this really is a clean run.", r.episodesEvaluated()));
            return l;
        }
        l.add("NOTHING WAS ANALYSED - this is NOT a clean run.");
        l.add("");
        if (r.clustersTotal() == 0) {
            l.add("  No flows were found at all. Check that segmentation matches your logs:");
            l.add("    - ENTRY_MARKER: are entryCallSites/terminalCallSites the real call sites?");
            l.add("    - CORRELATION_ID: does correlationIdPattern match the id in your messages?");
        } else if (r.clustersUnderSampled() == r.clustersTotal()) {
            l.add(String.format("  All %d flow group(s) were too small to baseline (%,d episodes skipped).",
                    r.clustersTotal(), r.episodesSkippedUnderSampled()));
            l.add(String.format("  A group needs at least minClusterSize=%d examples, because this",
                    r.minClusterSize()));
            l.add("  tool finds defects by comparing a flow against OTHER RUNS OF THE SAME FLOW.");
            l.add("");
            l.add("  Fix by either:");
            l.add("    - analysing more traffic (more runs of each flow), or");
            l.add("    - lowering clustering.minClusterSize (results get statistically weak), or");
            l.add("    - lowering clustering.signatureK so similar flows group together.");
        } else {
            l.add(String.format("  %d of %d flow groups were too small to baseline (%,d episodes skipped),",
                    r.clustersUnderSampled(), r.clustersTotal(), r.episodesSkippedUnderSampled()));
            l.add("  and every remaining episode was excluded (boundary-censored or outside the eval window).");
        }
        return l;
    }

    private static void line(Appendable out, String s) throws IOException {
        out.append(s).append('\n');
    }
}
