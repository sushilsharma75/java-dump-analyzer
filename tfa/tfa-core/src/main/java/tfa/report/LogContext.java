package tfa.report;

import tfa.model.Episode;
import tfa.model.Finding;
import tfa.model.LogRecord;

import java.util.ArrayList;
import java.util.List;

/**
 * Extracts the raw log lines around a finding's divergence point — N records
 * before and after — so an engineer can read what actually happened. Continuation
 * lines (stack traces) are included verbatim; the envelope line is reconstructed
 * in the canonical format ({@code ts | LEVEL | thread | Class:line | message}),
 * since the parser keeps fields rather than the original bytes.
 */
public final class LogContext {

    private LogContext() {}

    /** The record index in the episode that the finding anchors to. */
    public static int anchorIndex(Episode episode, Finding finding) {
        List<LogRecord> records = episode.records();
        String anchor = finding.divergenceCallSite();
        if (anchor != null) {
            for (int i = 0; i < records.size(); i++) {
                if (anchor.equals(records.get(i).callSite())) {
                    return i;
                }
            }
        }
        return records.isEmpty() ? 0 : records.size() - 1;
    }

    /** Raw lines from {@code before} records before the anchor to {@code after} after it. */
    public static List<String> lines(Finding finding, int before, int after) {
        Episode episode = finding.episode();
        List<LogRecord> records = episode.records();
        List<String> out = new ArrayList<>();
        if (records.isEmpty()) {
            return out;
        }
        int anchor = anchorIndex(episode, finding);
        int from = Math.max(0, anchor - before);
        int to = Math.min(records.size() - 1, anchor + after);
        for (int i = from; i <= to; i++) {
            LogRecord r = records.get(i);
            String marker = (i == anchor) ? "  >> " : "     ";
            out.add(marker + envelope(r));
            for (String cont : r.continuationLines()) {
                out.add("       " + cont);
            }
        }
        return out;
    }

    private static String envelope(LogRecord r) {
        return String.format("%s | %s | %s | %s | %s",
                r.timestamp(), r.level(), r.threadId(), r.callSite(), r.message());
    }
}
