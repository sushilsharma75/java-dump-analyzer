package tfa.model;

import java.time.Instant;
import java.util.List;

/**
 * One record = one envelope-matched log line plus every following line that did
 * not match the envelope (stack-trace frames, multi-line payloads). Continuation
 * lines are attached here; they are never dropped.
 *
 * <p>{@code timestamp} may be {@code null} if the envelope matched but the
 * timestamp text failed to parse against the profile's pattern — the line is
 * still a record, and callers decide how to treat a missing timestamp.
 *
 * @param timestamp        parsed event time, or {@code null} if unparseable
 * @param level            log level text (may be {@code null} if the profile lacks a level group)
 * @param threadId         emitting thread id (may be {@code null} if the profile lacks a thread group)
 * @param className        emitting class name (may be {@code null} under a message-template fallback)
 * @param lineNumber       emitting source line, or {@code -1} if absent
 * @param message          rest-of-line message; never split on the field separator
 * @param continuationLines lines attached to this record, in order; empty if none
 * @param sourceFile       file this record was read from
 * @param lineNumberInFile 1-based line number of the envelope line within {@code sourceFile}
 */
public record LogRecord(
        Instant timestamp,
        String level,
        String threadId,
        String className,
        int lineNumber,
        String message,
        List<String> continuationLines,
        String sourceFile,
        long lineNumberInFile
) {
    public LogRecord {
        continuationLines = continuationLines == null ? List.of() : List.copyOf(continuationLines);
    }

    /**
     * The primary sequence key: {@code "Classname:lineNumber"}. Returns just the
     * class name when no line number is available ({@code lineNumber < 0}).
     */
    public String callSite() {
        if (className == null) {
            return null;
        }
        return lineNumber < 0 ? className : className + ":" + lineNumber;
    }

    /** True if any continuation line looks like a Java stack frame or exception header. */
    public boolean hasStackTrace() {
        for (String c : continuationLines) {
            String t = c.strip();
            if (t.startsWith("at ") || t.startsWith("Caused by:") || t.startsWith("... ")
                    || t.contains("Exception") || t.contains("Error:")) {
                return true;
            }
        }
        return false;
    }
}
