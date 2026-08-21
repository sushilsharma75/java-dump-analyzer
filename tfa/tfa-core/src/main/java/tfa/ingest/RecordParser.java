package tfa.ingest;

import tfa.model.LogRecord;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZonedDateTime;
import java.time.temporal.TemporalAccessor;
import java.util.List;
import java.util.regex.Matcher;

/**
 * Turns lines into {@link LogRecord}s according to a {@link FormatProfile}.
 *
 * <p>Stateless with respect to record grouping: it classifies and builds, while
 * the caller ({@link FileSetReader}) owns the streaming state that attaches
 * continuation lines to the preceding record. This split keeps grouping logic in
 * one place and lets the same parser drive both real ingestion and match-rate
 * sampling.
 */
public final class RecordParser {

    private final FormatProfile profile;

    public RecordParser(FormatProfile profile) {
        this.profile = profile;
    }

    public FormatProfile profile() { return profile; }

    /** Raw envelope groups captured from a matched line, before typing. */
    public record Envelope(String ts, String level, String thread, String cls,
                           String line, String msg) {}

    /**
     * Attempt to match {@code line} against the envelope. Returns {@code null} if
     * it does not match (i.e. it is a continuation or malformed line).
     */
    public Envelope tryMatch(String line) {
        Matcher m = profile.envelope().matcher(line);
        if (!m.matches()) {
            return null;
        }
        return new Envelope(
                group(m, "ts"),
                group(m, "level"),
                group(m, "thread"),
                group(m, "class"),
                group(m, "line"),
                group(m, "msg"));
    }

    private String group(Matcher m, String name) {
        if (!profile.hasGroup(name)) {
            return null;
        }
        String v = m.group(name);
        return v == null ? null : v.strip();
    }

    /**
     * Build a record from a matched envelope plus its continuation lines.
     * A timestamp that fails to parse yields a {@code null} timestamp and bumps
     * the failure counter in {@code stats}.
     */
    public LogRecord build(Envelope env, List<String> continuations,
                           String sourceFile, long lineNumberInFile, ParseStats stats) {
        Instant ts = null;
        if (env.ts() != null && profile.formatter() != null) {
            ts = parseTimestamp(env.ts());
            if (ts == null && stats != null) {
                stats.countTimestampFailure();
            }
        }
        int lineNumber = -1;
        if (env.line() != null) {
            try {
                lineNumber = Integer.parseInt(env.line());
            } catch (NumberFormatException ignored) {
                lineNumber = -1;
            }
        }
        return new LogRecord(ts, env.level(), env.thread(), env.cls(), lineNumber,
                env.msg() == null ? "" : env.msg(),
                continuations, sourceFile, lineNumberInFile);
    }

    /**
     * Parse a timestamp string against the profile pattern and zone. Supports
     * patterns that carry their own zone/offset and patterns that do not (the
     * profile zone is applied). Returns {@code null} on failure.
     */
    public Instant parseTimestamp(String text) {
        if (text == null || profile.formatter() == null) {
            return null;
        }
        try {
            TemporalAccessor ta = profile.formatter().parse(text);
            try {
                return ZonedDateTime.from(ta).toInstant();
            } catch (RuntimeException noZone) {
                return LocalDateTime.from(ta).atZone(profile.zone()).toInstant();
            }
        } catch (RuntimeException e) {
            return null;
        }
    }
}
