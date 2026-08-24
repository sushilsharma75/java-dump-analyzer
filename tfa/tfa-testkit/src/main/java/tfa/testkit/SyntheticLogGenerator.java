package tfa.testkit;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;

/**
 * Writes synthetic log files in the default TFA envelope
 * {@code ts | LEVEL | thread | Class:line | msg}. Phase 1 uses it to build small
 * fixtures; later phases extend it to inject known flows and defects.
 *
 * <p>Deliberately tiny and deterministic — a test helper, not a load generator.
 */
public final class SyntheticLogGenerator {

    private static final DateTimeFormatter FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS").withZone(ZoneId.of("UTC"));

    /** One synthetic log event. Use {@code null} continuations for a plain line. */
    public record Event(Instant ts, String level, String thread, String callSite,
                        String message, List<String> continuations) {
        public Event(Instant ts, String level, String thread, String callSite, String message) {
            this(ts, level, thread, callSite, message, List.of());
        }
    }

    private SyntheticLogGenerator() {}

    /** Format a single event as its envelope line (no trailing newline). */
    public static String formatLine(Event e) {
        return String.format("%s | %s | %s | %s | %s",
                FMT.format(e.ts()), e.level(), e.thread(), e.callSite(), e.message());
    }

    /** Write events (with their continuation lines) to a file, in the given order. */
    public static void writeFile(Path file, List<Event> events) {
        try {
            Files.createDirectories(file.toAbsolutePath().getParent());
            try (Writer w = Files.newBufferedWriter(file, StandardCharsets.UTF_8)) {
                for (Event e : events) {
                    w.write(formatLine(e));
                    w.write("\n");
                    if (e.continuations() != null) {
                        for (String c : e.continuations()) {
                            w.write(c);
                            w.write("\n");
                        }
                    }
                }
            }
        } catch (IOException ex) {
            throw new UncheckedIOException("cannot write " + file, ex);
        }
    }
}
