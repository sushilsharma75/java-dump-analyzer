package tfa.ingest;

import org.junit.jupiter.api.Test;
import tfa.model.LogRecord;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RecordParserTest {

    private final RecordParser parser = new RecordParser(FormatProfile.defaultProfile());

    @Test
    void parsesCanonicalEnvelope() {
        var env = parser.tryMatch("2026-08-20 10:00:00.123 | INFO | exec-7 | com.acme.OrderService:142 | processing");
        assertEquals("2026-08-20 10:00:00.123", env.ts());
        assertEquals("INFO", env.level());
        assertEquals("exec-7", env.thread());
        assertEquals("com.acme.OrderService", env.cls());
        assertEquals("142", env.line());
        assertEquals("processing", env.msg());

        LogRecord r = parser.build(env, List.of(), "app.log", 1, new ParseStats());
        assertEquals("com.acme.OrderService:142", r.callSite());
        assertEquals(Instant.parse("2026-08-20T10:00:00.123Z"), r.timestamp());
    }

    @Test
    void nonEnvelopeLineDoesNotMatch() {
        assertNull(parser.tryMatch("\tat com.acme.Repo.load(Repo.java:30)"));
        assertNull(parser.tryMatch("plain text"));
    }

    @Test
    void timestampParseFailureYieldsNullTimestampAndCounts() {
        var env = parser.tryMatch("NOT-A-DATE zzz | INFO | t | com.acme.A:1 | msg");
        // envelope still matched (ts group is \S+ \S+), but the date won't parse
        assertEquals("NOT-A-DATE zzz", env.ts());
        ParseStats stats = new ParseStats();
        LogRecord r = parser.build(env, List.of(), "f", 1, stats);
        assertNull(r.timestamp());
        assertEquals(1, stats.timestampParseFailures());
    }

    @Test
    void callSiteAndStackDetection() {
        var env = parser.tryMatch("2026-08-20 10:00:00.000 | ERROR | t | com.acme.A:5 | boom");
        LogRecord r = parser.build(env, List.of("java.lang.NullPointerException", "\tat com.acme.A.x(A.java:5)"),
                "f", 1, new ParseStats());
        assertEquals("com.acme.A:5", r.callSite());
        assertTrue(r.hasStackTrace());
    }
}
