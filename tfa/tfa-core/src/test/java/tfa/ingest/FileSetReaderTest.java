package tfa.ingest;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import tfa.model.LogRecord;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FileSetReaderTest {

    private static FileSetReader reader(Path dir, ParseStats stats) {
        return new FileSetReader(dir, new RecordParser(FormatProfile.defaultProfile()), stats);
    }

    private static List<LogRecord> readAll(FileSetReader r) {
        try (var s = r.records()) {
            return s.toList();
        }
    }

    @Test
    void multilineStackTraceAttachesToCorrectRecord(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("app.log"), """
                2026-08-20 10:00:00.100 | INFO | exec-1 | com.acme.Web:10 | begin
                2026-08-20 10:00:00.200 | ERROR | exec-1 | com.acme.Repo:30 | boom
                java.sql.SQLException: timeout
                \tat com.acme.Repo.load(Repo.java:30)
                \tat com.acme.Svc.run(Svc.java:20)
                2026-08-20 10:00:00.300 | INFO | exec-1 | com.acme.Web:99 | end
                """);
        ParseStats stats = new ParseStats();
        List<LogRecord> records = readAll(reader(dir, stats));

        assertEquals(3, records.size());
        LogRecord err = records.get(1);
        assertEquals("com.acme.Repo:30", err.callSite());
        assertEquals(3, err.continuationLines().size(), "3 continuation lines belong to the ERROR record");
        assertTrue(err.hasStackTrace());
        // continuations were counted, not attached to the following record
        assertTrue(records.get(2).continuationLines().isEmpty());
        assertEquals(3, stats.matched());
        assertEquals(3, stats.continuation());
        assertEquals(0, stats.malformed());
        assertEquals(6, stats.totalLines());
    }

    @Test
    void malformedLinesAreCountedNotDropped(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("app.log"), """
                ### rotated header, not an envelope
                garbage before any record
                2026-08-20 10:00:00.100 | INFO | exec-1 | com.acme.Web:10 | begin
                a trailing continuation
                """);
        ParseStats stats = new ParseStats();
        List<LogRecord> records = readAll(reader(dir, stats));

        assertEquals(1, records.size());
        assertEquals(2, stats.malformed(), "two junk lines before the first match are malformed");
        assertEquals(1, stats.matched());
        assertEquals(1, stats.continuation(), "the line after the match is a continuation");
        assertEquals(4, stats.totalLines());
        assertFalse(stats.malformedSample().isEmpty());
    }

    @Test
    void filesReturnedInTimestampOrderRegardlessOfFilename(@TempDir Path dir) throws IOException {
        // filename order (z before a would be wrong) is deliberately reversed vs. ts order
        Files.writeString(dir.resolve("zzz-first.log"),
                "2026-08-20 09:00:00.000 | INFO | t | com.acme.A:1 | early\n");
        Files.writeString(dir.resolve("aaa-second.log"),
                "2026-08-20 11:00:00.000 | INFO | t | com.acme.B:2 | late\n");
        FileSetReader r = reader(dir, new ParseStats());

        List<Path> ordered = r.orderedFiles();
        assertEquals("zzz-first.log", ordered.get(0).getFileName().toString());
        assertEquals("aaa-second.log", ordered.get(1).getFileName().toString());

        List<LogRecord> records = readAll(r);
        assertEquals("com.acme.A:1", records.get(0).callSite());
        assertEquals("com.acme.B:2", records.get(1).callSite());
    }

    @Test
    void recordContinuationSplitAcrossFileBoundary(@TempDir Path dir) throws IOException {
        // The ERROR record starts in the earlier file; its stack frames spill into
        // the later file before the next matched line appears.
        Files.writeString(dir.resolve("part-a.log"), """
                2026-08-20 10:00:00.100 | ERROR | exec-1 | com.acme.Repo:30 | boom
                java.sql.SQLException: timeout
                \tat com.acme.Repo.load(Repo.java:30)
                """);
        Files.writeString(dir.resolve("part-b.log"), """
                \tat com.acme.Svc.run(Svc.java:20)
                \tat com.acme.Web.handle(Web.java:10)
                2026-08-20 10:00:05.000 | INFO | exec-1 | com.acme.Web:99 | end
                """);
        ParseStats stats = new ParseStats();
        List<LogRecord> records = readAll(reader(dir, stats));

        assertEquals(2, records.size());
        LogRecord err = records.get(0);
        assertEquals("com.acme.Repo:30", err.callSite());
        assertEquals(4, err.continuationLines().size(),
                "continuation lines split across the file boundary all attach to the ERROR record");
        assertEquals(0, stats.malformed(), "cross-boundary continuations are not malformed");
        assertEquals(2, stats.matched());
        assertEquals(4, stats.continuation());
    }

    @Test
    void emptyFile(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("empty.log"), "");
        ParseStats stats = new ParseStats();
        assertTrue(readAll(reader(dir, stats)).isEmpty());
        assertEquals(0, stats.totalLines());
    }

    @Test
    void fileWithNoMatchedLines(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("junk.log"), "not a log line\nanother junk line\n");
        ParseStats stats = new ParseStats();
        assertTrue(readAll(reader(dir, stats)).isEmpty());
        assertEquals(2, stats.malformed());
        assertEquals(0, stats.matched());
    }

    @Test
    void fileWithOnlyContinuationLinesAfterAnEarlierRecord(@TempDir Path dir) throws IOException {
        // an open record in file 1 whose file 2 is nothing but continuation lines
        Files.writeString(dir.resolve("1.log"),
                "2026-08-20 10:00:00.000 | ERROR | t | com.acme.A:1 | boom\n");
        Files.writeString(dir.resolve("2.log"), "\tat com.acme.A.x(A.java:1)\n\tat com.acme.B.y(B.java:2)\n");
        ParseStats stats = new ParseStats();
        List<LogRecord> records = readAll(reader(dir, stats));

        assertEquals(1, records.size());
        assertEquals(2, records.get(0).continuationLines().size());
        assertEquals(0, stats.malformed());
    }

    @Test
    void messageContainingSeparatorIsNotSplit(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("app.log"),
                "2026-08-20 10:00:00.000 | INFO | t | com.acme.A:1 | payload a=1 | b=2 | c=3\n");
        List<LogRecord> records = readAll(reader(dir, new ParseStats()));
        assertEquals("payload a=1 | b=2 | c=3", records.get(0).message());
    }

    @Test
    void matchRateFailsFastBelowThreshold(@TempDir Path dir) throws IOException {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 60; i++) sb.append("junk line ").append(i).append("\n");
        for (int i = 0; i < 40; i++) {
            sb.append("2026-08-20 10:00:00.00").append(i % 10)
              .append(" | INFO | t | com.acme.A:1 | ok\n");
        }
        Files.writeString(dir.resolve("mixed.log"), sb.toString());
        FileSetReader r = reader(dir, new ParseStats());
        MatchRateReport rep = r.checkMatchRate(1000);
        assertTrue(rep.rate() < 0.95);
        try {
            r.requireMatchRate(1000, 0.95);
            org.junit.jupiter.api.Assertions.fail("expected MatchRateException");
        } catch (MatchRateException e) {
            assertNotNull(e.report());
            assertFalse(e.report().failures().isEmpty());
        }
    }
}
