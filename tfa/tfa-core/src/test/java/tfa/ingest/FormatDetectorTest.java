package tfa.ingest;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FormatDetectorTest {

    @Test
    void detectsCanonicalPipeFormat(@TempDir Path dir) throws IOException {
        Path f = dir.resolve("app.log");
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 100; i++) {
            sb.append("2026-08-20 10:00:0").append(i % 10)
              .append(".123 | INFO | exec-").append(i % 4)
              .append(" | com.acme.Svc:").append(10 + i % 5).append(" | doing work\n");
        }
        Files.writeString(f, sb.toString());

        FormatDetector.Detected d = FormatDetector.detect(f);
        assertTrue(d.matchRate() > 0.95, "should confidently match the canonical format");
        assertEquals("yyyy-MM-dd HH:mm:ss.SSS", d.profile().timestampPattern());
        assertTrue(d.profile().has(Capability.CALL_SITE));
        assertTrue(d.profile().has(Capability.LEVEL));
        assertTrue(d.profile().has(Capability.THREAD));
        assertTrue(d.yaml().contains("profiles:"));
        assertTrue(d.yaml().contains("capabilities:"));
    }

    @Test
    void flagsNonPipeFormatAsLowConfidence(@TempDir Path dir) throws IOException {
        Path f = dir.resolve("weird.log");
        Files.writeString(f, "some random application output\nwith no structure at all\nreally nothing here\n");
        FormatDetector.Detected d = FormatDetector.detect(f);
        assertTrue(d.matchRate() < 0.95);
        assertTrue(d.note().toLowerCase().contains("hand"));
    }
}
