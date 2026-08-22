package tfa.validate;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GroundTruthTest {

    @Test
    void loadsDefectsWithWindows(@TempDir Path dir) throws IOException {
        Path f = dir.resolve("ground-truth.yaml");
        Files.writeString(f, """
                defects:
                  - id: DEF-1
                    threadId: exec-3
                    timestampWindow:
                      start: "2026-08-20T10:00:00Z"
                      end:   "2026-08-20T10:05:00Z"
                    expectedDivergenceCallSite: "com.acme.repo.OrderRepository:30"
                    description: "DB timeout wrong branch"
                """);
        GroundTruth gt = GroundTruth.load(f);
        assertEquals(1, gt.defects().size());
        GroundTruth.Defect d = gt.defects().get(0);
        assertEquals("DEF-1", d.id());
        assertEquals("exec-3", d.threadId());
        assertEquals("com.acme.repo.OrderRepository:30", d.expectedDivergenceCallSite());
        assertTrue(d.contains(Instant.parse("2026-08-20T10:02:00Z")));
        assertFalse(d.contains(Instant.parse("2026-08-20T11:00:00Z")));
    }
}
