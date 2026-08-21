package tfa.model;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class EpisodeCollapseTest {

    private static Episode episodeOf(String... callSitesAtMs) {
        Episode e = new Episode("t");
        long t = 0;
        for (String cs : callSitesAtMs) {
            int colon = cs.lastIndexOf(':');
            e.add(new LogRecord(Instant.ofEpochMilli(t++), "INFO", "t",
                    cs.substring(0, colon), Integer.parseInt(cs.substring(colon + 1)),
                    "m", List.of(), "f", 1));
        }
        return e;
    }

    @Test
    void consecutiveRepeatsCollapseWithCounts() {
        Episode e = episodeOf("A:1", "A:1", "A:1", "B:2", "B:2", "C:3");

        // raw sequence keeps every record
        assertEquals(List.of("A:1", "A:1", "A:1", "B:2", "B:2", "C:3"), e.callSiteSequence());
        // collapsed shape removes consecutive repeats
        assertEquals(List.of("A:1", "B:2", "C:3"), e.collapsedSequence());

        List<Episode.Run> runs = e.collapsedRuns();
        assertEquals(3, runs.size());
        assertEquals("A:1", runs.get(0).callSite());
        assertEquals(3, runs.get(0).count());
        assertEquals("B:2", runs.get(1).callSite());
        assertEquals(2, runs.get(1).count());
        assertEquals("C:3", runs.get(2).callSite());
        assertEquals(1, runs.get(2).count());
    }

    @Test
    void nonConsecutiveRepeatsAreNotCollapsed() {
        // A B A is a real alternation, not a loop
        Episode e = episodeOf("A:1", "B:2", "A:1");
        assertEquals(List.of("A:1", "B:2", "A:1"), e.collapsedSequence());
        assertEquals(3, e.collapsedRuns().size());
    }
}
