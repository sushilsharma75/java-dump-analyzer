package tfa.segment;

import org.junit.jupiter.api.Test;
import tfa.model.Episode;
import tfa.model.TerminalStatus;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static tfa.segment.SegmentTestSupport.rec;

class IdleGapStrategyTest {

    private final IdleGapStrategy strategy = new IdleGapStrategy(5_000, Set.of("T:9"));

    @Test
    void gapAboveThresholdStartsNewEpisode() {
        List<Episode> eps = strategy.segment("t", List.of(
                rec(0, "t", "A:1"),
                rec(100, "t", "B:2"),
                rec(200, "t", "T:9"),        // terminal reached in episode 1
                rec(10_200, "t", "C:3"),     // +10s gap -> new episode
                rec(10_300, "t", "D:4")      // no terminal -> TRUNCATED
        ));

        assertEquals(2, eps.size());
        assertEquals(List.of("A:1", "B:2", "T:9"), eps.get(0).callSiteSequence());
        assertEquals(TerminalStatus.COMPLETED, eps.get(0).status());
        assertEquals(List.of("C:3", "D:4"), eps.get(1).callSiteSequence());
        assertEquals(TerminalStatus.TRUNCATED, eps.get(1).status());
    }

    @Test
    void gapAtOrBelowThresholdStaysInSameEpisode() {
        List<Episode> eps = strategy.segment("t", List.of(
                rec(0, "t", "A:1"),
                rec(4_999, "t", "B:2"),      // just under threshold
                rec(9_998, "t", "T:9")       // another sub-threshold gap
        ));
        assertEquals(1, eps.size());
        assertEquals(List.of("A:1", "B:2", "T:9"), eps.get(0).callSiteSequence());
        assertEquals(TerminalStatus.COMPLETED, eps.get(0).status());
    }

    @Test
    void errorRecordMakesEpisodeErrored() {
        List<Episode> eps = strategy.segment("t", List.of(
                rec(0, "t", "A:1"),
                rec(100, "ERROR", "t", "B:2")
        ));
        assertEquals(1, eps.size());
        assertEquals(TerminalStatus.ERRORED, eps.get(0).status());
    }
}
