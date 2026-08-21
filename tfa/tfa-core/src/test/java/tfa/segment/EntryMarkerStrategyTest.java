package tfa.segment;

import org.junit.jupiter.api.Test;
import tfa.model.Episode;
import tfa.model.TerminalStatus;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static tfa.segment.SegmentTestSupport.rec;

class EntryMarkerStrategyTest {

    private final EntryMarkerStrategy strategy =
            new EntryMarkerStrategy(Set.of("A:1"), Set.of("C:3"));

    @Test
    void completedTruncatedAndCompletedAgain() {
        List<Episode> eps = strategy.segment("t", List.of(
                rec(0, "t", "A:1"),
                rec(1, "t", "B:2"),
                rec(2, "t", "C:3"),   // terminal -> COMPLETED
                rec(3, "t", "A:1"),
                rec(4, "t", "B:2"),   // next entry cuts this -> TRUNCATED
                rec(5, "t", "A:1"),
                rec(6, "t", "X:9"),
                rec(7, "t", "C:3")    // terminal -> COMPLETED
        ));

        assertEquals(3, eps.size());
        assertEquals(List.of("A:1", "B:2", "C:3"), eps.get(0).callSiteSequence());
        assertEquals(TerminalStatus.COMPLETED, eps.get(0).status());
        assertEquals(List.of("A:1", "B:2"), eps.get(1).callSiteSequence());
        assertEquals(TerminalStatus.TRUNCATED, eps.get(1).status());
        assertEquals(List.of("A:1", "X:9", "C:3"), eps.get(2).callSiteSequence());
        assertEquals(TerminalStatus.COMPLETED, eps.get(2).status());
    }

    @Test
    void errorRecordMakesEpisodeErrored() {
        List<Episode> eps = strategy.segment("t", List.of(
                rec(0, "t", "A:1"),
                rec(1, "ERROR", "t", "B:2"),
                rec(2, "t", "C:3")     // terminal reached, but an ERROR was logged
        ));
        assertEquals(1, eps.size());
        assertEquals(TerminalStatus.ERRORED, eps.get(0).status());
        assertEquals(true, eps.get(0).hasErrorRecord());
    }

    @Test
    void leadingNonEntryRecordsAreDropped() {
        List<Episode> eps = strategy.segment("t", List.of(
                rec(0, "t", "B:2"),   // before any entry -> dropped
                rec(1, "t", "Z:9"),   // dropped
                rec(2, "t", "A:1"),
                rec(3, "t", "C:3")
        ));
        assertEquals(1, eps.size());
        assertEquals(List.of("A:1", "C:3"), eps.get(0).callSiteSequence());
    }

    @Test
    void finalOpenEpisodeIsTruncated() {
        List<Episode> eps = strategy.segment("t", List.of(
                rec(0, "t", "A:1"),
                rec(1, "t", "B:2")    // no terminal, stream ends
        ));
        assertEquals(1, eps.size());
        assertEquals(TerminalStatus.TRUNCATED, eps.get(0).status());
    }

    @Test
    void singleRecordEntryAndTerminal() {
        EntryMarkerStrategy s = new EntryMarkerStrategy(Set.of("A:1"), Set.of("A:1"));
        List<Episode> eps = s.segment("t", List.of(rec(0, "t", "A:1")));
        assertEquals(1, eps.size());
        assertEquals(TerminalStatus.COMPLETED, eps.get(0).status());
    }
}
