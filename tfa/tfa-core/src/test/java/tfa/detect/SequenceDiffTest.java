package tfa.detect;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SequenceDiffTest {

    @Test
    void editDistanceBasics() {
        assertEquals(0, SequenceDiff.editDistance(List.of("A", "B", "C"), List.of("A", "B", "C")));
        assertEquals(1, SequenceDiff.editDistance(List.of("A", "B", "C"), List.of("A", "X", "C")));
        assertEquals(1, SequenceDiff.editDistance(List.of("A", "B", "C"), List.of("A", "B")));
        assertEquals(1, SequenceDiff.editDistance(List.of("A", "B"), List.of("A", "B", "C")));
    }

    @Test
    void identicalSequencesHaveNoDivergence() {
        assertTrue(SequenceDiff.firstDivergence(List.of("A", "B", "C"), List.of("A", "B", "C")).isEmpty());
    }

    @Test
    void prefixIsNotADivergence() {
        // observed is a prefix of modal -> truncation, not divergence
        assertTrue(SequenceDiff.firstDivergence(List.of("A", "B", "C"), List.of("A", "B")).isEmpty());
    }

    @Test
    void wrongBranchIsASubstitutionAtFirstDifferingPosition() {
        Optional<SequenceDiff.Divergence> d =
                SequenceDiff.firstDivergence(List.of("A", "B", "C", "D"), List.of("A", "B", "X", "D"));
        assertTrue(d.isPresent());
        assertEquals(2, d.get().index());
        assertEquals("X", d.get().observedCallSite());
        assertEquals(SequenceDiff.Kind.SUBSTITUTION, d.get().kind());
    }

    @Test
    void continuationPastModalEndIsAnInsertion() {
        Optional<SequenceDiff.Divergence> d =
                SequenceDiff.firstDivergence(List.of("A", "B"), List.of("A", "B", "C"));
        assertTrue(d.isPresent());
        assertEquals(2, d.get().index());
        assertEquals("C", d.get().observedCallSite());
        assertEquals(SequenceDiff.Kind.INSERTION, d.get().kind());
    }
}
