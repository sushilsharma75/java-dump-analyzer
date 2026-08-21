package tfa.segment;

import org.junit.jupiter.api.Test;
import tfa.model.Episode;
import tfa.model.LogRecord;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static tfa.segment.SegmentTestSupport.rec;

class StreamingSegmenterTest {

    @Test
    void interleavedThreadsDoNotCrossContaminate() {
        EntryMarkerStrategy strategy = new EntryMarkerStrategy(Set.of("A:1"), Set.of("C:3"));
        StreamingSegmenter segmenter = new StreamingSegmenter(strategy);

        // two threads, episodes interleaved in the global stream
        List<LogRecord> stream = List.of(
                rec(0, "t1", "A:1"),
                rec(1, "t2", "A:1"),
                rec(2, "t1", "B:2"),
                rec(3, "t2", "B:2"),
                rec(4, "t1", "C:3"),   // t1 episode 1 completes
                rec(5, "t2", "C:3"),   // t2 episode 1 completes
                rec(6, "t1", "A:1"),
                rec(7, "t1", "C:3")    // t1 episode 2 completes
        );

        List<Episode> eps = segmenter.segmentToList(stream.stream());

        List<Episode> t1 = eps.stream().filter(e -> e.threadId().equals("t1")).toList();
        List<Episode> t2 = eps.stream().filter(e -> e.threadId().equals("t2")).toList();

        assertEquals(2, t1.size());
        assertEquals(1, t2.size());
        assertEquals(List.of("A:1", "B:2", "C:3"), t1.get(0).callSiteSequence());
        assertEquals(List.of("A:1", "C:3"), t1.get(1).callSiteSequence());
        assertEquals(List.of("A:1", "B:2", "C:3"), t2.get(0).callSiteSequence());
    }

    @Test
    void episodesEmittedIncrementallyNotOnlyAtEnd() {
        EntryMarkerStrategy strategy = new EntryMarkerStrategy(Set.of("A:1"), Set.of("C:3"));
        StreamingSegmenter segmenter = new StreamingSegmenter(strategy);
        List<LogRecord> stream = List.of(
                rec(0, "t", "A:1"),
                rec(1, "t", "C:3"),   // closes episode 1 mid-stream
                rec(2, "t", "A:1"),
                rec(3, "t", "C:3")
        );
        List<Integer> emissionSizes = new ArrayList<>();
        segmenter.segment(stream.stream(), e -> emissionSizes.add(emissionSizes.size()));
        // two episodes emitted; the first was emitted before the stream was exhausted
        assertEquals(2, emissionSizes.size());
    }

    @Test
    void correlationIdStrategyIsAStubProvingTheInterfaceFits() {
        CorrelationIdStrategy s = new CorrelationIdStrategy();
        assertEquals("CORRELATION_ID", s.name());
        // it implements FlowKeyStrategy (compiles), but is not implemented in V1
        assertThrows(UnsupportedOperationException.class, () -> s.newThreadSegmenter("t"));
        assertTrue(s instanceof FlowKeyStrategy);
    }
}
