package tfa.segment;

import org.junit.jupiter.api.Test;
import tfa.model.Episode;
import tfa.model.TerminalStatus;
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
    void correlationIdGroupsOneFlowAcrossThreadsAndServices() {
        // A flow spanning several threads/services is ONE episode when joined by id.
        CorrelationIdStrategy strategy =
                new CorrelationIdStrategy("trace_id=([0-9a-f]+)", Set.of("Order:38"));
        assertEquals("CORRELATION_ID", strategy.name());
        assertTrue(strategy instanceof FlowKeyStrategy);

        List<LogRecord> stream = List.of(
                traced(0, "order-1", "Order:28", "aaa"),
                traced(1, "order-9", "Order:28", "bbb"),
                traced(2, "inv-7", "Inventory:31", "aaa"),
                traced(3, "pay-2", "Payment:29", "aaa"),
                traced(4, "order-1", "Order:38", "aaa"),
                traced(5, "order-9", "Order:38", "bbb"));

        List<Episode> eps = new StreamingSegmenter(strategy).segmentToList(stream.stream());
        assertEquals(2, eps.size(), "one episode per correlation id, not per thread");
        Episode aaa = eps.stream().filter(e -> e.threadId().equals("aaa")).findFirst().orElseThrow();
        assertEquals(List.of("Order:28", "Inventory:31", "Payment:29", "Order:38"),
                aaa.callSiteSequence());
        assertEquals(TerminalStatus.COMPLETED, aaa.status());
    }

    @Test
    void correlationIdSortsRecordsIntoTimeOrderAndDropsUnmatchedRecords() {
        CorrelationIdStrategy strategy = new CorrelationIdStrategy("trace_id=(\\w+)", Set.of());
        // out of order (as if read from separate service files), plus one with no id
        List<LogRecord> stream = List.of(
                traced(300, "t", "C:3", "x"),
                traced(100, "t", "A:1", "x"),
                untraced(150, "t", "Z:9"),
                traced(200, "t", "B:2", "x"));
        List<Episode> eps = new StreamingSegmenter(strategy).segmentToList(stream.stream());
        assertEquals(1, eps.size());
        assertEquals(List.of("A:1", "B:2", "C:3"), eps.get(0).callSiteSequence());
    }

    private static LogRecord traced(long ms, String thread, String cs, String trace) {
        return withMessage(ms, thread, cs, "work [trace_id=" + trace + "]");
    }

    private static LogRecord untraced(long ms, String thread, String cs) {
        return withMessage(ms, thread, cs, "no id here");
    }

    private static LogRecord withMessage(long ms, String thread, String cs, String msg) {
        int colon = cs.lastIndexOf(':');
        return new LogRecord(java.time.Instant.ofEpochMilli(ms), "INFO", thread,
                cs.substring(0, colon), Integer.parseInt(cs.substring(colon + 1)),
                msg, List.of(), "f", 1);
    }
}
