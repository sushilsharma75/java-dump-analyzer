package tfa.segment;

import tfa.model.Episode;
import tfa.model.LogRecord;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.stream.Stream;

/**
 * Drives a {@link FlowKeyStrategy} over the whole, globally time-ordered record
 * stream and emits episodes as they close. Records are grouped by thread id;
 * only one open {@link ThreadSegmenter} per thread is held, each carrying at most
 * one open episode — so memory stays bounded by the number of concurrently-active
 * threads, never by total record count (§Phase 2 constraint).
 */
public final class StreamingSegmenter {

    private final FlowKeyStrategy strategy;

    public StreamingSegmenter(FlowKeyStrategy strategy) {
        this.strategy = strategy;
    }

    public FlowKeyStrategy strategy() { return strategy; }

    /**
     * Segment the stream, passing each completed episode to {@code sink} in the
     * order episodes close. The stream is consumed and closed.
     */
    public void segment(Stream<LogRecord> records, Consumer<Episode> sink) {
        Map<String, ThreadSegmenter> open = new HashMap<>();
        try (records) {
            records.forEach(r -> {
                String key = strategy.groupingKey(r);
                if (key == null) {
                    return;   // record belongs to no flow (e.g. no correlation id)
                }
                ThreadSegmenter seg = open.computeIfAbsent(key, strategy::newThreadSegmenter);
                List<Episode> closed = seg.accept(r);
                for (Episode e : closed) {
                    sink.accept(e);
                }
            });
        }
        // flush every thread's final open episode
        for (ThreadSegmenter seg : open.values()) {
            seg.finish().ifPresent(sink);
        }
    }

    /** Convenience for small inputs and tests: collect all episodes into a list. */
    public List<Episode> segmentToList(Stream<LogRecord> records) {
        List<Episode> out = new ArrayList<>();
        segment(records, out::add);
        return out;
    }
}
