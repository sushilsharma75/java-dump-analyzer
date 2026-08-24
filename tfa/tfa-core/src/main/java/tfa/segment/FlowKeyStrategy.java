package tfa.segment;

import tfa.model.Episode;
import tfa.model.LogRecord;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Segments one thread's ordered record stream into {@link Episode}s. The single
 * riskiest step in the pipeline. Nothing downstream may depend on which
 * implementation ran (§5).
 *
 * <p>The charter's contract is the batch {@link #segment(String, List)} method.
 * To satisfy the streaming constraint — records for a single thread must not all
 * be held in memory at once if a thread has millions of records — implementations
 * express their logic as an incremental {@link ThreadSegmenter} via
 * {@link #newThreadSegmenter(String)}; the batch method is a thin default that
 * drives one. {@link StreamingSegmenter} uses the incremental path so only the
 * currently-open episode per thread is ever held.
 */
public interface FlowKeyStrategy {

    /** Human-readable strategy name, for reports. */
    String name();

    /** Create a fresh incremental segmenter for a single thread. */
    ThreadSegmenter newThreadSegmenter(String threadId);

    /**
     * Which key this record belongs to. Thread id by default; a correlation
     * strategy overrides this so one flow can span threads and services.
     * Returning {@code null} drops the record (it belongs to no flow).
     */
    default String groupingKey(LogRecord record) {
        return record.threadId();
    }

    /**
     * Segment a thread's fully-materialised, time-ordered records into episodes.
     * Convenience over the incremental path; prefer {@link StreamingSegmenter}
     * for large corpora.
     */
    default List<Episode> segment(String threadId, List<LogRecord> orderedRecords) {
        ThreadSegmenter seg = newThreadSegmenter(threadId);
        List<Episode> out = new ArrayList<>();
        for (LogRecord r : orderedRecords) {
            out.addAll(seg.accept(r));
        }
        Optional<Episode> last = seg.finish();
        last.ifPresent(out::add);
        return out;
    }
}
