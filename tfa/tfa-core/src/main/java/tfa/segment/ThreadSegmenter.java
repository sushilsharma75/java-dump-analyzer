package tfa.segment;

import tfa.model.Episode;
import tfa.model.LogRecord;

import java.util.List;
import java.util.Optional;

/**
 * Incremental, single-thread segmenter. Fed records in time order; emits an
 * episode the moment a boundary is crossed, so at most one open episode per
 * thread is held in memory at a time.
 */
public interface ThreadSegmenter {

    /**
     * Accept the next record for this thread. Returns any episodes that this
     * record closed (usually zero or one) — the returned episodes are complete
     * and will not be mutated further.
     */
    List<Episode> accept(LogRecord record);

    /**
     * Signal end of stream for this thread. Returns the final open episode, if
     * one is still accumulating.
     */
    Optional<Episode> finish();
}
