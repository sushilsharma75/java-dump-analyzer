package tfa.segment;

/**
 * Segments by a correlation id carried in the log (Impl C) — <b>stub</b>.
 *
 * <p>TODO: Logs will later carry a correlation id (a request/trace id in the
 * message or a dedicated field). That makes segmentation deterministic — every
 * record tagged with the same id is one flow — and, crucially, lets a single
 * flow span multiple threads (hand-off from an HTTP worker to an async executor
 * to a DB-callback thread). When that lands, this strategy will:
 *
 * <ul>
 *   <li>extract the correlation id from each record (via a profile capability),</li>
 *   <li>group records by id rather than by thread, so {@code segment} is fed the
 *       records of one correlation id across threads, and</li>
 *   <li>emit one {@link tfa.model.Episode} per correlation id.</li>
 * </ul>
 *
 * <p>This stub exists to prove the {@link FlowKeyStrategy} interface accommodates
 * a cross-thread key without a redesign: the per-key incremental
 * {@link ThreadSegmenter} contract is identical, only the grouping key upstream
 * changes from thread id to correlation id. Do not implement in V1.
 */
public final class CorrelationIdStrategy implements FlowKeyStrategy {

    @Override
    public String name() { return "CORRELATION_ID"; }

    @Override
    public ThreadSegmenter newThreadSegmenter(String threadId) {
        throw new UnsupportedOperationException(
                "CorrelationIdStrategy is a V1 stub - logs do not carry a correlation id yet. "
                        + "See the class javadoc for the intended cross-thread design.");
    }
}
