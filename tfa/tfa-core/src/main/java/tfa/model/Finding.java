package tfa.model;

/**
 * A ranked, explained deviation of one episode from its cluster baseline.
 *
 * <p>The fields are shared across finding types; how each is populated depends on
 * {@link #type()}:
 * <ul>
 *   <li><b>TRUNCATION</b> — {@code divergenceCallSite} = the last call site
 *       actually reached; {@code expectedCallSite} = the modal terminal that was
 *       never reached; {@code expectedShare} = the modal share; {@code observed}
 *       = the terminal status.</li>
 *   <li><b>DIVERGENCE</b> — {@code divergenceIndex} = the first collapsed
 *       position that differs; {@code expectedCallSite}/{@code expectedShare} =
 *       what the majority did at that position and how strong it was;
 *       {@code observed} = what this episode did instead;
 *       {@code divergenceCallSite} = the same observed (wrong) call site.</li>
 *   <li><b>TIMING</b> — the slow transition is {@code expectedCallSite ->
 *       divergenceCallSite}; {@code observed} carries the elapsed vs p95;
 *       {@code rawScore} is the multiple over p95.</li>
 * </ul>
 *
 * {@code rawScore} is a per-detector severity signal in roughly [0, ∞); Phase 6
 * combines it with rarity, cluster size, and error presence into the final rank.
 */
public record Finding(
        Episode episode,
        FindingType type,
        String divergenceCallSite,
        int divergenceIndex,
        String expectedCallSite,
        double expectedShare,
        String observed,
        double rawScore
) {
    /** Cluster + divergence identity used to deduplicate many episodes failing the same way. */
    public String dedupeKey(String clusterSignature) {
        return clusterSignature + "" + type + "" + divergenceIndex
                + "" + divergenceCallSite + "" + expectedCallSite;
    }
}
