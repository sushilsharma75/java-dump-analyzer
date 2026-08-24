package tfa.ingest;

/**
 * Declared capabilities of a {@link FormatProfile}. Capabilities are declared in
 * config, never inferred by probing. Downstream phases read them to decide what
 * they can do — e.g. a profile without {@link #CALL_SITE} cannot use the primary
 * sequence key and must fall back to a message-derived template (§3.3).
 */
public enum Capability {
    /** Profile provides {@code class} and {@code line} groups → primary sequence key. */
    CALL_SITE,
    /** Profile provides a {@code level} group. */
    LEVEL,
    /** Profile provides a {@code thread} group. */
    THREAD,
    /** Profile provides a {@code ts} group with a parseable timestamp. */
    TIMESTAMP,
    /** Profile provides a {@code msg} group. */
    MESSAGE
}
