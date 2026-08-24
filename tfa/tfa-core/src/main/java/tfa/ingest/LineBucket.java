package tfa.ingest;

/**
 * Every input line lands in exactly one bucket. All three are counted and
 * reported; a malformed line is never silently discarded (§3.2).
 */
public enum LineBucket {
    /** Line matched the envelope and starts a new record. */
    MATCHED,
    /** Line did not match the envelope but follows a record → attached to it. */
    CONTINUATION,
    /** Line matched nothing and no record was open (e.g. junk before the first match). */
    MALFORMED
}
