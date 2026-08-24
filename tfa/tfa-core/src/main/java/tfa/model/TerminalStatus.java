package tfa.model;

/**
 * How an episode ended.
 *
 * <ul>
 *   <li>{@link #COMPLETED} — a configured terminal call site was reached.</li>
 *   <li>{@link #TRUNCATED} — the episode ended without reaching a terminal
 *       (a new entry arrived, an idle gap opened, or the corpus ran out).</li>
 *   <li>{@link #ERRORED} — the episode contains an ERROR-level record.</li>
 * </ul>
 *
 * <p>Precedence when assigning: an ERROR-level record makes the episode
 * {@code ERRORED} regardless of whether a terminal was reached (§Phase 2, Impl A:
 * "an episode containing an ERROR-level record is ERRORED"). Error <em>presence</em>
 * is separately available via {@link Episode#hasErrorRecord()} for detectors that
 * want it as a ranking input independent of status.
 */
public enum TerminalStatus {
    COMPLETED,
    TRUNCATED,
    ERRORED
}
