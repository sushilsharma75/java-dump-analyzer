package tfa.segment;

/** Which {@link FlowKeyStrategy} a run uses. Chosen in config, from the Phase 0 verdict. */
public enum StrategyKind {
    ENTRY_MARKER,
    IDLE_GAP,
    CORRELATION_ID
}
