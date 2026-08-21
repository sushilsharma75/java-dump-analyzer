package tfa.model;

/** The kind of deviation a {@link Finding} represents. */
public enum FindingType {
    /** The flow broke: it did not complete / never reached the modal terminal. */
    TRUNCATION,
    /** The flow took a wrong branch: it diverged from the modal sequence. */
    DIVERGENCE,
    /** Same path, wrong speed: a transition far exceeded its baseline p95. */
    TIMING
}
