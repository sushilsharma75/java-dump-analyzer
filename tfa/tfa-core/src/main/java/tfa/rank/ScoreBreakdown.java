package tfa.rank;

/**
 * The weighted components that produced a finding's score. Kept for the report
 * and for {@code tfa explain} (Phase 7), so a rank can be reasoned about rather
 * than guessed at.
 */
public record ScoreBreakdown(
        double rarity,
        double severity,
        double errorPresence,
        double magnitude,
        double clusterTrust,
        double variantPenalty,
        double total
) {}
