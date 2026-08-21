package tfa.config;

/**
 * Ranking weights and knobs (Phase 6). Weights come from config so they can be
 * tuned without a rebuild.
 *
 * @param rarityWeight       weight on how uncommon the variant is within its cluster
 * @param severityWeight     weight on type severity (TRUNCATION &gt; DIVERGENCE &gt; TIMING)
 * @param errorWeight        weight on ERROR record / stack-trace presence
 * @param magnitudeWeight    weight on TIMING magnitude (multiples over p95)
 * @param clusterSizeWeight  weight on cluster-size trust (large clusters are more trustworthy)
 * @param benignVariantPenalty multiplier applied to a DIVERGENCE whose episode
 *                           completed normally with no error — a variant, not a
 *                           defect. Rarity alone is a false-positive firehose.
 * @param topN               how many findings the report surfaces
 */
public record RankingConfig(
        double rarityWeight,
        double severityWeight,
        double errorWeight,
        double magnitudeWeight,
        double clusterSizeWeight,
        double benignVariantPenalty,
        int topN
) {
    public static RankingConfig defaults() {
        return new RankingConfig(1.0, 1.0, 0.5, 0.5, 0.5, 0.2, 20);
    }
}
