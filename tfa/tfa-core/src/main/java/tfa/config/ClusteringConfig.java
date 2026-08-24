package tfa.config;

/**
 * Clustering settings (Phase 3).
 *
 * @param signatureK   number of leading call sites forming a cluster signature
 * @param minClusterSize clusters smaller than this are UNDER_SAMPLED and excluded
 *                       from baselining, but still reported
 * @param clusterCeiling a cluster count above this warns that K is too large
 */
public record ClusteringConfig(int signatureK, int minClusterSize, int clusterCeiling) {

    public static ClusteringConfig defaults() {
        return new ClusteringConfig(3, 10, 200);
    }

    public ClusteringConfig {
        if (signatureK < 1) {
            throw new IllegalArgumentException("signatureK must be >= 1");
        }
        if (minClusterSize < 1) {
            throw new IllegalArgumentException("minClusterSize must be >= 1");
        }
    }
}
