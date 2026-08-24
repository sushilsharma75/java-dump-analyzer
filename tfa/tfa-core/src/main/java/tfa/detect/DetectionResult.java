package tfa.detect;

import tfa.model.Baseline;
import tfa.model.Finding;
import tfa.model.FlowCluster;

import java.time.Instant;
import java.util.List;

/**
 * The output of a detection pass: findings grouped by cluster (so ranking has the
 * cluster and its baseline), plus the corpus bounds and censoring used.
 */
public record DetectionResult(
        List<ClusterFindings> perCluster,
        long episodesEvaluated,
        long episodesCensored,
        long marginMillis,
        Instant corpusStart,
        Instant corpusEnd
) {
    /** Findings for one cluster, with the baseline they were measured against. */
    public record ClusterFindings(FlowCluster cluster, Baseline baseline, List<Finding> findings) {}

    /** All findings flattened, in cluster order. */
    public List<Finding> allFindings() {
        List<Finding> out = new java.util.ArrayList<>();
        for (ClusterFindings cf : perCluster) {
            out.addAll(cf.findings());
        }
        return out;
    }
}
