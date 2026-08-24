package tfa.detect;

import tfa.baseline.ConsensusBuilder;
import tfa.config.BaselineConfig;
import tfa.config.DetectionConfig;
import tfa.model.Baseline;
import tfa.model.Episode;
import tfa.model.Finding;
import tfa.model.FlowCluster;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Runs the three detectors over every episode of every well-sampled cluster,
 * against that cluster's consensus baseline. Applies corpus-boundary censoring
 * (§3.5) and the evaluation window before any detector sees an episode, so
 * censored and out-of-window episodes never become findings.
 *
 * <p>Under-sampled clusters have no baseline and are skipped for detection; they
 * are still surfaced at the cluster level (Phase 3) since a rare flow is itself
 * interesting.
 */
public final class DetectionEngine {

    private final BaselineConfig baselineConfig;
    private final List<Detector> detectors;
    private final DetectionConfig detectionConfig;

    public DetectionEngine(DetectionConfig detectionConfig, BaselineConfig baselineConfig) {
        this.detectionConfig = detectionConfig;
        this.baselineConfig = baselineConfig;
        this.detectors = List.of(
                new TruncationDetector(),
                new DivergenceDetector(),
                new TimingDetector(detectionConfig.timingFactor()));
    }

    public DetectionResult detect(List<FlowCluster> clusters) {
        Instant corpusStart = null;
        Instant corpusEnd = null;
        List<Long> durations = new ArrayList<>();
        for (FlowCluster c : clusters) {
            for (Episode e : c.episodes()) {
                Instant s = e.start();
                Instant en = e.end();
                if (s != null && (corpusStart == null || s.isBefore(corpusStart))) corpusStart = s;
                if (en != null && (corpusEnd == null || en.isAfter(corpusEnd))) corpusEnd = en;
                if (s != null && en != null) {
                    durations.add(Math.max(0L, en.toEpochMilli() - s.toEpochMilli()));
                }
            }
        }

        long margin = detectionConfig.hasExplicitMargin()
                ? detectionConfig.censorMarginMillis()
                : p99(durations);
        Censor censor = new Censor(corpusStart, corpusEnd, margin);

        List<DetectionResult.ClusterFindings> perCluster = new ArrayList<>();
        long evaluated = 0;
        long censored = 0;

        for (FlowCluster cluster : clusters) {
            if (cluster.isUnderSampled()) {
                continue;
            }
            Baseline baseline = ConsensusBuilder.build(cluster, baselineConfig);
            if (baseline == null) {
                continue;
            }
            List<Finding> clusterFindings = new ArrayList<>();
            for (Episode episode : cluster.episodes()) {
                if (!baselineConfig.inEvalWindow(episode.start())) {
                    continue;
                }
                if (censor.isCensored(episode)) {
                    censored++;
                    continue;
                }
                evaluated++;
                for (Detector d : detectors) {
                    clusterFindings.addAll(d.detect(episode, baseline));
                }
            }
            perCluster.add(new DetectionResult.ClusterFindings(cluster, baseline, clusterFindings));
        }

        return new DetectionResult(perCluster, evaluated, censored, margin, corpusStart, corpusEnd);
    }

    /** p99 of the durations, or 0 if none. */
    private static long p99(List<Long> durations) {
        if (durations.isEmpty()) {
            return 0L;
        }
        List<Long> sorted = new ArrayList<>(durations);
        sorted.sort(Long::compareTo);
        int rank = (int) Math.ceil(0.99 * sorted.size());
        rank = Math.max(1, Math.min(rank, sorted.size()));
        return sorted.get(rank - 1);
    }
}
