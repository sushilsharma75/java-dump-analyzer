package tfa.pipeline;

import org.junit.jupiter.api.Test;
import tfa.config.BaselineConfig;
import tfa.config.DetectionConfig;
import tfa.detect.DetectionEngine;
import tfa.detect.DetectionResult;
import tfa.model.Episode;
import tfa.model.Finding;
import tfa.model.FindingType;
import tfa.model.FlowCluster;
import tfa.testkit.Defects;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** End-to-end detection: each injected defect is found, and the clean corpus is quiet. */
class DetectionEngineTest {

    private static final Instant T0 = Instant.parse("2026-08-20T10:00:00Z");

    private static long countType(List<Finding> findings, FindingType type) {
        return findings.stream().filter(f -> f.type() == type).count();
    }

    @Test
    void findsEachInjectedDefectAndZeroFalsePositivesOnClean() {
        FlowCluster cluster = new FlowCluster("sig");
        // 50 clean episodes spread over time, none near the corpus boundary margin
        for (int i = 0; i < 50; i++) {
            cluster.add(Defects.clean("clean-" + i, T0.plusSeconds(10 + i)));
        }
        // one of each defect, also mid-corpus
        cluster.add(Defects.truncated("trunc", T0.plusSeconds(30)));
        cluster.add(Defects.wrongBranch("wrong", T0.plusSeconds(31)));
        cluster.add(Defects.slowTransition("slow", T0.plusSeconds(32)));
        Episode retry = Defects.retryStorm("retry", T0.plusSeconds(33));
        cluster.add(retry);

        // explicit small censor margin so mid-corpus episodes are never censored
        DetectionEngine engine = new DetectionEngine(
                new DetectionConfig(3.0, 500L), BaselineConfig.defaults());
        DetectionResult result = engine.detect(List.of(cluster));
        List<Finding> findings = result.allFindings();

        assertEquals(1, countType(findings, FindingType.TRUNCATION), "the truncated flow");
        assertEquals(1, countType(findings, FindingType.DIVERGENCE), "the wrong-branch flow");
        assertEquals(1, countType(findings, FindingType.TIMING), "the slow transition");

        // no finding references a clean or retry-storm episode (zero false positives)
        for (Finding f : findings) {
            String t = f.episode().threadId();
            assertTrue(t.equals("trunc") || t.equals("wrong") || t.equals("slow"),
                    "unexpected finding on " + t + " (" + f.type() + ")");
        }
    }

    @Test
    void completedSlowEpisodeAtBoundaryIsFlaggedNotCensored() {
        // Regression: a slow-but-COMPLETE flow at the corpus edge must not be
        // hidden by the p99-duration censor margin (which the outlier inflates).
        FlowCluster cluster = new FlowCluster("sig");
        for (int i = 0; i < 30; i++) {
            cluster.add(Defects.clean("clean-" + i, T0.plusSeconds(25L * i)));
        }
        cluster.add(Defects.slowTransition("slow", T0.plusSeconds(25L * 30)));   // last, at the boundary
        DetectionResult result = new DetectionEngine(new DetectionConfig(3.0, null), BaselineConfig.defaults())
                .detect(List.of(cluster));
        List<Finding> timing = result.allFindings().stream()
                .filter(f -> f.type() == FindingType.TIMING).toList();
        assertTrue(!timing.isEmpty(), "the slow completed flow at the boundary should be flagged");
        assertTrue(timing.stream().allMatch(f -> f.episode().threadId().equals("slow")));
        assertEquals(0, result.episodesCensored());
    }

    @Test
    void boundaryCensoringExcludesInFlightEpisodes() {
        FlowCluster cluster = new FlowCluster("sig");
        for (int i = 0; i < 50; i++) {
            cluster.add(Defects.clean("clean-" + i, T0.plusSeconds(10 + i)));
        }
        // a mid-corpus truncation -> a finding
        cluster.add(Defects.truncated("mid", T0.plusSeconds(30)));
        // an in-flight truncation at the very end of the corpus -> censored, never a finding.
        // The last clean episode ends around T0+69s+400ms; put this one right at the tail.
        cluster.add(Defects.truncated("boundary", T0.plusSeconds(120)));

        DetectionEngine engine = new DetectionEngine(
                new DetectionConfig(3.0, 5_000L), BaselineConfig.defaults());
        DetectionResult result = engine.detect(List.of(cluster));

        List<String> truncThreads = result.allFindings().stream()
                .filter(f -> f.type() == FindingType.TRUNCATION)
                .map(f -> f.episode().threadId())
                .toList();

        assertTrue(truncThreads.contains("mid"), "mid-corpus truncation is a finding");
        assertTrue(!truncThreads.contains("boundary"), "in-flight truncation is censored");
        assertTrue(result.episodesCensored() >= 1);
    }
}
