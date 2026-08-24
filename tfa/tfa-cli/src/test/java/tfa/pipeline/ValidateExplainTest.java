package tfa.pipeline;

import org.junit.jupiter.api.Test;
import tfa.Analysis;
import tfa.cluster.SignatureClusterer;
import tfa.config.AnalysisConfig;
import tfa.config.BaselineConfig;
import tfa.config.ClusteringConfig;
import tfa.config.DetectionConfig;
import tfa.config.RankingConfig;
import tfa.config.SegmentationConfig;
import tfa.detect.DetectionEngine;
import tfa.detect.DetectionResult;
import tfa.ingest.FormatProfile;
import tfa.model.Episode;
import tfa.model.FlowCluster;
import tfa.model.LogRecord;
import tfa.model.TerminalStatus;
import tfa.rank.FindingRanker;
import tfa.rank.Suppressions;
import tfa.segment.StrategyKind;
import tfa.testkit.Defects;
import tfa.validate.Explainer;
import tfa.validate.GroundTruth;
import tfa.validate.Validator;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ValidateExplainTest {

    private static final Instant T0 = Instant.parse("2026-08-20T10:00:00Z");

    private static AnalysisConfig config(long censorMargin) {
        return new AnalysisConfig(
                FormatProfile.defaultProfile(), 0.95, 1000,
                new SegmentationConfig(StrategyKind.ENTRY_MARKER,
                        Set.of("com.acme.Entry:1"), Set.of("com.acme.Entry:99"), 5000),
                new ClusteringConfig(3, 10, 200),
                BaselineConfig.defaults(),
                new DetectionConfig(3.0, censorMargin),
                RankingConfig.defaults());
    }

    private static Analysis.Result result(List<Episode> episodes, AnalysisConfig cfg) {
        SignatureClusterer c = new SignatureClusterer(cfg.clustering().signatureK());
        episodes.forEach(c::add);
        List<FlowCluster> clusters = c.finish(cfg.clustering().minClusterSize());
        DetectionResult d = new DetectionEngine(cfg.detection(), cfg.baseline()).detect(clusters);
        FindingRanker.RankingResult r = new FindingRanker(cfg.ranking(), Suppressions.none()).rank(d);
        return new Analysis.Result(clusters, d, r, List.of());
    }

    /** 100 clean + one truncated defect on thread "trunc", all one cluster. */
    private static List<Episode> corpusWithTruncationDefect() {
        List<Episode> eps = new ArrayList<>();
        for (int i = 0; i < 100; i++) {
            eps.add(Defects.clean("clean-" + i, T0.plusSeconds(10 + i)));
        }
        eps.add(Defects.truncated("trunc", T0.plusSeconds(30)));
        return eps;
    }

    @Test
    void validatorFindsDefectInTop() {
        AnalysisConfig cfg = config(0L);
        Analysis.Result r = result(corpusWithTruncationDefect(), cfg);
        GroundTruth truth = new GroundTruth(List.of(new GroundTruth.Defect(
                "DEF-1", "trunc", T0.plusSeconds(29), T0.plusSeconds(31),
                "com.acme.Proc:3", "truncated flow that never completes")));

        Validator.ValidationReport report = new Validator(r, cfg).validate(truth);
        assertTrue(report.allPassed());
        Validator.DefectOutcome o = report.outcomes().get(0);
        assertTrue(o.found());
        assertEquals(1, o.rank(), "the truncation is the top finding");
        assertEquals("TRUNCATION", o.type());
    }

    @Test
    void validatorReportsMissingDefectWithReason() {
        AnalysisConfig cfg = config(0L);
        Analysis.Result r = result(corpusWithTruncationDefect(), cfg);
        GroundTruth truth = new GroundTruth(List.of(new GroundTruth.Defect(
                "DEF-GHOST", "ghost-thread", T0, T0.plusSeconds(5), null, "not present")));

        Validator.ValidationReport report = new Validator(r, cfg).validate(truth);
        assertFalse(report.allPassed());
        Validator.DefectOutcome o = report.outcomes().get(0);
        assertFalse(o.found());
        assertTrue(o.note().toLowerCase().contains("no episode"), o.note());
    }

    @Test
    void explainReportsDefectRankAndReasoning() {
        AnalysisConfig cfg = config(0L);
        Analysis.Result r = result(corpusWithTruncationDefect(), cfg);
        Explainer.Trace trace = new Explainer(r, cfg).explain("trunc", T0.plusSeconds(30));

        assertTrue(trace.episodeFound());
        assertNotNull(trace.reportedRank());
        assertEquals(1, trace.reportedRank());
        assertTrue(trace.outcome().startsWith("REPORTED"), trace.outcome());
        assertTrue(trace.lines().stream().anyMatch(l -> l.contains("truncation") && l.contains("FIRED")));
    }

    @Test
    void explainCleanEpisodeIsNotReported() {
        AnalysisConfig cfg = config(0L);
        Analysis.Result r = result(corpusWithTruncationDefect(), cfg);
        // clean-25 sits mid-corpus, not on the boundary
        Explainer.Trace trace = new Explainer(r, cfg).explain("clean-25", T0.plusSeconds(35));

        assertTrue(trace.episodeFound());
        assertTrue(trace.outcome().contains("no detector fired"), trace.outcome());
    }

    @Test
    void explainCensoredEpisodeNamesTheGate() {
        AnalysisConfig cfg = config(3_600_000L);   // a huge margin censors everything
        Analysis.Result r = result(corpusWithTruncationDefect(), cfg);
        Explainer.Trace trace = new Explainer(r, cfg).explain("trunc", T0.plusSeconds(30));

        assertTrue(trace.outcome().contains("CENSORED"), trace.outcome());
    }

    @Test
    void explainUnderSampledClusterNamesTheGate() {
        AnalysisConfig cfg = config(0L);
        // only 3 episodes of a distinct flow -> its own under-sampled cluster
        List<Episode> eps = new ArrayList<>();
        for (int i = 0; i < 3; i++) {
            eps.add(distinctFlow("other-" + i, T0.plusSeconds(10 + i)));
        }
        Analysis.Result r = result(eps, cfg);
        Explainer.Trace trace = new Explainer(r, cfg).explain("other-0", T0.plusSeconds(10));

        assertTrue(trace.outcome().toLowerCase().contains("under-sampled"), trace.outcome());
    }

    private static Episode distinctFlow(String threadId, Instant start) {
        Episode e = new Episode(threadId);
        long t = start.toEpochMilli();
        for (String cs : List.of("com.other.A:1", "com.other.B:2", "com.other.C:3")) {
            int colon = cs.lastIndexOf(':');
            e.add(new LogRecord(Instant.ofEpochMilli(t), "INFO", threadId, cs.substring(0, colon),
                    Integer.parseInt(cs.substring(colon + 1)), "m", List.of(), "f", 1));
            t += 100;
        }
        e.setStatus(TerminalStatus.COMPLETED);
        return e;
    }
}
