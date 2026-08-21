package tfa.pipeline;

import org.junit.jupiter.api.Test;
import tfa.config.BaselineConfig;
import tfa.config.DetectionConfig;
import tfa.config.RankingConfig;
import tfa.detect.DetectionEngine;
import tfa.detect.DetectionResult;
import tfa.model.Episode;
import tfa.model.FindingType;
import tfa.model.FlowCluster;
import tfa.model.LogRecord;
import tfa.model.TerminalStatus;
import tfa.rank.FindingRanker;
import tfa.rank.RankedFinding;
import tfa.rank.Suppressions;
import tfa.report.CorpusFingerprint;
import tfa.report.Report;
import tfa.report.TextReporter;
import tfa.testkit.Defects;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RankingReportTest {

    private static final Instant T0 = Instant.parse("2026-08-20T10:00:00Z");

    private static DetectionResult detectionWith(FlowCluster cluster) {
        return new DetectionEngine(new DetectionConfig(3.0, 0L), BaselineConfig.defaults())
                .detect(List.of(cluster));
    }

    private static FlowCluster corpusWithFiveWrongBranchAndOneTruncation() {
        FlowCluster cluster = new FlowCluster("sig");
        for (int i = 0; i < 100; i++) {
            cluster.add(Defects.clean("clean-" + i, T0.plusSeconds(10 + i)));
        }
        for (int i = 0; i < 5; i++) {
            cluster.add(Defects.wrongBranch("wrong-" + i, T0.plusSeconds(30 + i)));
        }
        cluster.add(Defects.truncated("trunc", T0.plusSeconds(50)));
        return cluster;
    }

    private static Optional<RankedFinding> firstOfType(List<RankedFinding> ranked, FindingType type) {
        return ranked.stream().filter(r -> r.representative().type() == type).findFirst();
    }

    @Test
    void deduplicatesManyEpisodesFailingTheSameWayIntoOneFinding() {
        DetectionResult detection = detectionWith(corpusWithFiveWrongBranchAndOneTruncation());
        FindingRanker.RankingResult r =
                new FindingRanker(RankingConfig.defaults(), Suppressions.none()).rank(detection);

        RankedFinding divergence = firstOfType(r.ranked(), FindingType.DIVERGENCE).orElseThrow();
        assertEquals(5, divergence.occurrences(), "five wrong-branch episodes collapse into one finding");
    }

    @Test
    void completedButRareRanksBelowTruncated() {
        DetectionResult detection = detectionWith(corpusWithFiveWrongBranchAndOneTruncation());
        FindingRanker.RankingResult r =
                new FindingRanker(RankingConfig.defaults(), Suppressions.none()).rank(detection);

        RankedFinding truncation = firstOfType(r.ranked(), FindingType.TRUNCATION).orElseThrow();
        RankedFinding divergence = firstOfType(r.ranked(), FindingType.DIVERGENCE).orElseThrow();

        assertTrue(truncation.score() > divergence.score(),
                "a rare wrong branch that completed cleanly is a variant, not a defect");
        // and the truncation sorts ahead of the divergence in the ranked output
        assertTrue(r.ranked().indexOf(truncation) < r.ranked().indexOf(divergence));
    }

    @Test
    void rankingIsReproducible() {
        DetectionResult detection = detectionWith(corpusWithFiveWrongBranchAndOneTruncation());
        FindingRanker ranker = new FindingRanker(RankingConfig.defaults(), Suppressions.none());
        assertEquals(ranker.rank(detection).ranked(), ranker.rank(detection).ranked());
    }

    @Test
    void suppressionsExcludeFromTopButAreCounted() {
        DetectionResult detection = detectionWith(corpusWithFiveWrongBranchAndOneTruncation());
        Suppressions supp = new Suppressions(List.of(
                new Suppressions.Rule("sig", "com.acme.Wrong:8", FindingType.DIVERGENCE, "known benign")));
        FindingRanker.RankingResult r =
                new FindingRanker(RankingConfig.defaults(), supp).rank(detection);

        assertTrue(r.top().stream().noneMatch(f -> f.representative().type() == FindingType.DIVERGENCE),
                "suppressed divergence is not in the top list");
        assertEquals(1, r.suppressedCount());
    }

    @Test
    void reportRendersWithStackTracesIntact() {
        FlowCluster cluster = new FlowCluster("sig");
        for (int i = 0; i < 100; i++) {
            cluster.add(Defects.clean("clean-" + i, T0.plusSeconds(10 + i)));
        }
        cluster.add(erroredWithStackTrace("boom", T0.plusSeconds(40)));

        DetectionResult detection = detectionWith(cluster);
        FindingRanker.RankingResult ranking =
                new FindingRanker(RankingConfig.defaults(), Suppressions.none()).rank(detection);

        Report report = new Report("test", T0, "cfg", new CorpusFingerprint("h", List.of(), T0, T0),
                "default", "ENTRY_MARKER", detection.episodesEvaluated(), detection.episodesCensored(),
                detection.marginMillis(), ranking.ranked().size(), ranking.suppressedCount(), ranking.top());

        StringBuilder sb = new StringBuilder();
        TextReporter.render(report, sb);
        String text = sb.toString();

        assertTrue(text.contains("java.lang.RuntimeException: boom"), "stack trace header is rendered");
        assertTrue(text.contains("at com.acme.Proc.run(Proc.java:3)"), "stack frame is rendered verbatim");
    }

    /** An episode that errors at Proc:3 with a stack trace, then breaks off. */
    private static Episode erroredWithStackTrace(String threadId, Instant start) {
        Episode e = new Episode(threadId);
        long t = start.toEpochMilli();
        e.add(rec(t, "INFO", threadId, "com.acme.Entry:1")); t += 100;
        e.add(rec(t, "INFO", threadId, "com.acme.Svc:2")); t += 100;
        e.add(new LogRecord(Instant.ofEpochMilli(t), "ERROR", threadId, "com.acme.Proc", 3, "boom",
                List.of("java.lang.RuntimeException: boom", "\tat com.acme.Proc.run(Proc.java:3)"), "f", 1));
        e.setStatus(TerminalStatus.ERRORED);
        return e;
    }

    private static LogRecord rec(long ms, String level, String threadId, String cs) {
        int colon = cs.lastIndexOf(':');
        return new LogRecord(Instant.ofEpochMilli(ms), level, threadId, cs.substring(0, colon),
                Integer.parseInt(cs.substring(colon + 1)), "m", List.of(), "f", 1);
    }
}
