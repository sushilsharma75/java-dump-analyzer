package tfa.baseline;

import org.junit.jupiter.api.Test;
import tfa.config.BaselineConfig;
import tfa.model.Baseline;
import tfa.model.Episode;
import tfa.model.FlowCluster;
import tfa.model.LogRecord;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ConsensusBuilderTest {

    /** Build an episode starting at {@code startMs}, one record per call site spaced 100ms. */
    private static Episode episode(Instant start, String... callSites) {
        Episode e = new Episode("t");
        long t = start.toEpochMilli();
        for (String cs : callSites) {
            int colon = cs.lastIndexOf(':');
            e.add(new LogRecord(Instant.ofEpochMilli(t), "INFO", "t",
                    cs.substring(0, colon), Integer.parseInt(cs.substring(colon + 1)),
                    "m", List.of(), "f", 1));
            t += 100;
        }
        return e;
    }

    private static final Instant T0 = Instant.parse("2026-08-20T10:00:00Z");

    @Test
    void modalSequenceAndShareForAnEightyTwentySplit() {
        FlowCluster cluster = new FlowCluster("A:1 > * > C:3");
        for (int i = 0; i < 80; i++) cluster.add(episode(T0, "A:1", "B:2", "C:3"));
        for (int i = 0; i < 20; i++) cluster.add(episode(T0, "A:1", "X:9", "C:3"));

        Baseline b = ConsensusBuilder.build(cluster, BaselineConfig.defaults());

        assertEquals(List.of("A:1", "B:2", "C:3"), b.modalSequence());
        assertEquals(80, b.modalCount());
        assertEquals(0.80, b.modalShare(), 1e-9);
        assertEquals(100, b.episodesUsed());

        // top alternative is the 20% path (only two distinct sequences exist)
        assertEquals(1, b.alternatives().size());
        Baseline.SequenceShare alt = b.alternatives().get(0);
        assertEquals(List.of("A:1", "X:9", "C:3"), alt.sequence());
        assertEquals(20, alt.count());
        assertEquals(0.20, alt.share(), 1e-9);
    }

    @Test
    void positionalDistributionAndTransitionProbability() {
        FlowCluster cluster = new FlowCluster("sig");
        for (int i = 0; i < 80; i++) cluster.add(episode(T0, "A:1", "B:2", "C:3"));
        for (int i = 0; i < 20; i++) cluster.add(episode(T0, "A:1", "X:9", "C:3"));
        Baseline b = ConsensusBuilder.build(cluster, BaselineConfig.defaults());

        // position 1 (the divergence point): 80% B:2, 20% X:9
        Baseline.PositionOption expected = b.expectedAt(1);
        assertEquals("B:2", expected.callSite());
        assertEquals(0.80, expected.share(), 1e-9);

        assertEquals(0.80, b.transitionProbability("A:1", "B:2"), 1e-9);
        assertEquals(0.20, b.transitionProbability("A:1", "X:9"), 1e-9);
        assertEquals(1.0, b.transitionProbability("B:2", "C:3"), 1e-9);
    }

    @Test
    void transitionTimingMedianAndP95() {
        FlowCluster cluster = new FlowCluster("sig");
        // 100ms per step; enough episodes to make the cluster well-formed
        for (int i = 0; i < 20; i++) cluster.add(episode(T0, "A:1", "B:2", "C:3"));
        Baseline b = ConsensusBuilder.build(cluster, BaselineConfig.defaults());

        Baseline.TransitionTiming ab = b.timingFor("A:1", "B:2");
        assertEquals(100.0, ab.medianMillis(), 1e-9);
        assertEquals(100.0, ab.p95Millis(), 1e-9);
        assertEquals(20, ab.count());
    }

    @Test
    void loopCollapsingKeepsRetryStormOnTheModalPath() {
        FlowCluster cluster = new FlowCluster("sig");
        // 15 clean, 5 with a retry storm at B — collapsed, both are A B C
        for (int i = 0; i < 15; i++) cluster.add(episode(T0, "A:1", "B:2", "C:3"));
        for (int i = 0; i < 5; i++) cluster.add(episode(T0, "A:1", "B:2", "B:2", "B:2", "C:3"));
        Baseline b = ConsensusBuilder.build(cluster, BaselineConfig.defaults());

        // all 20 collapse to the same shape -> modal share is 100%, no alternatives
        assertEquals(List.of("A:1", "B:2", "C:3"), b.modalSequence());
        assertEquals(1.0, b.modalShare(), 1e-9);
        assertTrue(b.alternatives().isEmpty());
    }

    @Test
    void baselineWindowExcludesOutOfWindowEpisodes() {
        FlowCluster cluster = new FlowCluster("sig");
        Instant day1 = Instant.parse("2026-08-20T10:00:00Z");
        Instant day3 = Instant.parse("2026-08-22T10:00:00Z");
        for (int i = 0; i < 30; i++) cluster.add(episode(day1, "A:1", "B:2", "C:3"));
        for (int i = 0; i < 30; i++) cluster.add(episode(day3, "A:1", "X:9", "C:3"));

        // baseline only over day 1
        BaselineConfig cfg = new BaselineConfig(
                Instant.parse("2026-08-20T00:00:00Z"),
                Instant.parse("2026-08-21T00:00:00Z"),
                null, null, 3);
        Baseline b = ConsensusBuilder.build(cluster, cfg);

        assertEquals(30, b.episodesUsed(), "only day-1 episodes contribute");
        assertEquals(List.of("A:1", "B:2", "C:3"), b.modalSequence());
        assertEquals(1.0, b.modalShare(), 1e-9);
    }

    @Test
    void nullWhenNoEpisodesInWindow() {
        FlowCluster cluster = new FlowCluster("sig");
        cluster.add(episode(T0, "A:1", "B:2"));
        BaselineConfig cfg = new BaselineConfig(
                Instant.parse("2030-01-01T00:00:00Z"),
                Instant.parse("2030-01-02T00:00:00Z"), null, null, 3);
        assertNull(ConsensusBuilder.build(cluster, cfg));
    }
}
