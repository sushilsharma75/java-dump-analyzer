package tfa.cluster;

import org.junit.jupiter.api.Test;
import tfa.model.Episode;
import tfa.model.FlowCluster;
import tfa.model.LogRecord;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SignatureClustererTest {

    private static Episode episode(String threadId, String... callSites) {
        Episode e = new Episode(threadId);
        long t = 0;
        for (String cs : callSites) {
            int colon = cs.lastIndexOf(':');
            e.add(new LogRecord(Instant.ofEpochMilli(t++), "INFO", threadId,
                    cs.substring(0, colon), Integer.parseInt(cs.substring(colon + 1)),
                    "m", List.of(), "f", 1));
        }
        return e;
    }

    // Five flow types with deliberately overlapping prefixes, to exercise K.
    private static final String[][] FLOWS = {
            {"X:1", "X:2", "X:3", "X:4"},          // A
            {"X:1", "X:2", "Y:3", "Y:4"},          // B (shares first 2 with A)
            {"Z:1", "Z:2", "Z:3"},                 // C
            {"Z:1", "W:2", "W:3"},                 // D (shares first 1 with C)
            {"M:1", "M:2", "M:3", "M:4", "M:5", "M:6"}  // E
    };

    private static List<Episode> corpus(int copiesEach) {
        List<Episode> eps = new java.util.ArrayList<>();
        for (int f = 0; f < FLOWS.length; f++) {
            for (int i = 0; i < copiesEach; i++) {
                eps.add(episode("t" + f + "-" + i, FLOWS[f]));
            }
        }
        return eps;
    }

    private static int clusterCount(int k, List<Episode> eps) {
        SignatureClusterer c = new SignatureClusterer(k);
        eps.forEach(c::add);
        return c.finish(1).size();
    }

    @Test
    void kEquals3RecoversExactlyFiveFlowTypes() {
        assertEquals(5, clusterCount(3, corpus(12)));
    }

    @Test
    void kSensitivity() {
        List<Episode> eps = corpus(12);
        // K=1 collapses flows sharing the first call site: {X:1},{Z:1},{M:1} -> 3
        assertEquals(3, clusterCount(1, eps));
        // K=3 separates all five
        assertEquals(5, clusterCount(3, eps));
        // K=5 still five here (prefixes remain distinct within available length)
        assertEquals(5, clusterCount(5, eps));
    }

    @Test
    void underSampledClustersAreMarkedButStillReported() {
        // 15 copies of flow A (well-sampled), 3 copies of flow C (under-sampled at minSize 10)
        List<Episode> eps = new java.util.ArrayList<>();
        for (int i = 0; i < 15; i++) eps.add(episode("a" + i, FLOWS[0]));
        for (int i = 0; i < 3; i++) eps.add(episode("c" + i, FLOWS[2]));

        SignatureClusterer c = new SignatureClusterer(3);
        eps.forEach(c::add);
        List<FlowCluster> clusters = c.finish(10);

        assertEquals(2, clusters.size(), "both clusters reported");
        // sorted by size desc: A first (15), C second (3)
        assertFalse(clusters.get(0).isUnderSampled());
        assertEquals(15, clusters.get(0).size());
        assertTrue(clusters.get(1).isUnderSampled());
        assertEquals(3, clusters.get(1).size());
    }

    @Test
    void signatureOfShortEpisodeIsWholeSequence() {
        Episode e = episode("t", "Z:1", "Z:2");   // shorter than K=3
        assertEquals("Z:1 > Z:2", SignatureClusterer.signature(e, 3));
    }
}
