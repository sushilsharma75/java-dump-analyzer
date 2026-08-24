package tfa.pipeline;

import org.junit.jupiter.api.Test;
import tfa.baseline.ConsensusBuilder;
import tfa.config.BaselineConfig;
import tfa.detect.DivergenceDetector;
import tfa.detect.TimingDetector;
import tfa.detect.TruncationDetector;
import tfa.model.Baseline;
import tfa.model.Episode;
import tfa.model.Finding;
import tfa.model.FindingType;
import tfa.model.FlowCluster;
import tfa.testkit.Defects;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Each detector must find its own injected defect and must not fire on clean episodes. */
class DetectorsTest {

    private static final Instant T0 = Instant.parse("2026-08-20T10:00:00Z");

    /** A baseline built from a clean population of the modal flow. */
    private static Baseline cleanBaseline() {
        FlowCluster c = new FlowCluster("sig");
        for (int i = 0; i < 50; i++) {
            c.add(Defects.clean("t" + i, T0.plusSeconds(i)));
        }
        return ConsensusBuilder.build(c, BaselineConfig.defaults());
    }

    private final Baseline baseline = cleanBaseline();

    @Test
    void baselineModalIsTheCleanFlow() {
        assertEquals(Defects.MODAL, baseline.modalSequence());
        assertEquals(Defects.TERMINAL, baseline.modalTerminal());
    }

    @Test
    void truncationDetectorFindsTruncatedAndNotClean() {
        TruncationDetector det = new TruncationDetector();
        List<Finding> onDefect = det.detect(Defects.truncated("d", T0), baseline);
        assertEquals(1, onDefect.size());
        assertEquals(FindingType.TRUNCATION, onDefect.get(0).type());

        assertTrue(det.detect(Defects.clean("c", T0), baseline).isEmpty());
    }

    @Test
    void divergenceDetectorFindsWrongBranchAndNotCleanNorTruncated() {
        DivergenceDetector det = new DivergenceDetector();
        List<Finding> onDefect = det.detect(Defects.wrongBranch("d", T0), baseline);
        assertEquals(1, onDefect.size());
        Finding f = onDefect.get(0);
        assertEquals(FindingType.DIVERGENCE, f.type());
        assertEquals(3, f.divergenceIndex());
        assertEquals("com.acme.Repo:4", f.expectedCallSite());
        assertEquals("com.acme.Wrong:8", f.observed());
        assertTrue(f.expectedShare() > 0.9);

        assertTrue(det.detect(Defects.clean("c", T0), baseline).isEmpty());
        // a pure truncation (prefix) is the truncation detector's job, not divergence
        assertTrue(det.detect(Defects.truncated("t", T0), baseline).isEmpty());
    }

    @Test
    void timingDetectorFindsSlowAndNotCleanNorRetryStorm() {
        TimingDetector det = new TimingDetector(3.0);
        List<Finding> onDefect = det.detect(Defects.slowTransition("d", T0), baseline);
        assertTrue(onDefect.stream().anyMatch(f -> f.type() == FindingType.TIMING));

        assertTrue(det.detect(Defects.clean("c", T0), baseline).isEmpty());
        // a fast retry storm collapses to the modal shape and must not trip timing
        assertTrue(det.detect(Defects.retryStorm("r", T0), baseline).isEmpty());
    }

    @Test
    void retryStormProducesNoFindingsFromAnyDetector() {
        Episode retry = Defects.retryStorm("r", T0);
        assertTrue(new TruncationDetector().detect(retry, baseline).isEmpty());
        assertTrue(new DivergenceDetector().detect(retry, baseline).isEmpty());
        assertTrue(new TimingDetector(3.0).detect(retry, baseline).isEmpty());
    }
}
