package tfa.detect;

import tfa.model.Baseline;
import tfa.model.Episode;
import tfa.model.Finding;
import tfa.model.FindingType;

import java.util.List;
import java.util.Optional;

/**
 * Compares the episode's collapsed sequence against the modal sequence and
 * reports the FIRST position where they differ — not the whole diff. The expected
 * call site and its share come from the positional distribution, so the finding
 * reads: "94% went to X here, this went to Y."
 *
 * <p>A pure shortfall (the episode is a prefix of the modal sequence) is left to
 * the truncation detector; this detector fires only on a real departure — a wrong
 * branch or an unexpected continuation past the modal end.
 */
public final class DivergenceDetector implements Detector {

    @Override
    public List<Finding> detect(Episode episode, Baseline baseline) {
        List<String> modal = baseline.modalSequence();
        List<String> observed = episode.collapsedSequence();

        Optional<SequenceDiff.Divergence> divergence = SequenceDiff.firstDivergence(modal, observed);
        if (divergence.isEmpty()) {
            return List.of();
        }
        SequenceDiff.Divergence d = divergence.get();
        int index = d.index();

        String expectedCallSite;
        double expectedShare;
        Baseline.PositionOption expected = baseline.expectedAt(index);
        if (expected != null) {
            expectedCallSite = expected.callSite();
            expectedShare = expected.share();
        } else {
            // divergence past the modal end: the majority ended here
            expectedCallSite = "<end-of-flow>";
            expectedShare = baseline.modalShare();
        }

        // rarity of defying this majority is the severity signal; stronger majority = more suspicious
        double rawScore = expectedShare;

        Finding f = new Finding(episode, FindingType.DIVERGENCE,
                d.observedCallSite(), index, expectedCallSite, expectedShare,
                d.observedCallSite(), rawScore);
        return List.of(f);
    }
}
