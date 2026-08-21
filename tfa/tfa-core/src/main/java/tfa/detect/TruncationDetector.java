package tfa.detect;

import tfa.model.Baseline;
import tfa.model.Episode;
import tfa.model.Finding;
import tfa.model.FindingType;
import tfa.model.TerminalStatus;

import java.util.List;

/**
 * The primary "the flow broke" signal: the episode did not complete, or the modal
 * sequence's terminal call site was never reached.
 *
 * <p>Boundary censoring (§3.5) is applied by {@link DetectionEngine} before any
 * detector runs — episodes overlapping the corpus-boundary margin are never
 * findings, so a run's top findings are not simply the last requests in flight
 * when the dump was taken. This detector therefore assumes it is only handed
 * non-censored episodes.
 */
public final class TruncationDetector implements Detector {

    @Override
    public List<Finding> detect(Episode episode, Baseline baseline) {
        List<String> seq = episode.collapsedSequence();
        String modalTerminal = baseline.modalTerminal();
        boolean incomplete = episode.status() != TerminalStatus.COMPLETED;
        boolean terminalReached = modalTerminal != null
                && !seq.isEmpty() && seq.get(seq.size() - 1).equals(modalTerminal);

        if (!incomplete && terminalReached) {
            return List.of();
        }
        // if there is no modal terminal to expect and the episode completed, nothing to say
        if (!incomplete && modalTerminal == null) {
            return List.of();
        }

        String lastReached = seq.isEmpty() ? null : seq.get(seq.size() - 1);
        int index = seq.size() - 1;

        // how much of the modal flow was missed (longest common prefix vs modal)
        int matched = commonPrefix(seq, baseline.modalSequence());
        int modalLen = Math.max(1, baseline.modalSequence().size());
        double rawScore = (double) (modalLen - matched) / modalLen;

        Finding f = new Finding(episode, FindingType.TRUNCATION,
                lastReached, index, modalTerminal, baseline.modalShare(),
                episode.status().name(), rawScore);
        return List.of(f);
    }

    private static int commonPrefix(List<String> a, List<String> b) {
        int n = Math.min(a.size(), b.size());
        int i = 0;
        while (i < n && a.get(i).equals(b.get(i))) {
            i++;
        }
        return i;
    }
}
