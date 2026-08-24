package tfa.detect;

import tfa.model.Baseline;
import tfa.model.Episode;
import tfa.model.Finding;

import java.util.List;

/**
 * Takes an episode and its cluster baseline and returns zero or more findings.
 * Detectors are independent and independently testable. Log level is never a
 * detection trigger — an ERROR record is a ranking input, not a detector (§Phase
 * 5); the valuable defects are flows that silently took a wrong branch and logged
 * nothing at ERROR.
 */
public interface Detector {
    List<Finding> detect(Episode episode, Baseline baseline);
}
