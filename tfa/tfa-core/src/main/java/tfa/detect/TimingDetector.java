package tfa.detect;

import tfa.model.Baseline;
import tfa.model.Episode;
import tfa.model.Finding;
import tfa.model.FindingType;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Same path, wrong speed: any transition whose elapsed time exceeds the baseline
 * p95 by a configurable factor (default 3x). Timing is measured over the collapsed
 * runs (a retry loop is one run), so a fast retry storm does not trip this
 * detector; a genuinely slow step does.
 */
public final class TimingDetector implements Detector {

    private final double factor;

    public TimingDetector(double factor) {
        this.factor = factor;
    }

    @Override
    public List<Finding> detect(Episode episode, Baseline baseline) {
        List<Episode.Run> runs = episode.collapsedRuns();
        List<Finding> findings = new ArrayList<>();
        for (int i = 0; i + 1 < runs.size(); i++) {
            Episode.Run a = runs.get(i);
            Episode.Run b = runs.get(i + 1);
            Baseline.TransitionTiming timing = baseline.timingFor(a.callSite(), b.callSite());
            if (timing == null || timing.p95Millis() <= 0) {
                continue;
            }
            Instant from = a.firstTimestamp();
            Instant to = b.firstTimestamp();
            if (from == null || to == null) {
                continue;
            }
            long elapsed = Math.max(0L, to.toEpochMilli() - from.toEpochMilli());
            double threshold = timing.p95Millis() * factor;
            if (elapsed > threshold) {
                double multiple = elapsed / timing.p95Millis();
                String observed = String.format("elapsed=%dms p95=%.0fms (%.1fx)",
                        elapsed, timing.p95Millis(), multiple);
                findings.add(new Finding(episode, FindingType.TIMING,
                        b.callSite(), i + 1, a.callSite(), 0.0, observed, multiple));
            }
        }
        return findings;
    }
}
