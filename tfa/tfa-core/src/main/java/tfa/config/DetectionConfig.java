package tfa.config;

/**
 * Detection settings (Phase 5).
 *
 * @param timingFactor       a transition trips the timing detector when its
 *                           elapsed time exceeds baseline p95 by this factor
 * @param censorMarginMillis the corpus-boundary censoring margin; {@code null}
 *                           means derive it from the p99 episode duration
 */
public record DetectionConfig(double timingFactor, Long censorMarginMillis) {

    public static DetectionConfig defaults() {
        return new DetectionConfig(3.0, null);
    }

    public DetectionConfig {
        if (timingFactor <= 0) {
            throw new IllegalArgumentException("timingFactor must be > 0");
        }
    }

    public boolean hasExplicitMargin() {
        return censorMarginMillis != null;
    }
}
