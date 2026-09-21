package tfa.report;

import tfa.rank.RankedFinding;

import java.time.Instant;
import java.util.List;

/**
 * The assembled analysis report: header metadata for reproducibility plus the
 * ranked top findings. Rendered by {@link TextReporter} and {@link JsonReporter}.
 */
public record Report(
        String toolVersion,
        Instant runTimestamp,
        String configHash,
        CorpusFingerprint corpus,
        String profileName,
        String strategyName,
        long episodesEvaluated,
        long episodesCensored,
        long censorMarginMillis,
        int totalFindings,
        int suppressedCount,
        List<RankedFinding> top,
        int clustersTotal,
        int clustersUnderSampled,
        long episodesSkippedUnderSampled,
        int minClusterSize
) {}
