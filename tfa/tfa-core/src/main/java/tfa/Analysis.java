package tfa;

import tfa.cluster.SignatureClusterer;
import tfa.config.AnalysisConfig;
import tfa.detect.DetectionEngine;
import tfa.detect.DetectionResult;
import tfa.ingest.FileSetReader;
import tfa.ingest.ParseStats;
import tfa.ingest.RecordParser;
import tfa.model.FlowCluster;
import tfa.model.LogRecord;
import tfa.rank.FindingRanker;
import tfa.rank.Suppressions;
import tfa.segment.StreamingSegmenter;

import java.nio.file.Path;
import java.util.List;
import java.util.stream.Stream;

/**
 * The library's public entry point — the seam a future POSTMORTEM integration
 * joins on. Runs the whole pipeline (ingest &rarr; segment &rarr; cluster &rarr;
 * detect &rarr; rank) for a log directory and configuration, returning the
 * artifacts every downstream view (report, validation, explain) needs.
 */
public final class Analysis {

    private Analysis() {}

    /** All pipeline artifacts for one run. */
    public record Result(
            List<FlowCluster> clusters,
            DetectionResult detection,
            FindingRanker.RankingResult ranking,
            List<Path> orderedFiles
    ) {}

    public static Result analyze(Path logDirectory, AnalysisConfig config) {
        return analyze(logDirectory, config, Suppressions.none());
    }

    public static Result analyze(Path logDirectory, AnalysisConfig config, Suppressions suppressions) {
        RecordParser parser = new RecordParser(config.profile());
        FileSetReader reader = new FileSetReader(logDirectory, parser, new ParseStats());
        reader.requireMatchRate(config.sampleLines(), config.matchThreshold());
        List<Path> orderedFiles = reader.orderedFiles();

        StreamingSegmenter segmenter = new StreamingSegmenter(config.segmentation().buildStrategy());
        SignatureClusterer clusterer = new SignatureClusterer(config.clustering().signatureK());
        try (Stream<LogRecord> records = reader.records()) {
            segmenter.segment(records, clusterer::add);
        }
        List<FlowCluster> clusters = clusterer.finish(config.clustering().minClusterSize());

        DetectionResult detection =
                new DetectionEngine(config.detection(), config.baseline()).detect(clusters);
        FindingRanker.RankingResult ranking =
                new FindingRanker(config.ranking(), suppressions).rank(detection);

        return new Result(clusters, detection, ranking, orderedFiles);
    }
}
