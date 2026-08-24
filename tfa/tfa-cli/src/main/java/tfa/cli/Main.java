package tfa.cli;

import tfa.config.AnalysisConfig;
import tfa.ingest.FileSetReader;
import tfa.ingest.FormatDetector;
import tfa.ingest.FormatProfile;
import tfa.ingest.MatchRateException;
import tfa.ingest.MatchRateReport;
import tfa.ingest.ParseStats;
import tfa.ingest.ProfileLoader;
import tfa.ingest.RecordParser;
import tfa.Analysis;
import tfa.Version;
import tfa.baseline.ConsensusBuilder;
import tfa.cluster.SignatureClusterer;
import tfa.detect.DetectionEngine;
import tfa.detect.DetectionResult;
import tfa.model.Baseline;
import tfa.model.Episode;
import tfa.model.Finding;
import tfa.model.FlowCluster;
import tfa.rank.FindingRanker;
import tfa.rank.Suppressions;
import tfa.report.CorpusFingerprint;
import tfa.report.Hashing;
import tfa.report.JsonReporter;
import tfa.report.Report;
import tfa.report.TextReporter;
import tfa.validate.Explainer;
import tfa.validate.GroundTruth;
import tfa.validate.Validator;
import tfa.model.LogRecord;
import tfa.model.TerminalStatus;
import tfa.segment.FlowKeyStrategy;
import tfa.segment.StreamingSegmenter;

import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.PriorityQueue;
import java.util.Set;
import java.util.stream.Stream;

/**
 * Thin CLI over tfa-core. Dispatches subcommands; all real work lives in the
 * library. Phase 1 ships {@code parse} and {@code detect-format}.
 */
public final class Main {

    public static void main(String[] argv) {
        if (argv.length == 0) {
            usage();
            System.exit(1);
        }
        String cmd = argv[0];
        try {
            switch (cmd) {
                case "parse" -> parse(new Args(argv, 1));
                case "segment" -> segment(new Args(argv, 1));
                case "cluster" -> cluster(new Args(argv, 1));
                case "baseline" -> baseline(new Args(argv, 1));
                case "detect" -> detect(new Args(argv, 1));
                case "analyze" -> analyze(new Args(argv, 1));
                case "validate" -> validate(new Args(argv, 1));
                case "explain" -> explain(new Args(argv, 1));
                case "detect-format" -> detectFormat(new Args(argv, 1));
                case "serve" -> serve(new Args(argv, 1));
                case "-h", "--help", "help" -> usage();
                default -> {
                    System.err.println("unknown command: " + cmd);
                    usage();
                    System.exit(1);
                }
            }
        } catch (MatchRateException e) {
            reportMatchFailure(e);
            System.exit(2);
        } catch (UnsupportedOperationException e) {
            System.err.println("unsupported: " + e.getMessage());
            System.exit(3);
        } catch (IllegalArgumentException e) {
            System.err.println("error: " + e.getMessage());
            System.exit(1);
        }
    }

    // -- tfa parse <dir> ----------------------------------------------------

    private static void parse(Args args) {
        String dir = args.positional(0);
        if (dir == null) {
            System.err.println("usage: tfa parse <dir> [--profile <yaml>] [--profile-name <name>] "
                    + "[--threshold 0.95] [--sample 1000]");
            System.exit(1);
            return;
        }
        FormatProfile profile = resolveProfile(args);
        double threshold = args.getDouble("threshold", 0.95);
        int sampleLines = args.getInt("sample", 1000);

        RecordParser parser = new RecordParser(profile);
        ParseStats stats = new ParseStats();
        FileSetReader reader = new FileSetReader(Path.of(dir), parser, stats);

        System.out.printf("profile           : %s (capabilities %s)%n",
                profile.name(), profile.capabilities());
        System.out.printf("files (ts order)  : %d%n", reader.orderedFiles().size());

        // fail fast on mismatch before streaming the whole corpus
        MatchRateReport mr = reader.requireMatchRate(sampleLines, threshold);
        System.out.printf("sample match rate : %.2f%% (%d matched / %d malformed of %d sampled)%n",
                mr.rate() * 100, mr.matched(), mr.malformed(), mr.sampledLines());

        Set<String> threads = new HashSet<>();
        Set<String> callSites = new HashSet<>();
        Instant[] range = {null, null};
        long[] recCount = {0};
        long peakHeap = usedHeap();

        long t0 = System.nanoTime();
        try (Stream<LogRecord> records = reader.records()) {
            var it = records.iterator();
            while (it.hasNext()) {
                LogRecord r = it.next();
                recCount[0]++;
                if (r.threadId() != null) threads.add(r.threadId());
                if (r.callSite() != null) callSites.add(r.callSite());
                Instant ts = r.timestamp();
                if (ts != null) {
                    if (range[0] == null || ts.isBefore(range[0])) range[0] = ts;
                    if (range[1] == null || ts.isAfter(range[1])) range[1] = ts;
                }
                if ((recCount[0] & 0xFFFF) == 0) {
                    peakHeap = Math.max(peakHeap, usedHeap());
                }
            }
        }
        long elapsedMs = (System.nanoTime() - t0) / 1_000_000;
        peakHeap = Math.max(peakHeap, usedHeap());

        long total = stats.totalLines();
        System.out.println("----------------------------------------------------------");
        System.out.println("INGESTION STATISTICS");
        System.out.printf("  lines total     : %,d%n", total);
        System.out.printf("    matched       : %,d (%.2f%%)%n", stats.matched(), pct(stats.matched(), total));
        System.out.printf("    continuation  : %,d (%.2f%%)%n", stats.continuation(), pct(stats.continuation(), total));
        System.out.printf("    malformed     : %,d (%.2f%%)%n", stats.malformed(), pct(stats.malformed(), total));
        System.out.printf("  records         : %,d%n", recCount[0]);
        System.out.printf("  distinct threads: %,d%n", threads.size());
        System.out.printf("  distinct sites  : %,d%n", callSites.size());
        System.out.printf("  timestamp range : %s  ->  %s%n", range[0], range[1]);
        if (stats.timestampParseFailures() > 0) {
            System.out.printf("  ts parse fails  : %,d%n", stats.timestampParseFailures());
        }
        System.out.printf("  wall time       : %,d ms%n", elapsedMs);
        System.out.printf("  peak heap used  : %,d MB%n", peakHeap / (1024 * 1024));
        if (stats.malformed() > 0) {
            System.out.println("  malformed sample:");
            for (var m : stats.malformedSample()) {
                System.out.printf("    %s:%d  %s%n",
                        shortName(m.sourceFile()), m.lineNumberInFile(), truncate(m.text(), 140));
            }
        }
    }

    // -- tfa segment <dir> --config <yaml> ----------------------------------

    private static void segment(Args args) {
        String dir = args.positional(0);
        String configPath = args.get("config", null);
        if (dir == null || configPath == null) {
            System.err.println("usage: tfa segment <dir> --config <yaml>");
            System.exit(1);
            return;
        }
        AnalysisConfig config = AnalysisConfig.load(Path.of(configPath));
        FormatProfile profile = config.profile();
        RecordParser parser = new RecordParser(profile);
        ParseStats stats = new ParseStats();
        FileSetReader reader = new FileSetReader(Path.of(dir), parser, stats);
        reader.requireMatchRate(config.sampleLines(), config.matchThreshold());

        FlowKeyStrategy strategy = config.segmentation().buildStrategy();
        StreamingSegmenter segmenter = new StreamingSegmenter(strategy);

        System.out.printf("profile           : %s%n", profile.name());
        System.out.printf("strategy          : %s%n", strategy.name());

        SegmentStats agg = new SegmentStats();
        long t0 = System.nanoTime();
        try (Stream<LogRecord> records = reader.records()) {
            segmenter.segment(records, agg::accept);
        }
        long elapsedMs = (System.nanoTime() - t0) / 1_000_000;

        agg.print(elapsedMs);
    }

    /** Incremental aggregation of segmentation output for the report. */
    private static final class SegmentStats {
        long totalEpisodes;
        final Map<String, Long> perThread = new HashMap<>();
        final long[] recordBuckets = new long[RECORD_BUCKETS.length];
        final long[] durationBuckets = new long[DURATION_BUCKETS.length];
        final Map<TerminalStatus, Long> statusCounts = new EnumMap<>(TerminalStatus.class);
        // min-heap of the 10 longest episodes by record count
        final PriorityQueue<Episode> longest =
                new PriorityQueue<>((a, b) -> Integer.compare(a.size(), b.size()));

        void accept(Episode e) {
            totalEpisodes++;
            perThread.merge(e.threadId(), 1L, Long::sum);
            recordBuckets[bucketIndex(RECORD_BUCKETS, e.size())]++;
            durationBuckets[bucketIndex(DURATION_BUCKETS, durationMillis(e))]++;
            statusCounts.merge(e.status(), 1L, Long::sum);
            longest.offer(e);
            if (longest.size() > 10) {
                longest.poll();
            }
        }

        void print(long elapsedMs) {
            System.out.println("----------------------------------------------------------");
            System.out.println("SEGMENTATION");
            System.out.printf("  total episodes  : %,d%n", totalEpisodes);
            System.out.printf("  distinct threads: %,d%n", perThread.size());
            System.out.printf("  wall time       : %,d ms%n", elapsedMs);

            System.out.println("  status breakdown:");
            for (TerminalStatus s : TerminalStatus.values()) {
                long n = statusCounts.getOrDefault(s, 0L);
                System.out.printf("      %-10s: %,d (%.1f%%)%n", s, n, pct(n, totalEpisodes));
            }

            printHist("  episodes-per-thread histogram:", PER_THREAD_LABELS, perThreadCounts());
            printHist("  records-per-episode histogram:", RECORD_LABELS, recordBuckets);
            printHist("  episode-duration histogram:", DURATION_LABELS, durationBuckets);

            System.out.println("  10 longest episodes (by record count):");
            List<Episode> top = new ArrayList<>(longest);
            top.sort((a, b) -> Integer.compare(b.size(), a.size()));
            for (Episode e : top) {
                System.out.printf("      thread=%s size=%d status=%s start=%s%n",
                        e.threadId(), e.size(), e.status(), e.start());
                System.out.printf("        seq: %s%n", truncate(String.join(" -> ", e.callSiteSequence()), 300));
            }
        }

        private long[] perThreadCounts() {
            long[] counts = new long[PER_THREAD_BUCKETS.length];
            for (long c : perThread.values()) {
                counts[bucketIndex(PER_THREAD_BUCKETS, c)]++;
            }
            return counts;
        }
    }

    // bucket definitions: {upperBoundInclusive, label-index} — parallel to labels
    private static final long[] RECORD_BUCKETS   = {1, 5, 10, 25, 100, 1000, Long.MAX_VALUE};
    private static final String[] RECORD_LABELS  = {"1", "2-5", "6-10", "11-25", "26-100", "101-1000", ">1000"};
    private static final long[] PER_THREAD_BUCKETS  = {1, 5, 25, 100, 1000, Long.MAX_VALUE};
    private static final String[] PER_THREAD_LABELS = {"1", "2-5", "6-25", "26-100", "101-1000", ">1000"};
    private static final long[] DURATION_BUCKETS = {100, 1000, 5000, 30000, 300000, Long.MAX_VALUE};
    private static final String[] DURATION_LABELS = {"<100ms", "<1s", "<5s", "<30s", "<5m", "longer"};

    private static int bucketIndex(long[] bounds, long value) {
        for (int i = 0; i < bounds.length; i++) {
            if (value <= bounds[i]) {
                return i;
            }
        }
        return bounds.length - 1;
    }

    private static void printHist(String title, String[] labels, long[] counts) {
        System.out.println(title);
        long total = 0;
        for (long c : counts) {
            total += c;
        }
        for (int i = 0; i < counts.length; i++) {
            System.out.printf("      %-9s: %,10d (%5.1f%%)%n", labels[i], counts[i], pct(counts[i], total));
        }
    }

    private static long durationMillis(Episode e) {
        Instant s = e.start();
        Instant en = e.end();
        if (s == null || en == null) {
            return 0L;
        }
        return Math.max(0L, Duration.between(s, en).toMillis());
    }

    // -- tfa cluster <dir> --config <yaml> ----------------------------------

    private static void cluster(Args args) {
        String dir = args.positional(0);
        String configPath = args.get("config", null);
        if (dir == null || configPath == null) {
            System.err.println("usage: tfa cluster <dir> --config <yaml>");
            System.exit(1);
            return;
        }
        AnalysisConfig config = AnalysisConfig.load(Path.of(configPath));
        int k = config.clustering().signatureK();
        int minSize = config.clustering().minClusterSize();
        int ceiling = config.clustering().clusterCeiling();

        System.out.printf("profile           : %s%n", config.profile().name());
        System.out.printf("strategy          : %s%n", config.segmentation().strategy());
        System.out.printf("signature K       : %d   (min cluster size %d, ceiling %d)%n", k, minSize, ceiling);

        List<FlowCluster> clusters = clustersFrom(Path.of(dir), config);
        long totalEpisodes = clusters.stream().mapToLong(FlowCluster::size).sum();
        long underSampled = clusters.stream().filter(FlowCluster::isUnderSampled).count();

        System.out.println("----------------------------------------------------------");
        System.out.println("CLUSTERING");
        System.out.printf("  clusters        : %,d%n", clusters.size());
        System.out.printf("  episodes        : %,d%n", totalEpisodes);
        System.out.printf("  under-sampled   : %,d (size < %d, excluded from baselining)%n",
                underSampled, minSize);
        if (clusters.size() > ceiling) {
            System.out.printf("  WARNING: cluster count %,d exceeds ceiling %,d - K=%d may be too large.%n",
                    clusters.size(), ceiling, k);
        }

        long[] counts = new long[CLUSTER_SIZE_BUCKETS.length];
        for (FlowCluster c : clusters) {
            counts[bucketIndex(CLUSTER_SIZE_BUCKETS, c.size())]++;
        }
        printHist("  cluster-size distribution:", CLUSTER_SIZE_LABELS, counts);

        System.out.println("  top 20 clusters by size:");
        int shown = 0;
        for (FlowCluster c : clusters) {
            if (shown++ >= 20) {
                break;
            }
            Episode rep = c.representative();
            System.out.printf("      [%,d]%s  %s%n", c.size(),
                    c.isUnderSampled() ? " UNDER_SAMPLED" : "", c.signature());
            if (rep != null) {
                System.out.printf("        rep: thread=%s start=%s status=%s%n",
                        rep.threadId(), rep.start(), rep.status());
                System.out.printf("        seq: %s%n",
                        truncate(String.join(" -> ", rep.callSiteSequence()), 300));
            }
        }
    }

    private static final long[] CLUSTER_SIZE_BUCKETS = {1, 9, 49, 199, 999, Long.MAX_VALUE};
    private static final String[] CLUSTER_SIZE_LABELS = {"1", "2-9", "10-49", "50-199", "200-999", ">=1000"};

    /** Shared pipeline: ingest -> segment -> cluster, returning clusters sorted by size. */
    private static List<FlowCluster> clustersFrom(Path dir, AnalysisConfig config) {
        RecordParser parser = new RecordParser(config.profile());
        FileSetReader reader = new FileSetReader(dir, parser, new ParseStats());
        reader.requireMatchRate(config.sampleLines(), config.matchThreshold());
        StreamingSegmenter segmenter = new StreamingSegmenter(config.segmentation().buildStrategy());
        SignatureClusterer clusterer = new SignatureClusterer(config.clustering().signatureK());
        try (Stream<LogRecord> records = reader.records()) {
            segmenter.segment(records, clusterer::add);
        }
        return clusterer.finish(config.clustering().minClusterSize());
    }

    // -- tfa baseline <dir> --config <yaml> ---------------------------------

    private static void baseline(Args args) {
        String dir = args.positional(0);
        String configPath = args.get("config", null);
        if (dir == null || configPath == null) {
            System.err.println("usage: tfa baseline <dir> --config <yaml>");
            System.exit(1);
            return;
        }
        AnalysisConfig config = AnalysisConfig.load(Path.of(configPath));
        List<FlowCluster> clusters = clustersFrom(Path.of(dir), config);

        System.out.printf("profile           : %s%n", config.profile().name());
        System.out.printf("strategy          : %s%n", config.segmentation().strategy());
        if (config.baseline().baselineStart() != null || config.baseline().baselineEnd() != null) {
            System.out.printf("baseline window   : %s -> %s%n",
                    config.baseline().baselineStart(), config.baseline().baselineEnd());
        }

        int baselined = 0;
        for (FlowCluster c : clusters) {
            if (c.isUnderSampled()) {
                continue;
            }
            Baseline b = ConsensusBuilder.build(c, config.baseline());
            if (b == null) {
                continue;
            }
            baselined++;
            System.out.println("==========================================================");
            System.out.printf("cluster: %s%n", c.signature());
            System.out.printf("  episodes baselined : %d (of %d in cluster)%n", b.episodesUsed(), c.size());
            System.out.printf("  modal sequence     : %.1f%% (%d episodes)%n",
                    b.modalShare() * 100, b.modalCount());
            System.out.printf("     %s%n", truncate(String.join(" -> ", b.modalSequence()), 400));
            if (!b.alternatives().isEmpty()) {
                System.out.println("  top alternative sequences:");
                for (Baseline.SequenceShare alt : b.alternatives()) {
                    System.out.printf("     %5.1f%% (%d)  %s%n", alt.share() * 100, alt.count(),
                            truncate(String.join(" -> ", alt.sequence()), 300));
                }
            }
            List<Baseline.TransitionTiming> slow = b.slowestByP95(5);
            if (!slow.isEmpty()) {
                System.out.println("  slowest transitions (by p95):");
                for (Baseline.TransitionTiming t : slow) {
                    System.out.printf("     p95=%,.0fms median=%,.0fms (n=%d)  %s -> %s%n",
                            t.p95Millis(), t.medianMillis(), t.count(), t.from(), t.to());
                }
            }
        }
        System.out.println("==========================================================");
        System.out.printf("baselined %d cluster(s); %d under-sampled skipped.%n",
                baselined, clusters.stream().filter(FlowCluster::isUnderSampled).count());
    }

    // -- tfa analyze <dir> --config <yaml> --out <file> ---------------------

    private static void analyze(Args args) {
        String dir = args.positional(0);
        String configPath = args.get("config", null);
        if (dir == null || configPath == null) {
            System.err.println("usage: tfa analyze <dir> --config <yaml> [--out <file>] [--suppressions <file>]");
            System.exit(1);
            return;
        }
        AnalysisConfig config = AnalysisConfig.load(Path.of(configPath));
        Suppressions suppressions = Suppressions.none();
        String suppPath = args.get("suppressions", null);
        if (suppPath != null) {
            suppressions = Suppressions.load(Path.of(suppPath));
        }

        Analysis.Result r = Analysis.analyze(Path.of(dir), config, suppressions);
        DetectionResult detection = r.detection();
        FindingRanker.RankingResult ranking = r.ranking();

        CorpusFingerprint fingerprint = CorpusFingerprint.of(
                r.orderedFiles(), detection.corpusStart(), detection.corpusEnd());
        String configHash;
        try {
            configHash = Hashing.sha256Hex(java.nio.file.Files.readAllBytes(Path.of(configPath)));
        } catch (java.io.IOException e) {
            throw new java.io.UncheckedIOException(e);
        }
        Report report = new Report(
                Version.VERSION, java.time.Instant.now(), configHash, fingerprint,
                config.profile().name(), config.segmentation().strategy().name(),
                detection.episodesEvaluated(), detection.episodesCensored(), detection.marginMillis(),
                ranking.ranked().size(), ranking.suppressedCount(), ranking.top(),
                detection.clustersTotal(), detection.clustersUnderSampled(),
                detection.episodesSkippedUnderSampled(), config.clustering().minClusterSize());

        TextReporter.render(report, System.out);

        String out = args.get("out", null);
        if (out != null) {
            try {
                java.nio.file.Files.writeString(Path.of(out), JsonReporter.render(report));
                System.out.printf("%n[JSON report written to %s]%n", out);
            } catch (java.io.IOException e) {
                throw new java.io.UncheckedIOException(e);
            }
        }
    }

    // -- tfa validate <dir> --config <yaml> --ground-truth <file> -----------

    private static void validate(Args args) {
        String dir = args.positional(0);
        String configPath = args.get("config", null);
        String gtPath = args.get("ground-truth", null);
        if (dir == null || configPath == null || gtPath == null) {
            System.err.println("usage: tfa validate <dir> --config <yaml> --ground-truth <file>");
            System.exit(1);
            return;
        }
        AnalysisConfig config = AnalysisConfig.load(Path.of(configPath));
        Analysis.Result result = Analysis.analyze(Path.of(dir), config);
        GroundTruth truth = GroundTruth.load(Path.of(gtPath));
        Validator.ValidationReport report = new Validator(result, config).validate(truth);

        System.out.println("==================================================================");
        System.out.println("TFA VALIDATION");
        System.out.println("==================================================================");
        for (Validator.DefectOutcome o : report.outcomes()) {
            String status = o.withinTop(report.topN()) ? "PASS" : (o.found() ? "WARN" : "FAIL");
            System.out.printf("  [%s] %s - %s%n", status, o.id(), o.description());
            if (o.found()) {
                System.out.printf("        found at rank #%d (%s); %s%n", o.rank(), o.type(), o.note());
            } else {
                System.out.printf("        %s%n", o.note());
            }
        }
        System.out.println("------------------------------------------------------------------");
        System.out.printf("  %d of %d defects in the top %d.%n",
                report.passed(), report.outcomes().size(), report.topN());
        if (report.allPassed()) {
            System.out.println("  SUCCESS TEST PASSED.");
        } else {
            System.out.println("  SUCCESS TEST NOT PASSED. Use `tfa explain` on a missing defect.");
            System.exit(4);
        }
    }

    // -- tfa explain <dir> --config <yaml> --thread <id> --at <timestamp> ----

    private static void explain(Args args) {
        String dir = args.positional(0);
        String configPath = args.get("config", null);
        String thread = args.get("thread", null);
        String at = args.get("at", null);
        if (dir == null || configPath == null || thread == null || at == null) {
            System.err.println("usage: tfa explain <dir> --config <yaml> --thread <id> --at <timestamp>");
            System.exit(1);
            return;
        }
        AnalysisConfig config = AnalysisConfig.load(Path.of(configPath));
        Analysis.Result result = Analysis.analyze(Path.of(dir), config);
        Explainer.Trace trace = new Explainer(result, config)
                .explain(thread, java.time.Instant.parse(at));

        System.out.println("==================================================================");
        System.out.printf("TFA EXPLAIN - thread %s at %s%n", thread, at);
        System.out.println("==================================================================");
        for (String l : trace.lines()) {
            System.out.println("  " + l);
        }
        System.out.println("==================================================================");
    }

    // -- tfa detect <dir> --config <yaml> -----------------------------------

    private static void detect(Args args) {
        String dir = args.positional(0);
        String configPath = args.get("config", null);
        if (dir == null || configPath == null) {
            System.err.println("usage: tfa detect <dir> --config <yaml>");
            System.exit(1);
            return;
        }
        AnalysisConfig config = AnalysisConfig.load(Path.of(configPath));
        List<FlowCluster> clusters = clustersFrom(Path.of(dir), config);
        DetectionEngine engine = new DetectionEngine(config.detection(), config.baseline());
        DetectionResult result = engine.detect(clusters);

        System.out.printf("profile           : %s%n", config.profile().name());
        System.out.printf("strategy          : %s%n", config.segmentation().strategy());
        System.out.printf("episodes evaluated: %,d   censored: %,d   censor margin: %,dms%n",
                result.episodesEvaluated(), result.episodesCensored(), result.marginMillis());
        System.out.printf("corpus            : %s -> %s%n", result.corpusStart(), result.corpusEnd());

        List<Finding> all = result.allFindings();
        System.out.println("----------------------------------------------------------");
        System.out.printf("RAW FINDINGS (unranked): %,d%n", all.size());
        for (DetectionResult.ClusterFindings cf : result.perCluster()) {
            if (cf.findings().isEmpty()) {
                continue;
            }
            System.out.printf("  cluster [%d] %s%n", cf.cluster().size(), cf.cluster().signature());
            for (Finding f : cf.findings()) {
                System.out.printf("    %-11s idx=%d  expected=%s (%.0f%%)  observed=%s  thread=%s @ %s%n",
                        f.type(), f.divergenceIndex(), f.expectedCallSite(), f.expectedShare() * 100,
                        f.observed(), f.episode().threadId(), f.episode().start());
            }
        }
        System.out.println("(ranking, dedup and report land in Phase 6 `tfa analyze`.)");
    }

    // -- tfa serve [--port 8080] --------------------------------------------

    private static void serve(Args args) {
        int port = args.getInt("port", 8080);
        String jar = args.get("jar", null);
        try {
            WebServer.start(port, jar == null ? null : Path.of(jar));
            Thread.currentThread().join();   // keep the process alive
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (Exception e) {
            System.err.println("could not start web UI: " + e.getMessage());
            System.err.println("If running from classes (not the shaded jar), pass --jar <path-to-tfa.jar>.");
            System.exit(1);
        }
    }

    // -- tfa detect-format <file> -------------------------------------------

    private static void detectFormat(Args args) {
        String file = args.positional(0);
        if (file == null) {
            System.err.println("usage: tfa detect-format <file> [--sample 500]");
            System.exit(1);
            return;
        }
        int sample = args.getInt("sample", 500);
        FormatDetector.Detected d = FormatDetector.detect(Path.of(file), sample);
        System.out.printf("# detected from %s (%d lines sampled)%n", file, d.sampled());
        System.out.printf("# proposed profile match rate: %.2f%%%n", d.matchRate() * 100);
        System.out.printf("# note: %s%n", d.note());
        System.out.println();
        System.out.print(d.yaml());
        if (d.matchRate() < 0.95) {
            System.out.printf("%n# WARNING: match rate %.2f%% is below 95%%. Review the envelope "
                    + "and timestamp pattern before using this profile.%n", d.matchRate() * 100);
        }
    }

    // -- helpers ------------------------------------------------------------

    private static FormatProfile resolveProfile(Args args) {
        String yaml = args.get("profile", null);
        if (yaml == null) {
            return FormatProfile.defaultProfile();
        }
        String name = args.get("profile-name", null);
        return name == null
                ? ProfileLoader.loadFirst(Path.of(yaml))
                : ProfileLoader.load(Path.of(yaml), name);
    }

    private static void reportMatchFailure(MatchRateException e) {
        MatchRateReport r = e.report();
        System.err.printf("ABORTED: %s%n", e.getMessage());
        System.err.println("The profile does not fit this corpus. Failing (malformed) lines:");
        for (var m : r.failures()) {
            System.err.printf("  %s:%d  %s%n",
                    shortName(m.sourceFile()), m.lineNumberInFile(), truncate(m.text(), 160));
        }
        System.err.println("Fix the profile (try `tfa detect-format <file>`) or lower --threshold.");
    }

    private static long usedHeap() {
        Runtime rt = Runtime.getRuntime();
        return rt.totalMemory() - rt.freeMemory();
    }

    private static double pct(long n, long total) {
        return total == 0 ? 0.0 : 100.0 * n / total;
    }

    private static String shortName(String path) {
        int i = Math.max(path.lastIndexOf('/'), path.lastIndexOf('\\'));
        return i >= 0 ? path.substring(i + 1) : path;
    }

    private static String truncate(String s, int max) {
        return s.length() <= max ? s : s.substring(0, max) + "...";
    }

    private static void usage() {
        System.out.println("""
                tfa - Thread Flow Analyzer

                Usage:
                  tfa parse <dir> [--profile <yaml>] [--profile-name <name>]
                                  [--threshold 0.95] [--sample 1000]
                      Parse a directory and print ingestion statistics.

                  tfa segment <dir> --config <yaml>
                      Segment the corpus into episodes and print distributions.

                  tfa cluster <dir> --config <yaml>
                      Cluster episodes by signature and print the distribution.

                  tfa baseline <dir> --config <yaml>
                      Derive the consensus baseline per cluster and print it.

                  tfa detect <dir> --config <yaml>
                      Run the detectors and list raw (unranked) findings.

                  tfa analyze <dir> --config <yaml> [--out <file>] [--suppressions <file>]
                      Run the full pipeline and print the ranked report (JSON to --out).

                  tfa validate <dir> --config <yaml> --ground-truth <file>
                      Check that each known defect appears in the findings, and at what rank.

                  tfa explain <dir> --config <yaml> --thread <id> --at <timestamp>
                      Print the full reasoning trail for one episode.

                  tfa serve [--port 8080]
                      Start a local web UI to run the pipeline and view the report.

                  tfa detect-format <file> [--sample 500]
                      Sample a file and print a proposed format profile as YAML.
                """);
    }

    private Main() {}
}
