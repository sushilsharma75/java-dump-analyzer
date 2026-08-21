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
import tfa.model.Episode;
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
                case "detect-format" -> detectFormat(new Args(argv, 1));
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
                tfa — Thread Flow Analyzer

                Usage:
                  tfa parse <dir> [--profile <yaml>] [--profile-name <name>]
                                  [--threshold 0.95] [--sample 1000]
                      Parse a directory and print ingestion statistics.

                  tfa segment <dir> --config <yaml>
                      Segment the corpus into episodes and print distributions.

                  tfa detect-format <file> [--sample 500]
                      Sample a file and print a proposed format profile as YAML.
                """);
    }

    private Main() {}
}
