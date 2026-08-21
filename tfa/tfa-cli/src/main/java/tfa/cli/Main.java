package tfa.cli;

import tfa.ingest.FileSetReader;
import tfa.ingest.FormatDetector;
import tfa.ingest.FormatProfile;
import tfa.ingest.MatchRateException;
import tfa.ingest.MatchRateReport;
import tfa.ingest.ParseStats;
import tfa.ingest.ProfileLoader;
import tfa.ingest.RecordParser;
import tfa.model.LogRecord;

import java.nio.file.Path;
import java.time.Instant;
import java.util.HashSet;
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

                  tfa detect-format <file> [--sample 500]
                      Sample a file and print a proposed format profile as YAML.
                """);
    }

    private Main() {}
}
