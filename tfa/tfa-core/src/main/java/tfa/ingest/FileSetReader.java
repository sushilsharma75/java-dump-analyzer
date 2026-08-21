package tfa.ingest;

import tfa.model.LogRecord;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;
import java.util.zip.GZIPInputStream;

/**
 * Presents a directory of log files as one continuous, lazily-evaluated stream
 * of {@link LogRecord}. Memory stays flat over an arbitrarily large corpus:
 * only the current open record's continuation lines are held.
 *
 * <p>Files are ordered by the first parseable timestamp inside each file, never
 * by filename — log-rotation naming is unreliable. Because an open record is
 * carried across file boundaries, a record whose continuation lines are split
 * across a rotation boundary is reconstructed correctly.
 */
public final class FileSetReader {

    private static final int FIRST_TS_SCAN_LIMIT = 5000;

    private final List<Path> orderedFiles;
    private final RecordParser parser;
    private final ParseStats stats;

    public FileSetReader(Path root, RecordParser parser) {
        this(root, parser, new ParseStats());
    }

    public FileSetReader(Path root, RecordParser parser, ParseStats stats) {
        this.parser = parser;
        this.stats = stats;
        this.orderedFiles = orderByTimestamp(collectFiles(root), parser);
    }

    public List<Path> orderedFiles() { return List.copyOf(orderedFiles); }

    public ParseStats stats() { return stats; }

    // -- file discovery & ordering ------------------------------------------

    private static List<Path> collectFiles(Path root) {
        try {
            if (Files.isRegularFile(root)) {
                return List.of(root);
            }
            try (Stream<Path> walk = Files.walk(root)) {
                return walk.filter(Files::isRegularFile).collect(Collectors.toList());
            }
        } catch (IOException e) {
            throw new UncheckedIOException("cannot enumerate " + root, e);
        }
    }

    private static List<Path> orderByTimestamp(List<Path> files, RecordParser parser) {
        record Keyed(Path path, Instant firstTs) {}
        List<Keyed> keyed = new ArrayList<>(files.size());
        for (Path p : files) {
            keyed.add(new Keyed(p, firstTimestamp(p, parser)));
        }
        keyed.sort(Comparator
                .comparing((Keyed k) -> k.firstTs(),
                        Comparator.nullsLast(Comparator.naturalOrder()))
                .thenComparing(k -> k.path().toString()));
        return keyed.stream().map(Keyed::path).collect(Collectors.toList());
    }

    private static Instant firstTimestamp(Path path, RecordParser parser) {
        try (BufferedReader r = open(path)) {
            String line;
            int scanned = 0;
            while ((line = r.readLine()) != null && scanned++ < FIRST_TS_SCAN_LIMIT) {
                RecordParser.Envelope env = parser.tryMatch(line);
                if (env != null && env.ts() != null) {
                    Instant ts = parser.parseTimestamp(env.ts());
                    if (ts != null) {
                        return ts;
                    }
                }
            }
        } catch (IOException e) {
            // unreadable file sorts last; do not fail the whole run here
        }
        return null;
    }

    private static BufferedReader open(Path path) throws IOException {
        if (path.getFileName().toString().endsWith(".gz")) {
            return new BufferedReader(new InputStreamReader(
                    new GZIPInputStream(Files.newInputStream(path)), StandardCharsets.UTF_8));
        }
        return Files.newBufferedReader(path, StandardCharsets.UTF_8);
    }

    // -- match-rate sampling ------------------------------------------------

    /**
     * Sample up to {@code sampleLines} lines from the head of the corpus and
     * compute the match rate {@code matched / (matched + malformed)}, excluding
     * continuation lines. Does not mutate the reader's {@link ParseStats}.
     */
    public MatchRateReport checkMatchRate(int sampleLines) {
        long matched = 0, continuation = 0, malformed = 0, seen = 0;
        boolean recordOpen = false;
        List<ParseStats.MalformedLine> failures = new ArrayList<>();
        outer:
        for (Path p : orderedFiles) {
            long lineNo = 0;
            try (BufferedReader r = open(p)) {
                String line;
                while ((line = r.readLine()) != null) {
                    lineNo++;
                    if (seen >= sampleLines) {
                        break outer;
                    }
                    seen++;
                    if (parser.tryMatch(line) != null) {
                        matched++;
                        recordOpen = true;
                    } else if (recordOpen) {
                        continuation++;
                    } else {
                        malformed++;
                        if (failures.size() < 20 && !line.isBlank()) {
                            failures.add(new ParseStats.MalformedLine(
                                    p.toString(), lineNo, line));
                        }
                    }
                }
            } catch (IOException e) {
                throw new UncheckedIOException("cannot sample " + p, e);
            }
        }
        long denom = matched + malformed;
        double rate = denom == 0 ? 0.0 : (double) matched / denom;
        return new MatchRateReport(seen, matched, continuation, malformed, rate, failures);
    }

    /** Sample and throw {@link MatchRateException} if below {@code threshold}. */
    public MatchRateReport requireMatchRate(int sampleLines, double threshold) {
        MatchRateReport rep = checkMatchRate(sampleLines);
        if (!rep.meets(threshold)) {
            throw new MatchRateException(rep, threshold);
        }
        return rep;
    }

    // -- the record stream --------------------------------------------------

    /** A lazily-evaluated, ordered stream of records over the whole file set. */
    public Stream<LogRecord> records() {
        RecordIterator it = new RecordIterator();
        return StreamSupport.stream(
                        Spliterators.spliteratorUnknownSize(it,
                                Spliterator.ORDERED | Spliterator.NONNULL),
                        false)
                .onClose(it::close);
    }

    private final class RecordIterator implements Iterator<LogRecord>, AutoCloseable {
        private final Iterator<Path> fileIt = orderedFiles.iterator();
        private BufferedReader reader;
        private String currentFile;
        private long lineNoInFile;

        // the open (pending) record carried across file boundaries
        private RecordParser.Envelope pendingEnv;
        private List<String> pendingCont;
        private String pendingFile;
        private long pendingLine;

        private LogRecord lookahead;
        private boolean finished;

        @Override
        public boolean hasNext() {
            if (lookahead != null) {
                return true;
            }
            if (finished) {
                return false;
            }
            lookahead = computeNext();
            if (lookahead == null) {
                finished = true;
                close();
                return false;
            }
            return true;
        }

        @Override
        public LogRecord next() {
            if (!hasNext()) {
                throw new NoSuchElementException();
            }
            LogRecord r = lookahead;
            lookahead = null;
            return r;
        }

        private LogRecord computeNext() {
            try {
                String line;
                while ((line = nextLine()) != null) {
                    String file = currentFile;
                    long ln = lineNoInFile;
                    RecordParser.Envelope env = parser.tryMatch(line);
                    if (env != null) {
                        stats.count(LineBucket.MATCHED, file, ln, line);
                        if (pendingEnv != null) {
                            LogRecord rec = flushPending();
                            startPending(env, file, ln);
                            return rec;
                        }
                        startPending(env, file, ln);
                    } else if (pendingEnv != null) {
                        stats.count(LineBucket.CONTINUATION, file, ln, line);
                        pendingCont.add(line);
                    } else {
                        stats.count(LineBucket.MALFORMED, file, ln, line);
                    }
                }
                // global EOF: emit the final open record, if any
                if (pendingEnv != null) {
                    return flushPending();
                }
                return null;
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }

        private void startPending(RecordParser.Envelope env, String file, long ln) {
            pendingEnv = env;
            pendingCont = new ArrayList<>();
            pendingFile = file;
            pendingLine = ln;
        }

        private LogRecord flushPending() {
            LogRecord rec = parser.build(pendingEnv, pendingCont, pendingFile, pendingLine, stats);
            pendingEnv = null;
            pendingCont = null;
            return rec;
        }

        private String nextLine() throws IOException {
            while (true) {
                if (reader == null) {
                    if (!fileIt.hasNext()) {
                        return null;
                    }
                    Path p = fileIt.next();
                    currentFile = p.toString();
                    reader = open(p);
                    lineNoInFile = 0;
                }
                String line = reader.readLine();
                if (line == null) {
                    reader.close();
                    reader = null;
                    continue;
                }
                lineNoInFile++;
                return line;
            }
        }

        @Override
        public void close() {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException ignored) {
                    // best effort
                }
                reader = null;
            }
        }
    }
}
