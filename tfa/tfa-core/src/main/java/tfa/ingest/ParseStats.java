package tfa.ingest;

import java.util.ArrayList;
import java.util.List;

/**
 * Mutable line-accounting counters accumulated while a corpus streams past.
 * Every input line increments exactly one bucket, so
 * {@code matched + continuation + malformed == totalLines}.
 */
public final class ParseStats {

    /** A malformed line kept for the sample surfaced to the user. */
    public record MalformedLine(String sourceFile, long lineNumberInFile, String text) {}

    private long matched;
    private long continuation;
    private long malformed;
    private long totalLines;
    private long timestampParseFailures;
    private final List<MalformedLine> malformedSample = new ArrayList<>();
    private final int sampleLimit;

    public ParseStats() { this(20); }

    public ParseStats(int sampleLimit) { this.sampleLimit = sampleLimit; }

    void count(LineBucket bucket, String sourceFile, long lineNumberInFile, String text) {
        totalLines++;
        switch (bucket) {
            case MATCHED -> matched++;
            case CONTINUATION -> continuation++;
            case MALFORMED -> {
                malformed++;
                if (malformedSample.size() < sampleLimit && !text.isBlank()) {
                    malformedSample.add(new MalformedLine(sourceFile, lineNumberInFile, text));
                }
            }
        }
    }

    void countTimestampFailure() { timestampParseFailures++; }

    public long matched()                { return matched; }
    public long continuation()           { return continuation; }
    public long malformed()              { return malformed; }
    public long totalLines()             { return totalLines; }
    public long records()                { return matched; }
    public long timestampParseFailures() { return timestampParseFailures; }
    public List<MalformedLine> malformedSample() { return List.copyOf(malformedSample); }
}
