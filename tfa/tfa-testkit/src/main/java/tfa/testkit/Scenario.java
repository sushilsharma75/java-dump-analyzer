package tfa.testkit;

import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Generates a synthetic corpus of known flows running on a pool of reused
 * threads, interleaved in time, with ground-truth episode boundaries. Used to
 * verify that segmentation recovers the known boundaries exactly.
 *
 * <p>Each thread runs a series of episodes separated by an idle gap; within an
 * episode records are spaced by a small gap. Threads are staggered so their
 * records interleave in the merged, time-ordered stream — exactly the condition
 * segmentation must survive.
 */
public final class Scenario {

    /** A flow definition: an ordered list of call sites. First is entry, last is terminal. */
    public record FlowDef(String name, List<String> callSites) {
        public String entry()    { return callSites.get(0); }
        public String terminal() { return callSites.get(callSites.size() - 1); }
    }

    /** Ground truth for one thread: the ordered call-site sequences of its episodes. */
    public record Truth(String threadId, List<List<String>> episodeSequences) {}

    public record Result(
            List<Path> files,
            List<Truth> truths,
            Set<String> entryCallSites,
            Set<String> terminalCallSites
    ) {}

    private final List<FlowDef> flows;
    private int threadCount = 4;
    private int episodesPerThread = 5;
    private long withinGapMillis = 50;
    private long idleGapMillis = 10_000;
    private int files = 3;
    private Instant start = Instant.parse("2026-08-20T10:00:00Z");

    public Scenario(List<FlowDef> flows) {
        this.flows = List.copyOf(flows);
    }

    public Scenario threads(int n)          { this.threadCount = n; return this; }
    public Scenario episodesPerThread(int n){ this.episodesPerThread = n; return this; }
    public Scenario withinGapMillis(long m) { this.withinGapMillis = m; return this; }
    public Scenario idleGapMillis(long m)   { this.idleGapMillis = m; return this; }
    public Scenario files(int n)            { this.files = n; return this; }
    public Scenario start(Instant t)        { this.start = t; return this; }

    /** One generated event, carrying its absolute timestamp for the merge sort. */
    private record TimedEvent(long ts, SyntheticLogGenerator.Event event) {}

    public Result generate(Path dir) {
        List<TimedEvent> all = new ArrayList<>();
        List<Truth> truths = new ArrayList<>();
        Set<String> entries = new LinkedHashSet<>();
        Set<String> terminals = new LinkedHashSet<>();
        for (FlowDef f : flows) {
            entries.add(f.entry());
            terminals.add(f.terminal());
        }

        long base = start.toEpochMilli();
        for (int t = 0; t < threadCount; t++) {
            String threadId = "exec-" + t;
            // stagger threads by a fraction of the within-gap so records interleave
            long clock = base + t * (withinGapMillis / 2 + 1);
            List<List<String>> episodeSeqs = new ArrayList<>();
            for (int e = 0; e < episodesPerThread; e++) {
                FlowDef flow = flows.get((t + e) % flows.size());
                List<String> seq = new ArrayList<>();
                for (String cs : flow.callSites()) {
                    all.add(new TimedEvent(clock, new SyntheticLogGenerator.Event(
                            Instant.ofEpochMilli(clock), "INFO", threadId, cs,
                            flow.name() + " ep" + e)));
                    seq.add(cs);
                    clock += withinGapMillis;
                }
                episodeSeqs.add(seq);
                clock += idleGapMillis; // idle gap before the next episode on this thread
            }
            truths.add(new Truth(threadId, episodeSeqs));
        }

        // merge by timestamp (stable), then split into files by time order
        all.sort((a, b) -> Long.compare(a.ts(), b.ts()));
        List<Path> written = new ArrayList<>();
        int n = all.size();
        int perFile = Math.max(1, (int) Math.ceil((double) n / files));
        int fileIdx = 0;
        for (int i = 0; i < n; i += perFile) {
            List<SyntheticLogGenerator.Event> chunk = new ArrayList<>();
            for (int j = i; j < Math.min(i + perFile, n); j++) {
                chunk.add(all.get(j).event());
            }
            Path file = dir.resolve(String.format("app-%02d.log", fileIdx++));
            SyntheticLogGenerator.writeFile(file, chunk);
            written.add(file);
        }

        return new Result(written, truths, entries, terminals);
    }
}
