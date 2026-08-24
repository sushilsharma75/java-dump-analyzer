package tfa.pipeline;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import tfa.ingest.FileSetReader;
import tfa.ingest.FormatProfile;
import tfa.ingest.RecordParser;
import tfa.model.Episode;
import tfa.segment.EntryMarkerStrategy;
import tfa.segment.FlowKeyStrategy;
import tfa.segment.IdleGapStrategy;
import tfa.segment.StreamingSegmenter;
import tfa.testkit.Scenario;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * End-to-end: generate an interleaved synthetic corpus with known flows on a
 * reused thread pool, run the real ingest -> segment pipeline, and verify both
 * strategies recover the known episode boundaries exactly.
 */
class SegmentationPipelineTest {

    private static final List<Scenario.FlowDef> FLOWS = List.of(
            new Scenario.FlowDef("login", List.of("com.acme.Login:10", "com.acme.Token:20", "com.acme.Login:99")),
            new Scenario.FlowDef("order", List.of("com.acme.Order:10", "com.acme.Repo:20", "com.acme.Order:99")),
            new Scenario.FlowDef("batch", List.of("com.acme.Batch:10", "com.acme.Job:20", "com.acme.Job:30", "com.acme.Batch:99"))
    );

    private static Scenario.Result generate(Path dir) {
        return new Scenario(FLOWS)
                .threads(4)
                .episodesPerThread(5)
                .withinGapMillis(50)
                .idleGapMillis(10_000)
                .files(3)
                .generate(dir);
    }

    private static List<Episode> run(Path dir, FlowKeyStrategy strategy) {
        RecordParser parser = new RecordParser(FormatProfile.defaultProfile());
        FileSetReader reader = new FileSetReader(dir, parser);
        StreamingSegmenter segmenter = new StreamingSegmenter(strategy);
        List<Episode> eps = new ArrayList<>();
        try (var s = reader.records()) {
            segmenter.segment(s, eps::add);
        }
        return eps;
    }

    /** Recovered per-thread ordered sequences, keyed by thread for comparison. */
    private static Map<String, List<List<String>>> byThread(List<Episode> eps) {
        Map<String, List<List<String>>> out = new TreeMap<>();
        for (Episode e : eps) {
            out.computeIfAbsent(e.threadId(), k -> new ArrayList<>()).add(e.callSiteSequence());
        }
        return out;
    }

    private static Map<String, List<List<String>>> expected(Scenario.Result r) {
        Map<String, List<List<String>>> out = new TreeMap<>();
        for (Scenario.Truth t : r.truths()) {
            out.put(t.threadId(), t.episodeSequences());
        }
        return out;
    }

    @Test
    void entryMarkerRecoversBoundariesExactly(@TempDir Path dir) {
        Scenario.Result r = generate(dir);
        FlowKeyStrategy strategy = new EntryMarkerStrategy(r.entryCallSites(), r.terminalCallSites());
        assertEquals(expected(r), byThread(run(dir, strategy)));
    }

    @Test
    void idleGapRecoversBoundariesExactly(@TempDir Path dir) {
        Scenario.Result r = generate(dir);
        // threshold sits in the valley: above the 50ms within-episode gap,
        // below the 10s idle gap between episodes
        FlowKeyStrategy strategy = new IdleGapStrategy(5_000, r.terminalCallSites());
        assertEquals(expected(r), byThread(run(dir, strategy)));
    }
}
