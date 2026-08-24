package tfa.report;

import tfa.model.Finding;
import tfa.rank.RankedFinding;
import tfa.rank.ScoreBreakdown;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Renders a {@link Report} as JSON. Key order is fixed, so output is stable. */
public final class JsonReporter {

    private JsonReporter() {}

    public static String render(Report r) {
        Map<String, Object> root = new LinkedHashMap<>();

        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("toolVersion", r.toolVersion());
        meta.put("runTimestamp", String.valueOf(r.runTimestamp()));
        meta.put("configHash", r.configHash());
        meta.put("corpusHash", r.corpus().hash());
        meta.put("corpusStart", String.valueOf(r.corpus().corpusStart()));
        meta.put("corpusEnd", String.valueOf(r.corpus().corpusEnd()));
        meta.put("profile", r.profileName());
        meta.put("strategy", r.strategyName());
        List<Object> files = new ArrayList<>();
        for (CorpusFingerprint.FileEntry fe : r.corpus().files()) {
            Map<String, Object> f = new LinkedHashMap<>();
            f.put("name", fe.name());
            f.put("sizeBytes", fe.sizeBytes());
            files.add(f);
        }
        meta.put("files", files);
        root.put("meta", meta);

        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("episodesEvaluated", r.episodesEvaluated());
        summary.put("episodesCensored", r.episodesCensored());
        summary.put("censorMarginMillis", r.censorMarginMillis());
        summary.put("totalFindings", r.totalFindings());
        summary.put("suppressedCount", r.suppressedCount());
        summary.put("clustersTotal", r.clustersTotal());
        summary.put("clustersUnderSampled", r.clustersUnderSampled());
        summary.put("episodesSkippedUnderSampled", r.episodesSkippedUnderSampled());
        summary.put("minClusterSize", r.minClusterSize());
        summary.put("noFindingsReason", r.top().isEmpty()
                ? String.join("\n", TextReporter.noFindingsExplanation(r)) : "");
        root.put("summary", summary);

        List<Object> findings = new ArrayList<>();
        int rank = 1;
        for (RankedFinding rf : r.top()) {
            findings.add(finding(rank++, rf));
        }
        root.put("findings", findings);

        return Json.write(root);
    }

    private static Map<String, Object> finding(int rank, RankedFinding rf) {
        Finding f = rf.representative();
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("rank", rank);
        m.put("score", rf.score());
        m.put("type", f.type().name());
        m.put("occurrences", rf.occurrences());
        m.put("clusterSignature", rf.clusterSignature());
        m.put("clusterSize", rf.clusterSize());
        m.put("divergenceCallSite", f.divergenceCallSite());
        m.put("divergenceIndex", f.divergenceIndex());
        m.put("expectedCallSite", f.expectedCallSite());
        m.put("expectedShare", f.expectedShare());
        m.put("observed", f.observed());
        m.put("exampleThread", f.episode().threadId());
        m.put("exampleTimestamp", String.valueOf(f.episode().start()));

        ScoreBreakdown b = rf.breakdown();
        Map<String, Object> score = new LinkedHashMap<>();
        score.put("rarity", b.rarity());
        score.put("severity", b.severity());
        score.put("errorPresence", b.errorPresence());
        score.put("magnitude", b.magnitude());
        score.put("clusterTrust", b.clusterTrust());
        score.put("variantPenalty", b.variantPenalty());
        m.put("scoreBreakdown", score);

        m.put("logContext", new ArrayList<Object>(LogContext.lines(f, 5, 5)));
        return m;
    }
}
