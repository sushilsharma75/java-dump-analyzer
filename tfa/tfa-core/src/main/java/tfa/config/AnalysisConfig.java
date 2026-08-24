package tfa.config;

import org.yaml.snakeyaml.Yaml;
import tfa.ingest.FormatProfile;
import tfa.ingest.ProfileLoader;
import tfa.segment.StrategyKind;

import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The run configuration loaded from a single YAML file. Grows phase by phase;
 * Phase 2 adds the ingest profile selection and the {@link SegmentationConfig}.
 *
 * <pre>
 * profile: default            # name under `profiles:`, or "default"
 * profiles:                   # optional inline profile definitions (§3.4)
 *   myapp:
 *     envelope: '...'
 *     timestampPattern: "yyyy-MM-dd HH:mm:ss.SSS"
 *     zone: "Asia/Kolkata"
 *     capabilities: [CALL_SITE, LEVEL, THREAD]
 * ingest:
 *   matchThreshold: 0.95
 *   sampleLines: 1000
 * segmentation:
 *   strategy: ENTRY_MARKER    # ENTRY_MARKER | IDLE_GAP | CORRELATION_ID
 *   entryCallSites: [com.acme.web.Dispatcher:10]
 *   terminalCallSites: [com.acme.web.Dispatcher:99]
 *   idleGapMillis: 5000
 * </pre>
 */
public final class AnalysisConfig {

    private final FormatProfile profile;
    private final double matchThreshold;
    private final int sampleLines;
    private final SegmentationConfig segmentation;
    private final ClusteringConfig clustering;
    private final BaselineConfig baseline;
    private final DetectionConfig detection;
    private final RankingConfig ranking;

    public AnalysisConfig(FormatProfile profile, double matchThreshold, int sampleLines,
                          SegmentationConfig segmentation, ClusteringConfig clustering,
                          BaselineConfig baseline, DetectionConfig detection, RankingConfig ranking) {
        this.profile = profile;
        this.matchThreshold = matchThreshold;
        this.sampleLines = sampleLines;
        this.segmentation = segmentation;
        this.clustering = clustering;
        this.baseline = baseline;
        this.detection = detection;
        this.ranking = ranking;
    }

    public FormatProfile profile()            { return profile; }
    public double matchThreshold()            { return matchThreshold; }
    public int sampleLines()                  { return sampleLines; }
    public SegmentationConfig segmentation()  { return segmentation; }
    public ClusteringConfig clustering()      { return clustering; }
    public BaselineConfig baseline()          { return baseline; }
    public DetectionConfig detection()        { return detection; }
    public RankingConfig ranking()            { return ranking; }

    @SuppressWarnings("unchecked")
    public static AnalysisConfig load(Path yaml) {
        Map<String, Object> doc;
        try (Reader r = Files.newBufferedReader(yaml, StandardCharsets.UTF_8)) {
            Object loaded = new Yaml().load(r);
            if (!(loaded instanceof Map)) {
                throw new IllegalArgumentException("config is not a YAML mapping: " + yaml);
            }
            doc = (Map<String, Object>) loaded;
        } catch (IOException e) {
            throw new IllegalArgumentException("cannot read config " + yaml, e);
        }

        FormatProfile profile = resolveProfile(doc);

        Map<String, Object> ingest = asMap(doc.get("ingest"));
        double threshold = ingest == null ? 0.95 : asDouble(ingest.get("matchThreshold"), 0.95);
        int sampleLines = ingest == null ? 1000 : asInt(ingest.get("sampleLines"), 1000);

        SegmentationConfig seg = resolveSegmentation(doc);
        ClusteringConfig clustering = resolveClustering(doc);
        BaselineConfig baseline = resolveBaseline(doc);
        DetectionConfig detection = resolveDetection(doc);
        RankingConfig ranking = resolveRanking(doc);

        return new AnalysisConfig(profile, threshold, sampleLines, seg, clustering,
                baseline, detection, ranking);
    }

    private static RankingConfig resolveRanking(Map<String, Object> doc) {
        Map<String, Object> r = asMap(doc.get("ranking"));
        if (r == null) {
            return RankingConfig.defaults();
        }
        Map<String, Object> w = asMap(r.get("weights"));
        RankingConfig d = RankingConfig.defaults();
        double rarity = w == null ? d.rarityWeight() : asDouble(w.get("rarity"), d.rarityWeight());
        double severity = w == null ? d.severityWeight() : asDouble(w.get("severity"), d.severityWeight());
        double error = w == null ? d.errorWeight() : asDouble(w.get("error"), d.errorWeight());
        double magnitude = w == null ? d.magnitudeWeight() : asDouble(w.get("magnitude"), d.magnitudeWeight());
        double clusterSize = w == null ? d.clusterSizeWeight() : asDouble(w.get("clusterSize"), d.clusterSizeWeight());
        double penalty = asDouble(r.get("benignVariantPenalty"), d.benignVariantPenalty());
        int topN = asInt(r.get("topN"), d.topN());
        return new RankingConfig(rarity, severity, error, magnitude, clusterSize, penalty, topN);
    }

    private static DetectionConfig resolveDetection(Map<String, Object> doc) {
        Map<String, Object> d = asMap(doc.get("detection"));
        if (d == null) {
            return DetectionConfig.defaults();
        }
        double factor = asDouble(d.get("timingFactor"), 3.0);
        Long margin = d.get("censorMarginMillis") == null
                ? null : Long.parseLong(String.valueOf(d.get("censorMarginMillis")));
        return new DetectionConfig(factor, margin);
    }

    private static BaselineConfig resolveBaseline(Map<String, Object> doc) {
        Map<String, Object> b = asMap(doc.get("baseline"));
        if (b == null) {
            return BaselineConfig.defaults();
        }
        Map<String, Object> win = asMap(b.get("window"));
        Map<String, Object> eval = asMap(b.get("evalWindow"));
        Instant bStart = instant(win, "start");
        Instant bEnd = instant(win, "end");
        Instant eStart = instant(eval, "start");
        Instant eEnd = instant(eval, "end");
        int alts = asInt(b.get("alternatives"), 3);
        return new BaselineConfig(bStart, bEnd, eStart, eEnd, alts);
    }

    private static Instant instant(Map<String, Object> map, String key) {
        if (map == null || map.get(key) == null) {
            return null;
        }
        return Instant.parse(String.valueOf(map.get(key)));
    }

    private static ClusteringConfig resolveClustering(Map<String, Object> doc) {
        Map<String, Object> c = asMap(doc.get("clustering"));
        if (c == null) {
            return ClusteringConfig.defaults();
        }
        int k = asInt(c.get("signatureK"), 3);
        int minSize = asInt(c.get("minClusterSize"), 10);
        int ceiling = asInt(c.get("clusterCeiling"), 200);
        return new ClusteringConfig(k, minSize, ceiling);
    }

    @SuppressWarnings("unchecked")
    private static FormatProfile resolveProfile(Map<String, Object> doc) {
        String name = doc.get("profile") == null ? "default" : String.valueOf(doc.get("profile"));
        Map<String, Object> profiles = asMap(doc.get("profiles"));
        if (profiles != null && profiles.containsKey(name)) {
            return ProfileLoader.fromMap(name, (Map<String, Object>) profiles.get(name));
        }
        if (!"default".equals(name)) {
            throw new IllegalArgumentException("profile '" + name + "' not defined under 'profiles:'");
        }
        return FormatProfile.defaultProfile();
    }

    private static SegmentationConfig resolveSegmentation(Map<String, Object> doc) {
        Map<String, Object> seg = asMap(doc.get("segmentation"));
        if (seg == null) {
            throw new IllegalArgumentException("config missing required 'segmentation' section");
        }
        StrategyKind strategy = StrategyKind.valueOf(
                String.valueOf(seg.getOrDefault("strategy", "ENTRY_MARKER")).trim());
        Set<String> entries = asStringSet(seg.get("entryCallSites"));
        Set<String> terminals = asStringSet(seg.get("terminalCallSites"));
        long idleGap = asLong(seg.get("idleGapMillis"), 5000L);
        Object corr = seg.get("correlationIdPattern");
        String correlationIdPattern = corr == null ? "" : String.valueOf(corr);
        return new SegmentationConfig(strategy, entries, terminals, idleGap, correlationIdPattern);
    }

    // -- small YAML coercion helpers ----------------------------------------

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(Object o) {
        return o instanceof Map ? (Map<String, Object>) o : null;
    }

    private static Set<String> asStringSet(Object o) {
        Set<String> out = new LinkedHashSet<>();
        if (o instanceof List<?> list) {
            for (Object e : list) {
                out.add(String.valueOf(e).trim());
            }
        }
        return out;
    }

    private static double asDouble(Object o, double dflt) {
        return o == null ? dflt : Double.parseDouble(String.valueOf(o));
    }

    private static int asInt(Object o, int dflt) {
        return o == null ? dflt : Integer.parseInt(String.valueOf(o));
    }

    private static long asLong(Object o, long dflt) {
        return o == null ? dflt : Long.parseLong(String.valueOf(o));
    }
}
