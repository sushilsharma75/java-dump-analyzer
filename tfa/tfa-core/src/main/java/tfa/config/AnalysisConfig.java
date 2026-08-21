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

    public AnalysisConfig(FormatProfile profile, double matchThreshold, int sampleLines,
                          SegmentationConfig segmentation, ClusteringConfig clustering,
                          BaselineConfig baseline) {
        this.profile = profile;
        this.matchThreshold = matchThreshold;
        this.sampleLines = sampleLines;
        this.segmentation = segmentation;
        this.clustering = clustering;
        this.baseline = baseline;
    }

    public FormatProfile profile()            { return profile; }
    public double matchThreshold()            { return matchThreshold; }
    public int sampleLines()                  { return sampleLines; }
    public SegmentationConfig segmentation()  { return segmentation; }
    public ClusteringConfig clustering()      { return clustering; }
    public BaselineConfig baseline()          { return baseline; }

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

        return new AnalysisConfig(profile, threshold, sampleLines, seg, clustering, baseline);
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
        return new SegmentationConfig(strategy, entries, terminals, idleGap);
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
