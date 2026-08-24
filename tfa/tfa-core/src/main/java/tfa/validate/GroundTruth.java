package tfa.validate;

import org.yaml.snakeyaml.Yaml;

import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Known defects recorded manually before implementation (§6). The success test:
 * every listed defect must appear in the top findings.
 *
 * <pre>
 * defects:
 *   - id: DEF-1
 *     threadId: exec-3
 *     timestampWindow:
 *       start: "2026-08-20T10:00:00Z"
 *       end:   "2026-08-20T10:05:00Z"
 *     expectedDivergenceCallSite: "com.acme.repo.OrderRepository:30"
 *     description: "DB timeout wrong branch that never completes"
 * </pre>
 */
public record GroundTruth(List<Defect> defects) {

    public record Defect(String id, String threadId, Instant windowStart, Instant windowEnd,
                         String expectedDivergenceCallSite, String description) {
        /** True if {@code t} falls within the defect's timestamp window (unbounded ends pass). */
        public boolean contains(Instant t) {
            if (t == null) {
                return false;
            }
            if (windowStart != null && t.isBefore(windowStart)) {
                return false;
            }
            return windowEnd == null || !t.isAfter(windowEnd);
        }
    }

    @SuppressWarnings("unchecked")
    public static GroundTruth load(Path yaml) {
        Map<String, Object> doc;
        try (Reader r = Files.newBufferedReader(yaml, StandardCharsets.UTF_8)) {
            Object loaded = new Yaml().load(r);
            if (!(loaded instanceof Map)) {
                throw new IllegalArgumentException("ground-truth file is not a YAML mapping: " + yaml);
            }
            doc = (Map<String, Object>) loaded;
        } catch (IOException e) {
            throw new IllegalArgumentException("cannot read ground-truth " + yaml, e);
        }

        List<Defect> defects = new ArrayList<>();
        Object list = doc.get("defects");
        if (list instanceof List<?> items) {
            for (Object item : items) {
                if (item instanceof Map<?, ?> m) {
                    Map<?, ?> window = m.get("timestampWindow") instanceof Map<?, ?> w ? w : Map.of();
                    defects.add(new Defect(
                            str(m.get("id")),
                            str(m.get("threadId")),
                            instant(window.get("start")),
                            instant(window.get("end")),
                            str(m.get("expectedDivergenceCallSite")),
                            str(m.get("description"))));
                }
            }
        }
        return new GroundTruth(defects);
    }

    private static String str(Object o) {
        return o == null ? null : String.valueOf(o);
    }

    private static Instant instant(Object o) {
        return o == null ? null : Instant.parse(String.valueOf(o));
    }
}
