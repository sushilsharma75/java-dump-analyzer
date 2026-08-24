package tfa.rank;

import org.yaml.snakeyaml.Yaml;
import tfa.model.FindingType;

import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * A list of known-benign (cluster signature, divergence call site, finding type)
 * tuples with reasons. Suppressed findings are excluded from the top N but counted
 * in a one-line summary — the practical workflow: mark a known variant once and
 * rerun clean, instead of re-triaging the same noise every time.
 *
 * <pre>
 * suppressions:
 *   - clusterSignature: "A:1 &gt; B:2"     # optional; matches any if omitted
 *     divergenceCallSite: "X:9"          # optional
 *     type: DIVERGENCE                    # optional
 *     reason: "known benign fallback path"
 * </pre>
 *
 * A rule matches a finding when every field it specifies equals the finding's.
 */
public final class Suppressions {

    /** One suppression rule; null fields are wildcards. */
    public record Rule(String clusterSignature, String divergenceCallSite,
                       FindingType type, String reason) {
        boolean matches(RankedFinding f) {
            if (clusterSignature != null && !clusterSignature.equals(f.clusterSignature())) {
                return false;
            }
            if (divergenceCallSite != null
                    && !divergenceCallSite.equals(f.representative().divergenceCallSite())) {
                return false;
            }
            return type == null || type == f.representative().type();
        }
    }

    private final List<Rule> rules;

    public Suppressions(List<Rule> rules) {
        this.rules = List.copyOf(rules);
    }

    public static Suppressions none() {
        return new Suppressions(List.of());
    }

    public boolean isEmpty() {
        return rules.isEmpty();
    }

    /** The reason the finding is suppressed, or null if no rule matches. */
    public String reasonFor(RankedFinding f) {
        for (Rule r : rules) {
            if (r.matches(f)) {
                return r.reason() == null ? "suppressed" : r.reason();
            }
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    public static Suppressions load(Path yaml) {
        Map<String, Object> doc;
        try (Reader r = Files.newBufferedReader(yaml, StandardCharsets.UTF_8)) {
            Object loaded = new Yaml().load(r);
            if (loaded == null) {
                return none();
            }
            if (!(loaded instanceof Map)) {
                throw new IllegalArgumentException("suppressions file is not a YAML mapping: " + yaml);
            }
            doc = (Map<String, Object>) loaded;
        } catch (IOException e) {
            throw new IllegalArgumentException("cannot read suppressions " + yaml, e);
        }

        List<Rule> rules = new ArrayList<>();
        Object list = doc.get("suppressions");
        if (list instanceof List<?> items) {
            for (Object item : items) {
                if (item instanceof Map<?, ?> m) {
                    rules.add(new Rule(
                            str(m.get("clusterSignature")),
                            str(m.get("divergenceCallSite")),
                            m.get("type") == null ? null
                                    : FindingType.valueOf(String.valueOf(m.get("type")).trim()),
                            str(m.get("reason"))));
                }
            }
        }
        return new Suppressions(rules);
    }

    private static String str(Object o) {
        return o == null ? null : String.valueOf(o);
    }
}
