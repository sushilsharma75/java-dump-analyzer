package tfa.ingest;

import org.yaml.snakeyaml.Yaml;

import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Loads {@link FormatProfile}s from YAML (§3.4). The document shape is:
 *
 * <pre>
 * profiles:
 *   payments-api:
 *     envelope: '^(?&lt;ts&gt;...)...$'
 *     timestampPattern: "yyyy-MM-dd HH:mm:ss.SSS"
 *     zone: "Asia/Kolkata"
 *     capabilities: [CALL_SITE, LEVEL, THREAD]
 * </pre>
 *
 * A single-profile document (the inner map without the {@code profiles} wrapper)
 * is also accepted.
 */
public final class ProfileLoader {

    private ProfileLoader() {}

    /** Load the named profile from a YAML file. */
    public static FormatProfile load(Path yaml, String name) {
        Map<String, Object> doc = read(yaml);
        Map<String, Object> profiles = section(doc);
        Object entry = profiles.get(name);
        if (!(entry instanceof Map)) {
            throw new IllegalArgumentException(
                    "profile '" + name + "' not found in " + yaml + "; available: " + profiles.keySet());
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> map = (Map<String, Object>) entry;
        return fromMap(name, map);
    }

    /** Load the first profile defined in a YAML file. */
    public static FormatProfile loadFirst(Path yaml) {
        Map<String, Object> profiles = section(read(yaml));
        if (profiles.isEmpty()) {
            throw new IllegalArgumentException("no profiles defined in " + yaml);
        }
        String name = profiles.keySet().iterator().next();
        @SuppressWarnings("unchecked")
        Map<String, Object> map = (Map<String, Object>) profiles.get(name);
        return fromMap(name, map);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> read(Path yaml) {
        try (Reader r = Files.newBufferedReader(yaml, StandardCharsets.UTF_8)) {
            Object loaded = new Yaml().load(r);
            if (!(loaded instanceof Map)) {
                throw new IllegalArgumentException("not a YAML mapping: " + yaml);
            }
            return (Map<String, Object>) loaded;
        } catch (IOException e) {
            throw new IllegalArgumentException("cannot read " + yaml, e);
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> section(Map<String, Object> doc) {
        Object p = doc.get("profiles");
        if (p instanceof Map) {
            return (Map<String, Object>) p;
        }
        // treat the document itself as a single {name: profileMap} mapping
        return doc;
    }

    public static FormatProfile fromMap(String name, Map<String, Object> map) {
        String envelope = str(map, "envelope", true);
        String tsPattern = str(map, "timestampPattern", false);
        String zoneStr = str(map, "zone", false);
        ZoneId zone = zoneStr == null ? ZoneId.of("UTC") : ZoneId.of(zoneStr);

        Set<Capability> caps = EnumSet.noneOf(Capability.class);
        Object capList = map.get("capabilities");
        if (capList instanceof List<?> list) {
            for (Object c : list) {
                caps.add(Capability.valueOf(String.valueOf(c).trim()));
            }
        }
        return new FormatProfile(name, envelope, tsPattern, zone, caps);
    }

    private static String str(Map<String, Object> map, String key, boolean required) {
        Object v = map.get(key);
        if (v == null) {
            if (required) {
                throw new IllegalArgumentException("profile missing required key '" + key + "'");
            }
            return null;
        }
        return String.valueOf(v);
    }

    /** Render a profile back to YAML text (used by {@code detect-format}). */
    public static String toYaml(FormatProfile p) {
        List<String> capNames = new ArrayList<>();
        for (Capability c : p.capabilities()) {
            capNames.add(c.name());
        }
        StringBuilder sb = new StringBuilder();
        sb.append("profiles:\n");
        sb.append("  ").append(p.name()).append(":\n");
        sb.append("    envelope: '").append(p.envelope().pattern().replace("'", "''")).append("'\n");
        if (p.timestampPattern() != null) {
            sb.append("    timestampPattern: \"").append(p.timestampPattern()).append("\"\n");
        }
        sb.append("    zone: \"").append(p.zone()).append("\"\n");
        sb.append("    capabilities: [").append(String.join(", ", capNames)).append("]\n");
        return sb.toString();
    }
}
