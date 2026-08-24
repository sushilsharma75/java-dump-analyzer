package tfa.ingest;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.zip.GZIPInputStream;

/**
 * Format auto-detection (Phase 1, first-class feature). Samples lines from a
 * file, infers a candidate envelope regex and timestamp pattern, and reports the
 * match rate the proposed profile would achieve. This is what makes onboarding a
 * new application tolerable without hand-writing a regex.
 *
 * <p>V1 detection targets the common pipe-delimited shape
 * {@code ts | LEVEL | thread | Class:line | msg}. When the sample does not look
 * pipe-delimited, it still reports what it found and the (low) match rate, so the
 * user knows to author a profile by hand rather than trusting a bad guess.
 */
public final class FormatDetector {

    private FormatDetector() {}

    /** Candidate timestamp patterns, tried in order of specificity. */
    private static final String[] TS_CANDIDATES = {
            "yyyy-MM-dd HH:mm:ss.SSS",
            "yyyy-MM-dd HH:mm:ss,SSS",
            "yyyy-MM-dd'T'HH:mm:ss.SSSXXX",
            "yyyy-MM-dd'T'HH:mm:ss.SSS",
            "yyyy-MM-dd'T'HH:mm:ssXXX",
            "yyyy-MM-dd HH:mm:ss",
            "yyyy-MM-dd'T'HH:mm:ss",
            "dd/MMM/yyyy:HH:mm:ss Z",
            "dd/MMM/yyyy:HH:mm:ss",
    };

    public record Detected(FormatProfile profile, double matchRate, long sampled, String note) {
        public String yaml() { return ProfileLoader.toYaml(profile); }
    }

    public static Detected detect(Path file) {
        return detect(file, 500);
    }

    public static Detected detect(Path file, int sampleLines) {
        List<String> sample = readSample(file, sampleLines);
        if (sample.isEmpty()) {
            throw new IllegalArgumentException("no readable lines in " + file);
        }

        // How many sample lines contain the " | " field separator?
        long piped = sample.stream().filter(l -> l.contains("|")).count();
        boolean pipeDelimited = piped >= sample.size() * 0.5;

        if (!pipeDelimited) {
            // Fall back to the default profile so the user gets a concrete rate,
            // but flag low confidence.
            FormatProfile def = FormatProfile.defaultProfile();
            double rate = rateOf(def, sample);
            return new Detected(def, rate, sample.size(),
                    "sample does not look pipe-delimited; author a profile by hand");
        }

        // Detect field count from the first well-formed piped line.
        int fields = detectFieldCount(sample);
        boolean hasCallSite = detectCallSite(sample);

        String tsPattern = detectTimestampPattern(sample);
        String envelope = buildEnvelope(fields, hasCallSite);

        Set<Capability> caps = EnumSet.of(Capability.MESSAGE);
        if (tsPattern != null) caps.add(Capability.TIMESTAMP);
        if (fields >= 2) caps.add(Capability.LEVEL);
        if (fields >= 3) caps.add(Capability.THREAD);
        if (hasCallSite) caps.add(Capability.CALL_SITE);

        FormatProfile profile = new FormatProfile(
                "detected-" + file.getFileName(),
                envelope,
                tsPattern,
                ZoneId.of("UTC"),
                caps);
        double rate = rateOf(profile, sample);

        String note = hasCallSite
                ? "call site present -> primary sequence key available"
                : "no Class:line field detected -> CALL_SITE unavailable, message-template fallback needed";
        if (tsPattern == null) {
            note += "; timestamp pattern not recognised — set it by hand";
        }
        return new Detected(profile, rate, sample.size(), note);
    }

    private static int detectFieldCount(List<String> sample) {
        int max = 0;
        for (String l : sample) {
            if (l.contains("|")) {
                int n = l.split("\\|", -1).length;
                if (n > max) max = n;
                if (max >= 5) break;
            }
        }
        return Math.min(max, 5);
    }

    private static boolean detectCallSite(List<String> sample) {
        // In the canonical layout the 4th field is Class:line.
        for (String l : sample) {
            String[] parts = l.split("\\|", -1);
            if (parts.length >= 4 && parts[3].strip().matches("[\\w.$]+:\\d+")) {
                return true;
            }
        }
        return false;
    }

    private static String detectTimestampPattern(List<String> sample) {
        // The timestamp is the first field, trimmed.
        for (String candidate : TS_CANDIDATES) {
            DateTimeFormatter fmt = DateTimeFormatter.ofPattern(candidate);
            int ok = 0, tried = 0;
            for (String l : sample) {
                String first = l.split("\\|", 2)[0].strip();
                if (first.isEmpty()) continue;
                tried++;
                try {
                    fmt.parse(first);
                    ok++;
                } catch (RuntimeException ignored) {
                    // not this pattern
                }
                if (tried >= 50) break;
            }
            if (tried > 0 && ok >= tried * 0.9) {
                return candidate;
            }
        }
        return null;
    }

    private static String buildEnvelope(int fields, boolean hasCallSite) {
        // Canonical 5-field pipe layout with rest-of-line message.
        StringBuilder sb = new StringBuilder("^(?<ts>[^|]+?)\\s*\\|\\s*");
        if (fields >= 2) sb.append("(?<level>\\w+)\\s*\\|\\s*");
        if (fields >= 3) sb.append("(?<thread>[^|]+?)\\s*\\|\\s*");
        if (fields >= 4) {
            if (hasCallSite) {
                sb.append("(?<class>[^:|]+):(?<line>\\d+)\\s*\\|\\s*");
            } else {
                sb.append("(?<src>[^|]+?)\\s*\\|\\s*");
            }
        }
        sb.append("(?<msg>.*)$");
        return sb.toString();
    }

    private static double rateOf(FormatProfile profile, List<String> sample) {
        RecordParser parser = new RecordParser(profile);
        long matched = 0, malformed = 0;
        boolean recordOpen = false;
        for (String l : sample) {
            if (parser.tryMatch(l) != null) {
                matched++;
                recordOpen = true;
            } else if (!recordOpen) {
                malformed++;
            }
            // lines after the first match that don't match are continuations
        }
        long denom = matched + malformed;
        return denom == 0 ? 0.0 : (double) matched / denom;
    }

    private static List<String> readSample(Path file, int sampleLines) {
        List<String> out = new ArrayList<>();
        try (BufferedReader r = open(file)) {
            String line;
            while ((line = r.readLine()) != null && out.size() < sampleLines) {
                if (!line.isBlank()) {
                    out.add(line);
                }
            }
        } catch (IOException e) {
            throw new UncheckedIOException("cannot read " + file, e);
        }
        return out;
    }

    private static BufferedReader open(Path path) throws IOException {
        if (path.getFileName().toString().endsWith(".gz")) {
            return new BufferedReader(new InputStreamReader(
                    new GZIPInputStream(Files.newInputStream(path)), StandardCharsets.UTF_8));
        }
        return Files.newBufferedReader(path, StandardCharsets.UTF_8);
    }
}
