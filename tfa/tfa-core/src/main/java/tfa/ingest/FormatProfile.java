package tfa.ingest;

import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.EnumSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A named, reusable log-format definition (§3.4). Selected per run. The envelope
 * regex uses canonical named groups — {@code ts, level, thread, class, line,
 * msg} — any of which a profile may omit if its format lacks them. The timestamp
 * pattern and zone are kept separate from the envelope so ordering across a DST
 * boundary is never ambiguous.
 *
 * <p>{@code msg} is rest-of-line: the message contains the separator character,
 * so the envelope must capture it greedily to end-of-line and never split on the
 * separator. That is a property of the regex the profile carries, enforced here
 * only by convention.
 */
public final class FormatProfile {

    /** Canonical named groups. A profile need not supply all of them. */
    static final String[] CANONICAL_GROUPS = {"ts", "level", "thread", "class", "line", "msg"};

    private final String name;
    private final Pattern envelope;
    private final String timestampPattern;
    private final ZoneId zone;
    private final Set<Capability> capabilities;
    private final DateTimeFormatter formatter; // derived, nullable
    private final Set<String> presentGroups;   // named groups actually present in the regex

    public FormatProfile(String name, String envelopeRegex, String timestampPattern,
                         ZoneId zone, Set<Capability> capabilities) {
        this.name = name;
        this.envelope = Pattern.compile(envelopeRegex);
        this.timestampPattern = timestampPattern;
        this.zone = zone;
        this.capabilities = capabilities == null ? EnumSet.noneOf(Capability.class)
                : EnumSet.copyOf(capabilities);
        this.presentGroups = detectGroups(envelopeRegex);
        this.formatter = timestampPattern == null ? null
                : DateTimeFormatter.ofPattern(timestampPattern);
    }

    private static Set<String> detectGroups(String regex) {
        Set<String> present = new java.util.HashSet<>();
        Matcher m = Pattern.compile("\\(\\?<([a-zA-Z][a-zA-Z0-9]*)>").matcher(regex);
        while (m.find()) {
            present.add(m.group(1));
        }
        return present;
    }

    /** The default profile matching {@code timestamp | LEVEL | threadId | Classname:lineNumber | message}. */
    public static FormatProfile defaultProfile() {
        String envelope =
                "^(?<ts>\\S+ \\S+)\\s*\\|\\s*" +
                "(?<level>\\w+)\\s*\\|\\s*" +
                "(?<thread>[^|]+?)\\s*\\|\\s*" +
                "(?<class>[^:|]+):(?<line>\\d+)\\s*\\|\\s*" +
                "(?<msg>.*)$";
        return new FormatProfile(
                "default",
                envelope,
                "yyyy-MM-dd HH:mm:ss.SSS",
                ZoneId.of("UTC"),
                EnumSet.of(Capability.CALL_SITE, Capability.LEVEL, Capability.THREAD,
                        Capability.TIMESTAMP, Capability.MESSAGE));
    }

    public String name()                 { return name; }
    public Pattern envelope()            { return envelope; }
    public String timestampPattern()     { return timestampPattern; }
    public ZoneId zone()                 { return zone; }
    public Set<Capability> capabilities(){ return EnumSet.copyOf(capabilities); }
    public DateTimeFormatter formatter() { return formatter; }

    public boolean has(Capability c)     { return capabilities.contains(c); }

    /** True if the named group is present in the envelope regex. */
    public boolean hasGroup(String group) { return presentGroups.contains(group); }
}
