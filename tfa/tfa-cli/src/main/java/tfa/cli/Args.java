package tfa.cli;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Tiny option parser: {@code --key value} and {@code --flag}. Everything else is
 * a positional argument. No dependency, no framework — argument parsing only.
 */
final class Args {
    private final List<String> positionals = new ArrayList<>();
    private final Map<String, String> options = new HashMap<>();

    Args(String[] argv, int from) {
        for (int i = from; i < argv.length; i++) {
            String a = argv[i];
            if (a.startsWith("--")) {
                String key = a.substring(2);
                if (i + 1 < argv.length && !argv[i + 1].startsWith("--")) {
                    options.put(key, argv[++i]);
                } else {
                    options.put(key, "true");
                }
            } else {
                positionals.add(a);
            }
        }
    }

    String positional(int i) {
        return i < positionals.size() ? positionals.get(i) : null;
    }

    String get(String key, String dflt) {
        return options.getOrDefault(key, dflt);
    }

    int getInt(String key, int dflt) {
        String v = options.get(key);
        return v == null ? dflt : Integer.parseInt(v);
    }

    double getDouble(String key, double dflt) {
        String v = options.get(key);
        return v == null ? dflt : Double.parseDouble(v);
    }

    boolean has(String key) {
        return options.containsKey(key);
    }
}
