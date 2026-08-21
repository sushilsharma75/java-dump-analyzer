package tfa.report;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.List;
import java.util.Map;

/**
 * Minimal, dependency-free JSON writer. Emits {@link Map} (object, in insertion
 * order — use {@link java.util.LinkedHashMap} for determinism), {@link List}
 * (array), String, Number, Boolean and null. Deterministic given deterministic
 * input, so reports are byte-identical run to run.
 */
public final class Json {

    private Json() {}

    public static String write(Object value) {
        StringBuilder sb = new StringBuilder();
        try {
            write(value, sb, 0);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        sb.append('\n');
        return sb.toString();
    }

    private static void write(Object value, Appendable out, int indent) throws IOException {
        switch (value) {
            case null -> out.append("null");
            case Map<?, ?> map -> writeObject(map, out, indent);
            case List<?> list -> writeArray(list, out, indent);
            case String s -> writeString(s, out);
            case Boolean b -> out.append(b.toString());
            case Number n -> out.append(formatNumber(n));
            default -> writeString(String.valueOf(value), out);
        }
    }

    private static void writeObject(Map<?, ?> map, Appendable out, int indent) throws IOException {
        if (map.isEmpty()) {
            out.append("{}");
            return;
        }
        out.append("{\n");
        int i = 0;
        for (Map.Entry<?, ?> e : map.entrySet()) {
            indent(out, indent + 1);
            writeString(String.valueOf(e.getKey()), out);
            out.append(": ");
            write(e.getValue(), out, indent + 1);
            if (++i < map.size()) {
                out.append(',');
            }
            out.append('\n');
        }
        indent(out, indent);
        out.append('}');
    }

    private static void writeArray(List<?> list, Appendable out, int indent) throws IOException {
        if (list.isEmpty()) {
            out.append("[]");
            return;
        }
        out.append("[\n");
        for (int i = 0; i < list.size(); i++) {
            indent(out, indent + 1);
            write(list.get(i), out, indent + 1);
            if (i + 1 < list.size()) {
                out.append(',');
            }
            out.append('\n');
        }
        indent(out, indent);
        out.append(']');
    }

    private static String formatNumber(Number n) {
        if (n instanceof Double || n instanceof Float) {
            double d = n.doubleValue();
            if (d == Math.floor(d) && !Double.isInfinite(d)) {
                return Long.toString((long) d);
            }
            return String.format("%.6f", d);
        }
        return n.toString();
    }

    private static void writeString(String s, Appendable out) throws IOException {
        out.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        out.append('"');
    }

    private static void indent(Appendable out, int level) throws IOException {
        for (int i = 0; i < level; i++) {
            out.append("  ");
        }
    }
}
