package tfa.cli;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import tfa.report.Json;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;

/**
 * A tiny local web UI over the tfa CLI. Runs each pipeline step against a folder
 * path on this machine, captures each step's output as a downloadable file, and
 * serves the final JSON report for inline rendering. Bound to loopback only; it
 * shells out to this same jar so the CLI output is exactly what you'd get on the
 * command line.
 */
public final class WebServer {

    private static final long MAX_OUTPUT_BYTES = 512 * 1024;
    private static final int TAIL_CHARS = 8192;

    private final int port;
    private final Path jar;
    private final Path baseDir;
    private final Map<String, Path> runs = new ConcurrentHashMap<>();

    private WebServer(int port, Path jar) throws IOException {
        this.port = port;
        this.jar = jar;
        this.baseDir = Files.createTempDirectory("tfa-web-");
    }

    public static void start(int port, Path jarOverride) throws Exception {
        Path jar = jarOverride != null ? jarOverride : selfJar();
        WebServer server = new WebServer(port, jar);
        server.run();
    }

    private static Path selfJar() throws Exception {
        URI uri = WebServer.class.getProtectionDomain().getCodeSource().getLocation().toURI();
        return Path.of(uri);
    }

    private void run() throws IOException {
        HttpServer http = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
        http.createContext("/", this::handleRoot);
        http.createContext("/api/run", this::handleRun);
        http.createContext("/api/artifact", this::handleArtifact);
        http.createContext("/api/report", this::handleReport);
        http.setExecutor(Executors.newFixedThreadPool(4));
        http.start();
        System.out.println("tfa web UI: http://127.0.0.1:" + port + "   (Ctrl-C to stop)");
        System.out.println("jar: " + jar);
        System.out.println("work dir: " + baseDir);
    }

    // -- GET / : the control panel -----------------------------------------

    private void handleRoot(HttpExchange ex) throws IOException {
        if (!"GET".equals(ex.getRequestMethod())) {
            send(ex, 405, "text/plain", "method not allowed".getBytes(StandardCharsets.UTF_8));
            return;
        }
        try (InputStream in = WebServer.class.getResourceAsStream("/webui/index.html")) {
            if (in == null) {
                send(ex, 500, "text/plain", "index.html resource missing".getBytes(StandardCharsets.UTF_8));
                return;
            }
            send(ex, 200, "text/html; charset=utf-8", in.readAllBytes());
        }
    }

    // -- POST /api/run : run steps against a folder -------------------------

    private void handleRun(HttpExchange ex) throws IOException {
        if (!"POST".equals(ex.getRequestMethod())) {
            send(ex, 405, "text/plain", "POST only".getBytes(StandardCharsets.UTF_8));
            return;
        }
        Map<String, String> form = parseForm(new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
        String dir = form.getOrDefault("dir", "").trim();
        String config = form.getOrDefault("config", "");
        String suppressions = form.getOrDefault("suppressions", "").trim();
        List<String> steps = new ArrayList<>();
        for (String s : form.getOrDefault("steps", "").split(",")) {
            if (!s.isBlank()) {
                steps.add(s.trim());
            }
        }

        if (dir.isEmpty() || !Files.isDirectory(Path.of(dir))) {
            send(ex, 400, "application/json",
                    Json.write(Map.of("error", "not a directory: " + dir)).getBytes(StandardCharsets.UTF_8));
            return;
        }

        String runId = UUID.randomUUID().toString();
        Path runDir = baseDir.resolve(runId);
        Files.createDirectories(runDir);
        runs.put(runId, runDir);

        Path cfgFile = runDir.resolve("config.yaml");
        Files.writeString(cfgFile, config);
        Path suppFile = null;
        if (!suppressions.isEmpty()) {
            suppFile = runDir.resolve("suppressions.yaml");
            Files.writeString(suppFile, suppressions);
        }

        List<Object> stepResults = new ArrayList<>();
        boolean hasReport = false;
        for (String step : steps) {
            StepRun sr = runStep(step, dir, cfgFile, suppFile, runDir);
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("name", step);
            m.put("exitCode", sr.exitCode);
            m.put("ok", sr.exitCode == 0);
            m.put("file", sr.outFile);
            m.put("bytes", sr.bytes);
            m.put("tail", sr.tail);
            stepResults.add(m);
            if ("analyze".equals(step) && Files.exists(runDir.resolve("report.json"))) {
                hasReport = true;
            }
        }

        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("runId", runId);
        resp.put("steps", stepResults);
        resp.put("report", hasReport);
        send(ex, 200, "application/json", Json.write(resp).getBytes(StandardCharsets.UTF_8));
    }

    private record StepRun(int exitCode, String outFile, long bytes, String tail) {}

    private StepRun runStep(String step, String dir, Path cfg, Path supp, Path runDir) throws IOException {
        List<String> cmd = new ArrayList<>();
        cmd.add(javaBin());
        cmd.add("-jar");
        cmd.add(jar.toString());
        cmd.add(step);
        cmd.add(dir);
        switch (step) {
            case "parse" -> { /* default profile; ingestion stats only */ }
            case "segment", "cluster", "baseline", "detect" -> {
                cmd.add("--config");
                cmd.add(cfg.toString());
            }
            case "analyze" -> {
                cmd.add("--config");
                cmd.add(cfg.toString());
                cmd.add("--out");
                cmd.add(runDir.resolve("report.json").toString());
                if (supp != null) {
                    cmd.add("--suppressions");
                    cmd.add(supp.toString());
                }
            }
            default -> { /* unknown step: run as-is */ }
        }

        Path outFile = runDir.resolve(step + ".txt");
        ProcessBuilder pb = new ProcessBuilder(cmd).redirectErrorStream(true);
        // keep the child's captured output clean of the JVM launcher's noise line
        pb.environment().remove("JAVA_TOOL_OPTIONS");
        int exit;
        long bytes;
        String tail;
        try {
            Process p = pb.start();
            byte[] out = readCapped(p.getInputStream());
            exit = p.waitFor();
            Files.write(outFile, out);
            bytes = out.length;
            String text = new String(out, StandardCharsets.UTF_8);
            tail = text.length() > TAIL_CHARS ? text.substring(0, TAIL_CHARS) + "\n… (truncated, download for full)" : text;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            exit = -1;
            bytes = 0;
            tail = "interrupted";
        }
        return new StepRun(exit, step + ".txt", bytes, tail);
    }

    private static byte[] readCapped(InputStream in) throws IOException {
        var buf = new java.io.ByteArrayOutputStream();
        byte[] chunk = new byte[8192];
        int n;
        long total = 0;
        while ((n = in.read(chunk)) != -1) {
            if (total < MAX_OUTPUT_BYTES) {
                buf.write(chunk, 0, n);
                total += n;
            }
        }
        return buf.toByteArray();
    }

    // -- GET /api/artifact?run=..&name=..  download a produced file ---------

    private void handleArtifact(HttpExchange ex) throws IOException {
        Map<String, String> q = parseForm(ex.getRequestURI().getRawQuery());
        Path file = resolveArtifact(q.get("run"), q.get("name"));
        if (file == null) {
            send(ex, 404, "text/plain", "not found".getBytes(StandardCharsets.UTF_8));
            return;
        }
        ex.getResponseHeaders().add("Content-Disposition",
                "attachment; filename=\"" + file.getFileName() + "\"");
        send(ex, 200, "application/octet-stream", Files.readAllBytes(file));
    }

    // -- GET /api/report?run=..  the report.json for inline rendering -------

    private void handleReport(HttpExchange ex) throws IOException {
        Map<String, String> q = parseForm(ex.getRequestURI().getRawQuery());
        Path file = resolveArtifact(q.get("run"), "report.json");
        if (file == null) {
            send(ex, 404, "text/plain", "no report".getBytes(StandardCharsets.UTF_8));
            return;
        }
        send(ex, 200, "application/json", Files.readAllBytes(file));
    }

    /** Resolve a file within a run dir, rejecting traversal. */
    private Path resolveArtifact(String runId, String name) {
        if (runId == null || name == null || !name.matches("[\\w.-]+")) {
            return null;
        }
        Path runDir = runs.get(runId);
        if (runDir == null) {
            return null;
        }
        Path file = runDir.resolve(name).normalize();
        if (!file.startsWith(runDir) || !Files.exists(file)) {
            return null;
        }
        return file;
    }

    // -- helpers ------------------------------------------------------------

    private static String javaBin() {
        String home = System.getProperty("java.home");
        Path bin = Path.of(home, "bin", "java");
        return Files.exists(bin) ? bin.toString() : "java";
    }

    private static Map<String, String> parseForm(String body) {
        Map<String, String> out = new HashMap<>();
        if (body == null || body.isEmpty()) {
            return out;
        }
        for (String pair : body.split("&")) {
            int eq = pair.indexOf('=');
            if (eq < 0) {
                continue;
            }
            String k = URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8);
            String v = URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
            out.put(k, v);
        }
        return out;
    }

    private static void send(HttpExchange ex, int code, String contentType, byte[] body) throws IOException {
        ex.getResponseHeaders().add("Content-Type", contentType);
        ex.sendResponseHeaders(code, body.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(body);
        }
    }

    private WebServer() { throw new AssertionError(); }
}
