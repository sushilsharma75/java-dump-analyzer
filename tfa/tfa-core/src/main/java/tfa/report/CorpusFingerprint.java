package tfa.report;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * A stable fingerprint of the analysed corpus — file names, sizes, and the
 * overall timestamp range — so two reports are comparable at a glance and it is
 * obvious when the input changed.
 */
public record CorpusFingerprint(String hash, List<FileEntry> files, Instant corpusStart, Instant corpusEnd) {

    public record FileEntry(String name, long sizeBytes) {}

    public static CorpusFingerprint of(List<Path> orderedFiles, Instant corpusStart, Instant corpusEnd) {
        List<FileEntry> entries = new ArrayList<>();
        StringBuilder material = new StringBuilder();
        for (Path p : orderedFiles) {
            long size;
            try {
                size = Files.size(p);
            } catch (IOException e) {
                throw new UncheckedIOException("cannot stat " + p, e);
            }
            String name = p.getFileName().toString();
            entries.add(new FileEntry(name, size));
            material.append(name).append(':').append(size).append('\n');
        }
        material.append("start=").append(corpusStart).append('\n');
        material.append("end=").append(corpusEnd).append('\n');
        return new CorpusFingerprint(Hashing.sha256Hex(material.toString()), entries, corpusStart, corpusEnd);
    }
}
