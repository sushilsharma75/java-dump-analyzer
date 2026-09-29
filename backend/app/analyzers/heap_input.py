"""Content-based heap format detection and bounded gzip expansion."""
from contextlib import contextmanager
import gzip
import tempfile


def detect_format(header):
    if header.startswith(b"JAVA PROFILE 1.0."):
        return "hprof"
    if header.startswith(b"\x1f\x8b"):
        return "gzip"
    if b"portable heap dump" in header[:40]:
        return "openj9_phd"
    if header.startswith(b"\x7fELF") or header[:4] in (b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"MDMP"):
        return "system_dump"
    if b"0SECTION" in header or b"1TISIGINFO" in header:
        return "javacore"
    if b"// Version:" in header or b"// JVM version:" in header:
        return "openj9_classic"
    return "unknown"


@contextmanager
def native_input(path, max_bytes, temp_dir=None, stage=None, check=None):
    """Keep the uncompressed file open only for the duration of analysis."""
    with open(path, "rb") as raw:
        kind = detect_format(raw.read(512))
        raw.seek(0)
        if kind == "hprof":
            yield raw, {"format": "hprof", "compression": None}
            return
        if kind != "gzip":
            raise ValueError(f"Input format: {kind}. This analyzer currently supports HPROF and gzip HPROF. OpenJ9 PHD/system-dump parsing is not yet implemented; javacore alone is not a complete heap.")
        if stage:
            stage("Decompressing heap (expanded byte limit applies)")
        with tempfile.TemporaryFile(dir=temp_dir) as expanded:
            total = 0
            with gzip.GzipFile(fileobj=raw) as compressed:
                while chunk := compressed.read(1024 * 1024):
                    if check:
                        check()
                    total += len(chunk)
                    if total > max_bytes:
                        raise ValueError("Expanded heap exceeds the configured input byte limit")
                    expanded.write(chunk)
            expanded.seek(0)
            if detect_format(expanded.read(512)) != "hprof":
                raise ValueError("Compressed input is not HPROF. OpenJ9 PHD and system-dump parsing are not yet implemented in this analyzer.")
            expanded.seek(0)
            yield expanded, {"format": "hprof", "compression": "gzip", "expanded_bytes": total}
