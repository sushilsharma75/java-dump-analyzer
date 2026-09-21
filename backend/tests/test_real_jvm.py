"""Integration coverage from a local HotSpot JDK; no network or attached processes."""

import shutil
import subprocess
import pytest
from app.analyzers.heap_index import (
    build_index,
    object_detail,
    root_paths,
    search_objects,
    heap_threads,
    retained,
)


@pytest.mark.skipif(
    not shutil.which("javac") or not shutil.which("java"),
    reason="local JDK unavailable",
)
def test_real_hotspot_heap_graph(tmp_path):
    source = tmp_path / "Capture.java"
    source.write_text("""
import java.lang.management.ManagementFactory;
import com.sun.management.HotSpotDiagnosticMXBean;
public class Capture {
    static final Holder retained = new Holder();
    static class Holder { byte[] payload = new byte[4096]; }
    public static void main(String[] args) throws Exception {
        ManagementFactory.getPlatformMXBean(HotSpotDiagnosticMXBean.class).dumpHeap(args[0], true);
    }
}
""")
    subprocess.run(
        ["javac", "-g", str(source)], check=True, capture_output=True, timeout=30
    )
    dump = tmp_path / "real.hprof"
    subprocess.run(
        ["java", "-Xmx32m", "-cp", str(tmp_path), "Capture", str(dump)],
        check=True,
        capture_output=True,
        timeout=30,
    )
    index = tmp_path / "real.sqlite"
    with dump.open("rb") as fp:
        build_index(fp, index)
    objects = search_objects(index, "Capture$Holder")
    holder = next(o for o in objects if o["kind"] == "instance")
    detail = object_detail(index, holder["oid"])
    assert any(e["field"] == "Capture$Holder.payload" for e in detail["outgoing"])
    paths = root_paths(index, holder["oid"])
    assert paths["paths"]
    assert any(
        e["field"] == "static:retained" for p in paths["paths"] for e in p["edges"]
    )
    assert heap_threads(index)
    result = retained(index)
    assert result["reachable_bytes"] >= 4096
    assert result["entries"]
