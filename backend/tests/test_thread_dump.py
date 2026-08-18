"""Thread dump analyzer over the bundled real-world sample dumps."""
import pytest

from app.analyzers.diagnostics import analyze

SAMPLE_FILES = [
    "sample_thread_dump.txt",
    "sample_jstack_java17.txt",
    "sample_jcmd_java21.txt",
    "sample_killdash3_java8.txt",
    "sample_stress_scenario.txt",
]


@pytest.mark.parametrize("name", SAMPLE_FILES)
def test_samples_parse(name, samples_dir):
    path = samples_dir / name
    if not path.exists():
        pytest.skip(f"sample {name} not present")
    a = analyze(path.read_text(encoding="utf-8", errors="replace"))
    assert a.total_threads > 0
    assert a.summary
    assert a.verdict in ("healthy", "degraded", "critical")
    # state breakdown should sum to the thread count
    assert sum(a.state_breakdown.values()) == a.total_threads


def test_primary_sample_has_findings(samples_dir):
    path = samples_dir / "sample_thread_dump.txt"
    if not path.exists():
        pytest.skip("primary sample not present")
    a = analyze(path.read_text(encoding="utf-8", errors="replace"))
    assert a.total_threads >= 3
    assert a.findings, "expected at least one finding in the demo dump"
    # The demo dump is built to show a deadlock and/or lock contention.
    categories = {f.category for f in a.findings}
    assert categories & {"deadlock", "contention", "exhaustion"}


def test_source_enrichment_runs(samples_dir, source_index):
    path = samples_dir / "sample_thread_dump.txt"
    if not path.exists():
        pytest.skip("primary sample not present")
    # Passing a source index must not break analysis even if no frames resolve.
    a = analyze(path.read_text(encoding="utf-8", errors="replace"), source=source_index)
    assert a.total_threads >= 3
