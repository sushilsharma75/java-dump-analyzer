"""End-to-end API smoke tests via FastAPI's TestClient (no real network/LLM)."""
import io

import pytest

from hprof_builder import HprofBuilder

fastapi_testclient = pytest.importorskip("fastapi.testclient")
from fastapi.testclient import TestClient  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def _order_heap_bytes(n=100):
    b = HprofBuilder()
    order = b.load_class("com.example.Order")
    b.class_dump(order)
    for _ in range(n):
        b.instance(order, body=b"\x00" * 16)
    return b.build()


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_source_path_indexing(client, fixture_src_path):
    r = client.post("/api/source/path", json={"path": fixture_src_path})
    assert r.status_code == 200
    body = r.json()
    assert body["classes_indexed"] >= 8
    assert body["session_id"]


def test_full_thread_heap_correlate_flow(client, fixture_src_path, samples_dir):
    sample = samples_dir / "sample_thread_dump.txt"
    if not sample.exists():
        pytest.skip("primary sample not present")

    # 1. index source
    sess = client.post("/api/source/path", json={"path": fixture_src_path}).json()["session_id"]

    # 2. thread analysis
    rt = client.post(
        "/api/analyze/thread",
        files={"file": ("dump.txt", sample.read_bytes(), "text/plain")},
        data={"source_session": sess},
    )
    assert rt.status_code == 200
    thread_json = rt.json()
    assert thread_json["total_threads"] > 0

    # 3. heap analysis (small synthetic dump, synchronous endpoint)
    rh = client.post(
        "/api/analyze/heap",
        files={"file": ("heap.hprof", _order_heap_bytes(), "application/octet-stream")},
        data={"quick": "false", "source_session": sess},
    )
    assert rh.status_code == 200
    heap_json = rh.json()
    assert heap_json["total_instances"] == 100

    # 4. correlate the two
    rc = client.post("/api/correlate", json={
        "heap": heap_json, "thread": thread_json, "source_session": sess,
    })
    assert rc.status_code == 200
    corr = rc.json()
    assert "findings" in corr and corr["summary"]


def test_heap_rejects_thread_dump(client):
    r = client.post(
        "/api/analyze/heap",
        files={"file": ("oops.hprof", b"Full thread dump ...\n" + b"x" * 80, "application/octet-stream")},
        data={"quick": "false"},
    )
    assert r.status_code == 500  # analysis error surfaced as 500 with a helpful message
