"""A tiny local web UI over the tfa CLI. Port of the Java `tfa.cli.WebServer`.

Runs each pipeline step against a folder path on this machine by shelling out to
`python -m tfa.cli <step>`, captures each step's output as a downloadable file,
and serves report.json for inline rendering. Bound to loopback only."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

MAX_OUTPUT_BYTES = 512 * 1024
TAIL_CHARS = 8192

_RUNS: dict[str, dict] = {}
_BASE = Path(tempfile.mkdtemp(prefix="tfa-web-"))
_WEBUI = Path(__file__).parent / "webui" / "index.html"


def _run_step(step: str, run: dict) -> dict:
    cmd = [sys.executable, "-m", "tfa.cli", step, run["dir"]]
    if step in ("segment", "cluster", "baseline", "detect"):
        cmd += ["--config", str(run["cfg"])]
    elif step == "analyze":
        cmd += ["--config", str(run["cfg"]), "--out", str(run["run_dir"] / "report.json")]
        if run.get("supp"):
            cmd += ["--suppressions", str(run["supp"])]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    out = (proc.stdout or "") + (proc.stderr or "")
    out_file = run["run_dir"] / f"{step}.txt"
    out_file.write_text(out[:MAX_OUTPUT_BYTES], encoding="utf-8")
    tail = out if len(out) <= TAIL_CHARS else out[:TAIL_CHARS] + "\n… (truncated, download for full)"
    return {
        "name": step,
        "exitCode": proc.returncode,
        "ok": proc.returncode == 0,
        "file": f"{step}.txt",
        "bytes": len(out.encode("utf-8")),
        "tail": tail,
        "reportReady": (run["run_dir"] / "report.json").exists(),
    }


def _resolve_artifact(run_id, name):
    if not run_id or not name or not name.replace(".", "").replace("-", "").replace("_", "").isalnum():
        return None
    run = _RUNS.get(run_id)
    if run is None:
        return None
    f = (run["run_dir"] / name).resolve()
    if not str(f).startswith(str(run["run_dir"].resolve())) or not f.exists():
        return None
    return f


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # quiet
        pass

    def _send(self, code, ctype, body: bytes, headers=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code, obj):
        self._send(code, "application/json", json.dumps(obj).encode("utf-8"))

    def _form(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8")
        return {k: v[0] for k, v in parse_qs(body, keep_blank_values=True).items()}

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/":
            self._send(200, "text/html; charset=utf-8", _WEBUI.read_bytes())
        elif u.path == "/api/artifact":
            q = parse_qs(u.query)
            f = _resolve_artifact(q.get("run", [None])[0], q.get("name", [None])[0])
            if f is None:
                self._send(404, "text/plain", b"not found")
            else:
                self._send(200, "application/octet-stream", f.read_bytes(),
                           {"Content-Disposition": f'attachment; filename="{f.name}"'})
        elif u.path == "/api/report":
            q = parse_qs(u.query)
            f = _resolve_artifact(q.get("run", [None])[0], "report.json")
            if f is None:
                self._send(404, "text/plain", b"no report")
            else:
                self._send(200, "application/json", f.read_bytes())
        else:
            self._send(404, "text/plain", b"not found")

    def do_POST(self):
        u = urlparse(self.path)
        if u.path == "/api/start":
            form = self._form()
            d = form.get("dir", "").strip()
            if not d or not Path(d).is_dir():
                self._json(400, {"error": f"not a directory: {d}"})
                return
            run_id = str(uuid.uuid4())
            run_dir = _BASE / run_id
            run_dir.mkdir(parents=True, exist_ok=True)
            cfg = run_dir / "config.yaml"
            cfg.write_text(form.get("config", ""), encoding="utf-8")
            supp = None
            if form.get("suppressions", "").strip():
                supp = run_dir / "suppressions.yaml"
                supp.write_text(form["suppressions"], encoding="utf-8")
            _RUNS[run_id] = {"run_dir": run_dir, "dir": d, "cfg": cfg, "supp": supp}
            self._json(200, {"runId": run_id})
        elif u.path == "/api/step":
            q = parse_qs(u.query)
            run = _RUNS.get(q.get("run", [None])[0])
            step = q.get("name", [None])[0]
            if run is None or step not in ("parse", "segment", "cluster", "baseline", "detect", "analyze"):
                self._json(400, {"error": "unknown run or step"})
                return
            self._json(200, _run_step(step, run))
        else:
            self._send(404, "text/plain", b"not found")


def start(port: int = 8080):
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"tfa web UI: http://127.0.0.1:{port}   (Ctrl-C to stop)")
    print(f"work dir: {_BASE}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
