#!/usr/bin/env python3
"""Generate a demo corpus + config + ground truth so you can PROVE the analyzer
works without needing your own logs yet.

It writes, into an output directory:
  logs/app.log         — many normal flows + injected defects (slow / truncated / wrong-branch)
  config.yaml          — the segmentation + detection config for those flows
  ground-truth.yaml    — where the injected defects are, for `tfa validate`

Then run:
  python -m tfa.cli analyze  <out>/logs --config <out>/config.yaml
  python -m tfa.cli validate <out>/logs --config <out>/config.yaml --ground-truth <out>/ground-truth.yaml

Edit the FLOWS / timings below to match YOUR application's flows, regenerate, and
re-run. This is the fastest way to confirm the tool identifies your flows and
flags a slow one before you point it at real data.

Usage:  python tools/make_demo.py [output_dir]   (default: ./demo)
"""
from __future__ import annotations

import sys
from datetime import datetime, timedelta
from pathlib import Path

# ---------------------------------------------------------------------------
# Edit these to model your own flows. Each flow is an ordered list of call sites
# (Classname:line). The first is the ENTRY, the last is the TERMINAL.
FLOWS = {
    "order":   ["com.app.OrderController:10", "com.app.OrderService:20",
                "com.app.Repo:30", "com.app.OrderController:99"],
    "payment": ["com.app.PaymentController:10", "com.app.PaymentService:20",
                "com.app.Gateway:30", "com.app.PaymentController:99"],
    "login":   ["com.app.LoginController:10", "com.app.AuthService:20",
                "com.app.LoginController:99"],
}
NORMAL_PER_FLOW = 40          # normal episodes per flow (the "population" baseline)
STEP_SECONDS = 0.5            # normal time between steps within an episode
IDLE_SECONDS = 20            # idle gap between episodes on a reused thread
THREADS = 4                  # pooled worker threads
# ---------------------------------------------------------------------------


def line(ts, thread, cs, msg):
    return f"{ts.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} | INFO | {thread} | {cs} | {msg}\n"


def err_line(ts, thread, cs, msg):
    body = line(ts, thread, cs, msg).replace("| INFO |", "| ERROR |")
    return body + "java.lang.RuntimeException: boom\n\tat " + cs.split(":")[0] + ".run(x.java:0)\n"


def main(out_dir="demo"):
    out = Path(out_dir)
    (out / "logs").mkdir(parents=True, exist_ok=True)
    rows = []                       # (timestamp, text)
    defects = []                    # ground-truth entries
    base = datetime(2026, 1, 1, 0, 0, 0)
    clock = {f"exec-{i}": base + timedelta(seconds=i) for i in range(THREADS)}
    ti = 0

    def next_thread():
        nonlocal ti
        t = f"exec-{ti % THREADS}"
        ti += 1
        return t

    def emit(flow_seq, thread, start, step=STEP_SECONDS, tag=""):
        t = start
        for cs in flow_seq:
            rows.append((t, line(t, thread, cs, tag or "ok")))
            t += timedelta(seconds=step)
        return t

    flow_names = list(FLOWS)
    # normal population
    for _ in range(NORMAL_PER_FLOW):
        for name in flow_names:
            th = next_thread()
            start = clock[th]
            end = emit(FLOWS[name], th, start)
            clock[th] = end + timedelta(seconds=IDLE_SECONDS)

    # --- injected defect 1: SLOW "order" flow (10x per step), placed LAST on its thread
    th = "exec-0"
    start = max(clock.values()) + timedelta(seconds=IDLE_SECONDS)
    emit(FLOWS["order"], th, start, step=STEP_SECONDS * 10, tag="SLOW")
    defects.append(("DEF-SLOW", th, start, FLOWS["order"][1],
                    "order flow ran ~10x slower than the population"))

    # --- injected defect 2: TRUNCATED "payment" flow (never reaches terminal), mid-corpus
    th = "exec-1"
    start = base + timedelta(seconds=300)
    seq = FLOWS["payment"][:-2]     # drop the last two -> no terminal
    emit(seq, th, start, tag="TRUNC")
    defects.append(("DEF-TRUNC", th, start, seq[-1],
                    "payment flow broke off and never completed"))

    # --- injected defect 3: WRONG BRANCH in "login". IMPORTANT: it must diverge
    # AFTER the K-call-site signature prefix, otherwise it forms its own cluster
    # and gets no baseline. It shares login's prefix, then branches into Fraud:77.
    th = "exec-2"
    start = base + timedelta(seconds=600)
    login = FLOWS["login"]
    t = start
    for cs in login[:-1]:                       # normal prefix (keeps it in the login cluster)
        rows.append((t, line(t, th, cs, "WRONG")))
        t += timedelta(seconds=STEP_SECONDS)
    rows.append((t, err_line(t, th, "com.app.Fraud:77", "unexpected branch")))  # the wrong turn
    t += timedelta(seconds=STEP_SECONDS)
    rows.append((t, line(t, th, login[-1], "WRONG")))                            # then the terminal
    defects.append(("DEF-DIVERGE", th, start, "com.app.Fraud:77",
                    "login flow took a wrong branch into Fraud:77 after the normal prefix"))

    rows.sort(key=lambda r: r[0])
    (out / "logs" / "app.log").write_text("".join(t for _, t in rows), encoding="utf-8")

    entries = ", ".join(f"{s[0]}" for s in FLOWS.values())
    terminals = ", ".join(f"{s[-1]}" for s in FLOWS.values())
    (out / "config.yaml").write_text(f"""profile: default
segmentation:
  strategy: ENTRY_MARKER
  entryCallSites: [{entries}]
  terminalCallSites: [{terminals}]
clustering:
  signatureK: 2
  minClusterSize: 10
detection:
  timingFactor: 3.0
ranking:
  topN: 20
""", encoding="utf-8")

    gt = "defects:\n"
    for did, th, start, cs, desc in defects:
        gt += (f"  - id: {did}\n"
               f"    threadId: {th}\n"
               f"    timestampWindow:\n"
               f"      start: \"{start.strftime('%Y-%m-%dT%H:%M:%SZ')}\"\n"
               f"      end:   \"{(start + timedelta(seconds=60)).strftime('%Y-%m-%dT%H:%M:%SZ')}\"\n"
               f"    expectedDivergenceCallSite: \"{cs}\"\n"
               f"    description: \"{desc}\"\n")
    (out / "ground-truth.yaml").write_text(gt, encoding="utf-8")

    print(f"wrote demo to {out}/  ({len(rows)} lines, {len(defects)} injected defects)")
    print(f"  analyze : python -m tfa.cli analyze  {out}/logs --config {out}/config.yaml")
    print(f"  validate: python -m tfa.cli validate {out}/logs --config {out}/config.yaml "
          f"--ground-truth {out}/ground-truth.yaml")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "demo")
