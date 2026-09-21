#!/usr/bin/env python3
"""
Generates synthetic multi-day, multi-file application logs for testing the
Thread Flow Analyzer (TFA).

Format (matches charter section 3.1):
  timestamp | LEVEL | threadId | Classname:lineNumber | message

Simulates:
  - A single JVM, thread-pool reuse (threads run many episodes over time)
  - Three flow types (Order, Payment, Login) with realistic call-site sequences
  - Legitimate variance (retries, optional branches) that is NOT a defect
  - Three deliberately injected defects (truncation, divergence, timing) whose
    exact location is recorded in ground-truth.yaml
  - Multi-file rotation (one file per day) with out-of-order-looking filenames
  - A duplicate-appender file (error.log) that re-writes ERROR events, to
    exercise the dedup logic in section 3.5
  - A handful of malformed lines, to exercise the malformed-line bucket
  - Natural boundary censoring: episodes in flight at the very start/end of
    the capture window
"""

import random
from datetime import datetime, timedelta

random.seed(42)

OUT_DIR = "/home/claude/sample-logs"
START = datetime(2026, 8, 20, 0, 0, 0)   # day 1
DAYS = 3
END = START + timedelta(days=DAYS)

TS_FMT = "%Y-%m-%d %H:%M:%S.%f"

def fmt_ts(dt):
    return dt.strftime(TS_FMT)[:-3]  # milliseconds, not microseconds

# ---------------------------------------------------------------------------
# Flow definitions
# ---------------------------------------------------------------------------
# Each step: (callsite, message, min_ms, max_ms)  -- timing is the gap BEFORE
# this step, relative to the previous step in the same episode.

ORDER_FLOW = [
    ("com.bank.order.OrderController:45", "Received order request orderId={oid}", 0, 0),
    ("com.bank.order.OrderService:88", "Validating order orderId={oid}", 5, 30),
    ("com.bank.order.InventoryClient:112", "Checking inventory for orderId={oid}", 10, 80),
    ("com.bank.order.PaymentClient:76", "Charging payment for orderId={oid}", 15, 120),
    ("com.bank.order.OrderService:150", "Persisting order orderId={oid}", 8, 40),
    ("com.bank.order.OrderController:99", "Order request completed orderId={oid}", 2, 10),
]

# Legitimate variant: coupon applied, inserted after validate
ORDER_COUPON_STEP = ("com.bank.order.OrderService:95", "Coupon applied to orderId={oid}", 3, 15)

PAYMENT_FLOW = [
    ("com.bank.payment.PaymentController:30", "Received payment request txnId={oid}", 0, 0),
    ("com.bank.payment.PaymentService:64", "Validating card for txnId={oid}", 5, 25),
    ("com.bank.payment.FraudCheckClient:41", "Running fraud check for txnId={oid}", 20, 150),
    ("com.bank.payment.PaymentGateway:203", "Charging gateway for txnId={oid}", 30, 200),
    ("com.bank.payment.PaymentController:80", "Payment request completed txnId={oid}", 2, 10),
]

LOGIN_FLOW = [
    ("com.bank.auth.LoginController:22", "Received login request user={oid}", 0, 0),
    ("com.bank.auth.AuthService:55", "Verifying credentials for user={oid}", 5, 40),
    ("com.bank.auth.SessionManager:33", "Creating session for user={oid}", 10, 60),
    ("com.bank.auth.LoginController:60", "Login request completed user={oid}", 2, 8),
]

FLOWS = {
    "ORDER": ORDER_FLOW,
    "PAYMENT": PAYMENT_FLOW,
    "LOGIN": LOGIN_FLOW,
}
FLOW_WEIGHTS = {"ORDER": 5, "PAYMENT": 3, "LOGIN": 4}

THREAD_POOL = [f"http-nio-8080-exec-{i}" for i in range(1, 26)]

# ---------------------------------------------------------------------------
# Episode generation
# ---------------------------------------------------------------------------

records = []          # list of dicts: ts, level, thread, callsite, message, is_error_dup_candidate
ground_truth_defects = []
oid_counter = 1000

thread_next_free = {t: START for t in THREAD_POOL}

def pick_thread(arrival):
    """Pick a thread from the pool: prefer one free at/ before arrival, else
    the one that frees up soonest (queueing)."""
    free_now = [t for t in THREAD_POOL if thread_next_free[t] <= arrival]
    if free_now:
        return random.choice(free_now)
    return min(THREAD_POOL, key=lambda t: thread_next_free[t])

def emit(ts, level, thread, callsite, message, stack=None):
    records.append({
        "ts": ts, "level": level, "thread": thread,
        "callsite": callsite, "message": message, "stack": stack,
    })

def run_episode(arrival, flow_name, defect=None):
    """defect: None | 'TRUNCATE' | 'DIVERGE_SKIP_FRAUD' | 'SLOW_LDAP'"""
    global oid_counter
    oid = f"{flow_name[:3]}-{oid_counter}"
    oid_counter += 1
    thread = pick_thread(arrival)
    t = max(arrival, thread_next_free[thread])
    steps = list(FLOWS[flow_name])

    # legitimate variance: occasionally insert coupon step in ORDER flow
    if flow_name == "ORDER" and random.random() < 0.12 and defect is None:
        steps = steps[:2] + [ORDER_COUPON_STEP] + steps[2:]

    # legitimate variance: occasional retry loop on InventoryClient
    retry_inventory = (flow_name == "ORDER" and random.random() < 0.06 and defect is None)

    episode_start_ts = None
    last_ts = t
    reached_terminal = True
    divergence_info = None

    for i, (callsite, msg_tmpl, lo, hi) in enumerate(steps):
        gap_ms = random.randint(lo, hi) if i > 0 else 0
        last_ts = last_ts + timedelta(milliseconds=gap_ms)
        if episode_start_ts is None:
            episode_start_ts = last_ts

        # --- DIVERGE_SKIP_FRAUD defect: PAYMENT flow skips FraudCheckClient ---
        if defect == "DIVERGE_SKIP_FRAUD" and flow_name == "PAYMENT" and callsite.endswith("FraudCheckClient:41"):
            divergence_info = {
                "thread": thread,
                "skipped_callsite": callsite,
                "went_to_callsite": steps[i + 1][0],
                "timestamp": fmt_ts(last_ts),
            }
            continue  # skip logging this step entirely -> straight to gateway charge

        emit(last_ts, "INFO", thread, callsite, msg_tmpl.format(oid=oid))

        if retry_inventory and callsite.endswith("InventoryClient:112"):
            retry_ts = last_ts + timedelta(milliseconds=random.randint(200, 400))
            emit(retry_ts, "WARN", thread, callsite, f"Inventory check retry for orderId={oid}")
            last_ts = retry_ts

        # --- SLOW_LDAP defect: LOGIN flow, huge gap before SessionManager ---
        if defect == "SLOW_LDAP" and flow_name == "LOGIN" and callsite.endswith("AuthService:55"):
            slow_gap = timedelta(seconds=45)
            last_ts = last_ts + slow_gap

        # --- TRUNCATE defect: ORDER flow dies after InventoryClient with an error ---
        if defect == "TRUNCATE" and flow_name == "ORDER" and callsite.endswith("InventoryClient:112"):
            err_ts = last_ts + timedelta(milliseconds=random.randint(3000, 6000))
            stack = [
                "java.net.SocketTimeoutException: Read timed out",
                "\tat java.base/java.net.SocketInputStream.socketRead0(Native Method)",
                "\tat java.base/java.net.SocketInputStream.read(SocketInputStream.java:168)",
                "\tat okhttp3.internal.http2.Http2Stream$StreamTimeout.newTimeoutException(Http2Stream.java:684)",
                "\tat com.bank.order.InventoryClient.checkStock(InventoryClient.java:118)",
                "\tat com.bank.order.OrderService.processOrder(OrderService.java:92)",
            ]
            emit(err_ts, "ERROR", thread, "com.bank.order.InventoryClient:118",
                 f"Inventory service timeout for orderId={oid}", stack=stack)
            reached_terminal = False
            last_ts = err_ts
            break

    thread_next_free[thread] = last_ts + timedelta(milliseconds=random.randint(5, 50))

    if defect == "TRUNCATE":
        ground_truth_defects.append({
            "id": "DEFECT-1-TRUNCATION",
            "type": "TRUNCATION",
            "flow": "ORDER",
            "thread": thread,
            "orderId": oid,
            "approx_timestamp": fmt_ts(episode_start_ts),
            "expected_divergence_callsite": "com.bank.order.InventoryClient:112",
            "description": ("Order flow calls InventoryClient, inventory service times out, "
                             "flow never reaches PaymentClient or the terminal log line. "
                             "Should surface as a TRUNCATION finding."),
        })
    elif defect == "DIVERGE_SKIP_FRAUD" and divergence_info:
        ground_truth_defects.append({
            "id": "DEFECT-2-DIVERGENCE",
            "type": "DIVERGENCE",
            "flow": "PAYMENT",
            "thread": divergence_info["thread"],
            "orderId": oid,
            "approx_timestamp": divergence_info["timestamp"],
            "expected_divergence_callsite": "com.bank.payment.PaymentGateway:203",
            "description": ("Payment flow goes straight from PaymentService:64 to "
                             "PaymentGateway:203, skipping FraudCheckClient:41 entirely. "
                             "The gateway charge is logged with no fraud-check log line "
                             "preceding it -- a silent skip, no ERROR level involved. "
                             "Should surface as a DIVERGENCE finding at PaymentGateway:203."),
        })
    elif defect == "SLOW_LDAP":
        ground_truth_defects.append({
            "id": "DEFECT-3-TIMING",
            "type": "TIMING",
            "flow": "LOGIN",
            "thread": thread,
            "orderId": oid,
            "approx_timestamp": fmt_ts(episode_start_ts),
            "expected_divergence_callsite": "com.bank.auth.SessionManager:33",
            "description": ("Login flow: AuthService:55 to SessionManager:33 transition "
                             "takes ~45s instead of the usual <100ms (looks like an LDAP "
                             "hang). Should surface as a TIMING finding on that transition."),
        })

# ---------------------------------------------------------------------------
# Simulate arrivals across 3 days: business-hours-heavy Poisson process
# ---------------------------------------------------------------------------

t = START
while t < END:
    hour = t.hour
    # traffic multiplier: quiet at night, busy 9am-6pm IST
    if 9 <= hour < 18:
        rate_per_min = 6.0
    elif 6 <= hour < 9 or 18 <= hour < 22:
        rate_per_min = 2.5
    else:
        rate_per_min = 0.4

    gap = random.expovariate(rate_per_min / 60.0)  # seconds
    t = t + timedelta(seconds=gap)
    if t >= END:
        break

    flow_name = random.choices(list(FLOW_WEIGHTS), weights=list(FLOW_WEIGHTS.values()))[0]
    run_episode(t, flow_name, defect=None)

# ---------------------------------------------------------------------------
# Inject the three defects at specific, well-spaced points (day 2, mid-day)
# ---------------------------------------------------------------------------

defect_time_1 = START + timedelta(days=1, hours=10, minutes=17)   # truncation
defect_time_2 = START + timedelta(days=1, hours=14, minutes=42)   # divergence (skip fraud check)
defect_time_3 = START + timedelta(days=1, hours=16, minutes=5)    # timing outlier

DEFECT_THREADS = {
    "TRUNCATE": "http-nio-8080-exec-90",
    "DIVERGE_SKIP_FRAUD": "http-nio-8080-exec-91",
    "SLOW_LDAP": "http-nio-8080-exec-92",
}
# Give each defect its own dedicated thread, free exactly at the intended
# moment, so injection time is not at the mercy of where the 3-day simulation
# left that thread's queue.
for tname in DEFECT_THREADS.values():
    THREAD_POOL.append(tname)
    thread_next_free[tname] = START

def run_defect_episode(arrival, flow_name, defect, forced_thread):
    thread_next_free[forced_thread] = arrival
    global pick_thread
    original_pick_thread = pick_thread
    pick_thread = lambda a: forced_thread
    try:
        run_episode(arrival, flow_name, defect=defect)
    finally:
        pick_thread = original_pick_thread

run_defect_episode(defect_time_1, "ORDER", "TRUNCATE", DEFECT_THREADS["TRUNCATE"])
run_defect_episode(defect_time_2, "PAYMENT", "DIVERGE_SKIP_FRAUD", DEFECT_THREADS["DIVERGE_SKIP_FRAUD"])
run_defect_episode(defect_time_3, "LOGIN", "SLOW_LDAP", DEFECT_THREADS["SLOW_LDAP"])

# ---------------------------------------------------------------------------
# Sort all records by timestamp (this is the "true" order; files will be
# written per-day, which is how a real rotating appender would produce them)
# ---------------------------------------------------------------------------

records.sort(key=lambda r: r["ts"])

# sprinkle a few malformed lines in, in-place, at random positions
MALFORMED_SAMPLES = [
    "2026-08-21 03:14:07 WARN  disk usage at 92% on /var/log",
    "<<<truncated by log rotation>>>",
    "",
    "NULL NULL NULL NULL NULL",
]

# ---------------------------------------------------------------------------
# Write files: one per day, plus a duplicate-appender error.log
# ---------------------------------------------------------------------------

import os
os.makedirs(OUT_DIR, exist_ok=True)

def line_for(r):
    return f"{fmt_ts(r['ts'])} | {r['level']:5s} | {r['thread']} | {r['callsite']} | {r['message']}"

day_files = {}
error_log_lines = []

for r in records:
    day_key = r["ts"].strftime("%Y-%m-%d")
    day_files.setdefault(day_key, []).append(r)

for day_key, day_records in sorted(day_files.items()):
    fname = os.path.join(OUT_DIR, f"app.log.{day_key}")
    with open(fname, "w") as f:
        # interleave a malformed line occasionally
        malformed_budget = 3
        for idx, r in enumerate(day_records):
            f.write(line_for(r) + "\n")
            if r["stack"]:
                for frame in r["stack"]:
                    f.write(frame + "\n")
                error_log_lines.append(r)  # duplicate appender: ERROR events also land in error.log
            if r["level"] == "ERROR":
                error_log_lines.append(r)
            if malformed_budget > 0 and random.random() < 0.0008:
                f.write(random.choice(MALFORMED_SAMPLES) + "\n")
                malformed_budget -= 1

with open(os.path.join(OUT_DIR, "error.log"), "w") as f:
    seen = set()
    for r in error_log_lines:
        key = (r["ts"], r["thread"], r["callsite"])
        if key in seen:
            continue
        seen.add(key)
        f.write(line_for(r) + "\n")
        if r["stack"]:
            for frame in r["stack"]:
                f.write(frame + "\n")

# ---------------------------------------------------------------------------
# Write ground-truth.yaml (charter section 6 / Phase 7 format)
# ---------------------------------------------------------------------------

gt_path = os.path.join(OUT_DIR, "ground-truth.yaml")
with open(gt_path, "w") as f:
    f.write("# Known defects injected into this synthetic corpus.\n")
    f.write("# Used by `tfa validate` (charter Phase 7) to confirm each defect\n")
    f.write("# appears in the top 20 ranked findings.\n\n")
    f.write("defects:\n")
    for d in ground_truth_defects:
        f.write(f"  - id: {d['id']}\n")
        f.write(f"    type: {d['type']}\n")
        f.write(f"    flow: {d['flow']}\n")
        f.write(f"    threadId: \"{d['thread']}\"\n")
        f.write(f"    orderId: \"{d['orderId']}\"\n")
        f.write(f"    approxTimestamp: \"{d['approx_timestamp']}\"\n")
        f.write(f"    expectedDivergenceCallSite: \"{d['expected_divergence_callsite']}\"\n")
        f.write(f"    description: >\n")
        f.write(f"      {d['description']}\n\n")

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

print(f"Total records generated: {len(records)}")
print(f"Days covered: {sorted(day_files.keys())}")
for day_key, day_records in sorted(day_files.items()):
    print(f"  {day_key}: {len(day_records)} records")
print(f"error.log duplicate lines: {len(error_log_lines)}")
print(f"Defects injected: {len(ground_truth_defects)}")
for d in ground_truth_defects:
    print(f"  - {d['id']}: {d['type']} in {d['flow']} flow, thread {d['thread']}, ~{d['approx_timestamp']}")
print(f"\nFiles written to: {OUT_DIR}")
