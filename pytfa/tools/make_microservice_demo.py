#!/usr/bin/env python3
"""Generate a realistic multi-service corpus in the order/inventory/payment log
format, joined by trace_id, with a known defect: payment-service DOWN.

Produces a population of healthy orders (payment UP) plus a few where the payment
service is unreachable, so the population-baseline engine has something to compare
against. Use it to prove end-to-end detection before pointing TFA at real logs.

    python tools/make_microservice_demo.py out
    python -m tfa.cli analyze  out/logs --config out/config.yaml
    python -m tfa.cli validate out/logs --config out/config.yaml --ground-truth out/ground-truth.yaml
"""
from __future__ import annotations

import sys
from datetime import datetime, timedelta
from pathlib import Path

HEALTHY = 30          # orders where payment-service is UP
PAYMENT_DOWN = 3      # orders where payment-service is DOWN  <-- the defect


def tid(n: int) -> str:
    # hex like a real trace id, with a leading letter so YAML never reads it
    # as a (possibly octal) number
    return f"a{n:031x}"


def main(out_dir="out"):
    out = Path(out_dir)
    (out / "logs").mkdir(parents=True, exist_ok=True)
    order, inventory, payment = [], [], []
    defects = []
    t = datetime(2026, 8, 24, 9, 0, 0)

    def w(buf, ts, lvl, thread, cs, msg, trace):
        buf.append((ts, f"{ts.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} | {lvl:<5} | {thread} | "
                        f"{cs} | {msg} [trace_id={trace}]\n"))

    def emit_order(i, trace, ts, payment_up):
        """One end-to-end order flow spread across the three service logs."""
        oth, ith, pth = f"http-nio-8081-exec-{i%4+1}", f"http-nio-8082-exec-{i%3+1}", f"http-nio-8083-exec-{i%2+1}"
        oid = f"ORD-{2000+i}"
        c = ts
        w(order, c, "INFO", oth, "OrderController:28", f"Received order placement request customerName=Sushil item=laptop qty=1", trace); c += timedelta(milliseconds=3)
        w(order, c, "INFO", oth, "OrderProcessingService:41", f"Received new order {oid} for customer=Sushil item=laptop qty=1", trace); c += timedelta(milliseconds=5)
        w(order, c, "DEBUG", oth, "JdbcTemplate:112", "INSERT INTO order (...) VALUES (?,?,?,?,?,?) executed in 12ms", trace); c += timedelta(milliseconds=3)
        # --- inventory leg (always healthy here) ---
        w(order, c, "INFO", oth, "OrderProcessingService:53", f"Calling inventory-service to reserve stock for order {oid}", trace); c += timedelta(milliseconds=2)
        w(order, c, "DEBUG", oth, "InventoryClient:24", "POST http://localhost:8082/inventory/reserve payload={item=laptop, quantity=1}", trace)
        ic = c + timedelta(milliseconds=4)
        w(inventory, ic, "INFO", ith, "InventoryController:31", "Checking stock for item=laptop requestedQty=1", trace); ic += timedelta(milliseconds=3)
        w(inventory, ic, "DEBUG", ith, "JdbcTemplate:98", "SELECT ... executed in 6ms", trace); ic += timedelta(milliseconds=2)
        w(inventory, ic, "DEBUG", ith, "InventoryController:39", "Stock check passed: available=50 requested=1", trace); ic += timedelta(milliseconds=140)
        w(inventory, ic, "INFO", ith, "InventoryController:46", "Reserved 1 units of laptop. Remaining=49", trace)
        c = ic + timedelta(milliseconds=2)
        w(order, c, "DEBUG", oth, "InventoryClient:27", "Response from inventory-service: {success=true, remaining=49} in 163ms", trace); c += timedelta(milliseconds=2)
        # --- payment leg ---
        w(order, c, "INFO", oth, "OrderProcessingService:62", f"Calling payment-service to charge amount for order {oid}", trace); c += timedelta(milliseconds=2)
        w(order, c, "DEBUG", oth, "PaymentClient:23", "POST http://localhost:8083/payments/charge payload={amount=75000.0}", trace)
        if payment_up:
            pc = c + timedelta(milliseconds=5)
            w(payment, pc, "INFO", pth, "PaymentController:29", "Processing payment of amount=75000.0", trace); pc += timedelta(milliseconds=240)
            w(payment, pc, "DEBUG", pth, "JdbcTemplate:87", "INSERT INTO payment (amount, status) VALUES (?,?) executed in 8ms", trace); pc += timedelta(milliseconds=3)
            w(payment, pc, "INFO", pth, "PaymentController:36", f"Payment {100+i} recorded with status=SUCCESS", trace)
            c = pc + timedelta(milliseconds=4)
            w(order, c, "DEBUG", oth, "PaymentClient:26", f"Response from payment-service: {{status=SUCCESS, paymentId={100+i}}} in 256ms", trace); c += timedelta(milliseconds=2)
            w(order, c, "DEBUG", oth, "JdbcTemplate:112", "UPDATE order SET status=? WHERE order_id=? executed in 9ms", trace); c += timedelta(milliseconds=2)
            w(order, c, "INFO", oth, "OrderProcessingService:70", f"Order {oid} CONFIRMED and saved", trace); c += timedelta(milliseconds=2)
            w(order, c, "INFO", oth, "OrderController:38", f"Responding to client with status=CONFIRMED traceId={trace}", trace)
        else:
            # payment-service DOWN: connection refused after a retry/timeout, no
            # PaymentController lines at all, order never confirmed.
            c += timedelta(seconds=5)                       # hangs on the dead socket
            order.append((c, f"{c.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} | ERROR | {oth} | "
                             f"PaymentClient:34 | Payment call failed: I/O error on POST "
                             f"http://localhost:8083/payments/charge: Connection refused [trace_id={trace}]\n"
                             "org.springframework.web.client.ResourceAccessException: Connection refused\n"
                             "\tat com.app.PaymentClient.charge(PaymentClient.java:34)\n"))
            c += timedelta(milliseconds=4)
            w(order, c, "WARN", oth, "OrderProcessingService:66", f"Payment failed for order {oid}, marking PAYMENT_FAILED", trace); c += timedelta(milliseconds=3)
            w(order, c, "DEBUG", oth, "JdbcTemplate:112", "UPDATE order SET status=? WHERE order_id=? executed in 8ms", trace)
        return c

    n = 0
    for i in range(HEALTHY // 2):
        emit_order(n, tid(n), t, payment_up=True); t += timedelta(seconds=20); n += 1
    for j in range(PAYMENT_DOWN):
        trace = tid(n)
        start = t
        emit_order(n, trace, t, payment_up=False)
        defects.append(("DEF-PAYMENT-DOWN-%d" % (j + 1), trace, start,
                        "PaymentClient:34", "payment-service down: order never confirmed"))
        t += timedelta(seconds=20); n += 1
    # traffic continues after the outage, so the defects are not at the corpus edge
    for i in range(HEALTHY - HEALTHY // 2):
        emit_order(n, tid(n), t, payment_up=True); t += timedelta(seconds=20); n += 1

    for name, buf in (("orderservice.log", order), ("inventoryservice.log", inventory),
                      ("paymentservice.log", payment)):
        buf.sort(key=lambda r: r[0])
        (out / "logs" / name).write_text("".join(x for _, x in buf), encoding="utf-8")

    (out / "config.yaml").write_text("""profile: default
segmentation:
  strategy: CORRELATION_ID
  correlationIdPattern: 'trace_id=([0-9a-f]+)'
  terminalCallSites: [OrderController:38]
clustering:
  signatureK: 3
  minClusterSize: 10
detection:
  timingFactor: 3.0
ranking:
  topN: 20
""", encoding="utf-8")

    gt = "defects:\n"
    for did, trace, start, cs, desc in defects:
        gt += (f"  - id: {did}\n    threadId: \"{trace}\"\n    timestampWindow:\n"
               f"      start: \"{(start - timedelta(seconds=1)).strftime('%Y-%m-%dT%H:%M:%SZ')}\"\n"
               f"      end:   \"{(start + timedelta(seconds=60)).strftime('%Y-%m-%dT%H:%M:%SZ')}\"\n"
               f"    expectedDivergenceCallSite: \"{cs}\"\n    description: \"{desc}\"\n")
    (out / "ground-truth.yaml").write_text(gt, encoding="utf-8")
    print(f"wrote {out}/ : {HEALTHY} healthy orders + {PAYMENT_DOWN} with payment-service DOWN")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "out")
