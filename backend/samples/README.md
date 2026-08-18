# Sample data — end-to-end walkthrough

Ready-to-upload artifacts for exercising the analyzer by hand. Everything here is
**synthetic** (built by `make_samples.py`, no real user data), but shaped to mirror
how real HotSpot dumps look so the findings resolve to exact `file:line`.

## Generate

```bash
python3 make_samples.py
```

Writes three files next to the script (they're git-ignored — regenerate as needed):

| File                  | What it is |
|-----------------------|------------|
| `order-leak.hprof`    | A heap dump with two distinct, real leak shapes (below). |
| `baseline.hprof`      | A healthy dump — no dominant class, no static caches — for the "no red flags" contrast. |
| `order-leak-gc.log`   | A G1 GC log for the same incident: the post-GC live set ratchets upward and ends in Full GCs (the run-up to OOM). |
| `order-leak-src.zip`  | The `com.example` mini-app source. Attach it so findings resolve to a file and line. |
| `incident-thread-dump.txt` | A matching thread dump (17 threads) — committed, not generated. |

## What `order-leak.hprof` demonstrates

Two leaks of **different shapes**, so each exercises a different analyzer:

1. **Instance-field retention → the reverse-path tracer.**
   `com.example.Order` is the single biggest consumer of heap (~49%). The orders are
   retained through a real `HashMap` (`Node[]` table → `Node.value`) held by the
   **instance** field `OrderCache.entries`, where the `OrderCache` is kept alive by a
   live worker thread (a GC root) — *not* a static field. The tracer climbs the
   reference graph in reverse and reports:

   ```
   Order ← HashMap$Node.value ← HashMap$Node[] ← HashMap.table ← OrderCache.entries
   ```

   → **CRITICAL**, resolved to `OrderCache.java:12`.

2. **Static collection → the static-field finder.**
   `com.example.Session` objects are held by the static `SessionRegistry.SESSIONS`
   `ConcurrentHashMap` that's only ever added to.

   → **WARNING**, resolved to `SessionRegistry.java:16`.

## Walkthrough

1. **Heap** — upload `order-leak.hprof` in the Heap Dump zone. You should see
   `com.example.Order` dominating the histogram, the CRITICAL retention path, and the
   WARNING static-cache finding.
2. **Source** — attach `order-leak-src.zip` (drag onto the Source zone, or point at
   the unzipped path). The findings now carry `file:line` and code snippets.
3. **Thread** — upload `incident-thread-dump.txt`. It shows worker threads parked in
   `OrderService.loadAll()` allocating `Order`s.
4. **GC log** — upload `order-leak-gc.log`. You should see collector `G1`, a
   **CRITICAL** "live set is growing ~420 MB/min — likely a memory leak" finding (the
   post-GC occupancy slope), Full GCs, and a long-pause warning. This is the over-time
   proof a single heap snapshot can't give.
5. **Correlation** — with heap + thread + GC all analyzed in the session, the
   **cross-dump** panel produces the headline:
   *"Confirmed memory leak: heap, GC trend, and threads all point at `Order`."* Three
   independent signals agree — the heap shows `Order` dominating, the GC log shows the
   live set genuinely trending toward OOM, and a live thread sits in the allocator
   (`OrderService.java:21`) — with the retaining field at `OrderCache.java:12`.
6. **Baseline** — for contrast, upload `baseline.hprof`: no dominant class, verdict
   `healthy`, "No obvious red flags".

## Source map

| Class | Role |
|-------|------|
| `OrderService.loadAll()` | Allocates an `Order` per row with no pagination — the allocator the thread frames sit in. |
| `OrderCache.entries`     | Unbounded **instance**-field `HashMap` — the retention anchor. |
| `App.main()`             | Holds the `OrderCache` on a live thread (the GC root) for the process lifetime. |
| `SessionRegistry.SESSIONS` | Unbounded **static** `ConcurrentHashMap` — the static-leak anchor. |
