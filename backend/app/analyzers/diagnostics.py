"""
Diagnostic engine for thread dumps.

Takes parsed thread data and produces:
  - Findings (severity-rated observations with remediation hints)
  - Stack-trace groupings (find clusters of threads doing the same thing)
  - Blocked chains (who's waiting on whom)
  - Plain-English summary
"""
from __future__ import annotations
import hashlib
from collections import Counter, defaultdict
from typing import List, Dict, Optional, Any
from ..schemas import (
    ThreadInfo, Finding, Severity, ThreadState, DeadlockCycle,
    StackGroup, ThreadDumpAnalysis, SourceLocation, PoolInfo, HotThread,
)
from .source import SourceIndex, is_user_code, first_user_frame


# Patterns we recognize for antipattern detection
DB_PATTERNS = (
    "java.sql.",
    "com.zaxxer.hikari",
    "org.apache.tomcat.jdbc",
    "org.apache.commons.dbcp",
    "org.hibernate.",
    "oracle.jdbc",
    "com.mysql.",
    "org.postgresql.",
)

HTTP_CLIENT_PATTERNS = (
    "org.apache.http",
    "okhttp3.",
    "java.net.http",
    "feign.",
    "org.springframework.web.client.RestTemplate",
)

POOL_HINTS = ("pool", "executor", "worker", "exec-")
GC_HINTS = ("GC ", "ConcurrentGC", "G1 ", "ZGC", "Shenandoah", "ParallelGC")


def _stack_signature(thread: ThreadInfo, depth: int = 5) -> str:
    """Hash of top-N stack frames for grouping similar threads."""
    sigs = [f.signature for f in thread.stack[:depth]]
    return hashlib.sha1("|".join(sigs).encode()).hexdigest()[:12]


def _normalize_thread_name(name: str) -> str:
    """Strip numeric/UUID suffixes from thread names so 'pool-1-thread-5' groups with 'pool-1-thread-12'."""
    import re as _re
    return _re.sub(r'\d+', '#', name)


def build_stack_groups(threads: List[ThreadInfo], depth: int = 5, min_size: int = 2) -> List[StackGroup]:
    """Cluster threads by their top-N stack frames."""
    buckets: Dict[str, List[ThreadInfo]] = defaultdict(list)
    for t in threads:
        if not t.stack:
            continue
        buckets[_stack_signature(t, depth)].append(t)

    groups: List[StackGroup] = []
    for sig, group_threads in buckets.items():
        if len(group_threads) < min_size:
            continue
        sample = group_threads[0]
        state_counter = Counter(t.state.value for t in group_threads)
        groups.append(StackGroup(
            signature=sig,
            top_frames=[f.signature for f in sample.stack[:depth]],
            thread_names=[t.name for t in group_threads],
            count=len(group_threads),
            states=dict(state_counter),
        ))
    groups.sort(key=lambda g: g.count, reverse=True)
    return groups


def build_blocked_chains(threads: List[ThreadInfo]) -> List[Dict[str, Any]]:
    """Build chains of 'thread A waiting on lock held by thread B who is waiting on...'."""
    # Map locked address -> holder thread
    holder_of: Dict[str, str] = {}
    for t in threads:
        for lock in t.held_locks:
            holder_of[lock.address] = t.name

    chains: List[Dict[str, Any]] = []
    for t in threads:
        wanted = t.wanted_lock
        if not wanted or wanted.op == "parking to wait for":
            continue
        holder = holder_of.get(wanted.address)
        if holder and holder != t.name:
            chains.append({
                "waiter": t.name,
                "waiting_for_lock": wanted.address,
                "lock_class": wanted.class_name,
                "holder": holder,
            })
    return chains


def detect_findings(
    threads: List[ThreadInfo],
    deadlocks: List[DeadlockCycle],
    blocked_chains: List[Dict[str, Any]],
    stack_groups: List[StackGroup],
) -> List[Finding]:
    findings: List[Finding] = []
    total = len(threads)

    # 1. Deadlocks (always critical)
    for dl in deadlocks:
        findings.append(Finding(
            severity=Severity.CRITICAL,
            title=f"Java-level deadlock involving {len(dl.threads)} thread(s)",
            description=(
                f"The JVM reports a deadlock: {dl.description}. "
                "These threads are permanently stuck waiting on each other's locks. "
                "The affected work units will never complete."
            ),
            affected_threads=dl.threads,
            impact=(
                "Whatever these threads were doing is frozen forever — requests hang until timeout, "
                "and if more requests hit the same code path, they pile up too. A restart clears it "
                "but the deadlock will recur under the same timing."
            ),
            likely_cause=(
                "Two code paths acquire the same pair of locks in opposite order. Thread A holds lock 1 "
                "and wants lock 2; thread B holds lock 2 and wants lock 1."
            ),
            evidence=[f"JVM deadlock detector: {dl.description}"] + [f"thread: {t}" for t in dl.threads[:4]],
            remediation=(
                "Establish a consistent lock-acquisition order across the affected code paths, "
                "or replace synchronized blocks with timed tryLock() to fail fast. "
                "The source locations below show exactly where each thread is stuck."
            ),
            category="deadlock",
        ))

    # 2. Lock contention - lots of threads BLOCKED on the same lock
    block_targets: Dict[str, List[str]] = defaultdict(list)
    for t in threads:
        if t.state == ThreadState.BLOCKED and t.wanted_lock:
            block_targets[t.wanted_lock.address].append(t.name)
    for addr, waiters in block_targets.items():
        if len(waiters) >= 3:
            findings.append(Finding(
                severity=Severity.CRITICAL if len(waiters) >= 10 else Severity.WARNING,
                title=f"{len(waiters)} threads BLOCKED on the same lock {addr}",
                description=(
                    f"Multiple threads are queued waiting for the same monitor. "
                    f"This is classic lock contention and likely a throughput bottleneck. "
                    f"Affected: {', '.join(waiters[:5])}{'...' if len(waiters) > 5 else ''}."
                ),
                affected_threads=waiters,
                impact=(
                    "Throughput through this code path is limited to one thread at a time — "
                    "the rest queue. Under load the queue grows and response times climb."
                ),
                likely_cause=(
                    "A synchronized method/block guarding work that takes too long: a slow query, "
                    "remote call, or heavy computation inside the lock."
                ),
                evidence=[f"{len(waiters)} threads waiting on monitor {addr}"] + waiters[:5],
                remediation=(
                    "Identify the holder thread (look for the same lock address in 'locked' entries — "
                    "shown in the blocked chains section) and shrink the critical section. Consider "
                    "read/write locks, lock striping, or concurrent data structures (e.g., ConcurrentHashMap)."
                ),
                category="contention",
            ))

    # 3. DB connection pool exhaustion - many threads waiting in JDBC code
    db_waiters = [
        t for t in threads
        if t.state in (ThreadState.WAITING, ThreadState.TIMED_WAITING)
        and any(any(p in f.class_name for p in DB_PATTERNS) for f in t.stack[:15])
    ]
    if len(db_waiters) >= 5:
        findings.append(Finding(
            severity=Severity.CRITICAL,
            title=f"Suspected DB connection pool exhaustion ({len(db_waiters)} threads waiting)",
            description=(
                f"{len(db_waiters)} threads are parked inside JDBC/connection-pool code. "
                "When request threads can't acquire connections, latency spikes and the app appears hung."
            ),
            affected_threads=[t.name for t in db_waiters][:10],
            impact=(
                "Every request that needs the database is queueing for a connection. "
                "Users see slow pages or timeouts; under sustained load the app appears completely hung."
            ),
            likely_cause=(
                "Either the pool is too small for the load, or — more often — connections are being "
                "held too long by slow queries, long transactions, or code that forgets to close them."
            ),
            evidence=[f"{t.name} waiting in {t.stack[0].class_name if t.stack else '?'}" for t in db_waiters[:6]],
            remediation=(
                "Check pool size vs. demand (HikariCP maximumPoolSize). Look for slow queries holding "
                "connections (enable leakDetectionThreshold=30000 in HikariCP). Verify connections are "
                "released in try-with-resources/finally blocks."
            ),
            category="exhaustion",
        ))

    # 4. HTTP client exhaustion
    http_waiters = [
        t for t in threads
        if t.state in (ThreadState.WAITING, ThreadState.TIMED_WAITING)
        and any(any(p in f.class_name for p in HTTP_CLIENT_PATTERNS) for f in t.stack[:15])
    ]
    if len(http_waiters) >= 5:
        findings.append(Finding(
            severity=Severity.WARNING,
            title=f"{len(http_waiters)} threads waiting in HTTP client code",
            description=(
                "Many threads are stuck inside an outbound HTTP client. "
                "Likely causes: slow upstream, missing timeouts, or HTTP-connection-pool exhaustion."
            ),
            affected_threads=[t.name for t in http_waiters][:10],
            remediation=(
                "Verify connect/read timeouts are configured (no defaults). "
                "Check connection-manager max-per-route limits. "
                "Add upstream latency monitoring and circuit breakers."
            ),
            category="exhaustion",
        ))

    # 5. Thread pool saturation — handled by build_pools() + _pool_findings() in analyze(),
    # which produce richer per-pool state breakdowns than the old heuristic here did.

    # 6. Stack-trace hotspot (many threads in identical code path)
    for group in stack_groups[:3]:
        if group.count >= max(5, total * 0.15):
            findings.append(Finding(
                severity=Severity.WARNING,
                title=f"{group.count} threads share an identical top-of-stack",
                description=(
                    f"{group.count} threads are all executing through: {group.top_frames[0]} → {group.top_frames[1] if len(group.top_frames) > 1 else '(end)'} ... "
                    "This concentration usually points to either a hot code path under load or a shared blocking call."
                ),
                affected_threads=group.thread_names[:10],
                remediation=(
                    "Inspect the full stack of one representative thread. "
                    "If the path is CPU-bound and unavoidable, scale horizontally. "
                    "If it includes a blocking call (DB, HTTP, lock), address that bottleneck."
                ),
                category="hotspot",
            ))

    # 7. Long blocked chains
    if blocked_chains:
        # Find chains longer than 1 hop
        chain_map = {bc["waiter"]: bc["holder"] for bc in blocked_chains}
        for waiter in list(chain_map.keys()):
            chain = [waiter]
            cursor = chain_map.get(waiter)
            while cursor and cursor not in chain:
                chain.append(cursor)
                cursor = chain_map.get(cursor)
            if len(chain) >= 3:
                findings.append(Finding(
                    severity=Severity.WARNING,
                    title=f"Blocking chain of {len(chain)} threads",
                    description=(
                        f"Thread chain: {' → '.join(chain)}. "
                        "Each thread is waiting on a lock held by the next."
                    ),
                    affected_threads=chain,
                    remediation=(
                        "Investigate the root holder. Reducing its critical section will unblock the whole chain."
                    ),
                    category="contention",
                ))
                break  # one report is enough; chains overlap

    # 8. Healthy baseline note
    if not findings:
        findings.append(Finding(
            severity=Severity.INFO,
            title="No major problems detected",
            description=(
                f"Analyzed {total} threads. No deadlocks, no significant lock contention, "
                "no obvious connection-pool exhaustion. Most threads appear idle and ready for work."
            ),
            impact="The application looks healthy at the moment of this snapshot.",
            remediation=(
                "If you're still seeing a problem, it may be intermittent — capture 3-4 dumps "
                "10 seconds apart during the incident and compare, or check the heap instead."
            ),
            category="none",
        ))

    return findings


def build_summary(
    threads: List[ThreadInfo],
    state_breakdown: Dict[str, int],
    findings: List[Finding],
    deadlocks: List[DeadlockCycle],
) -> str:
    """A 2-3 sentence plain-English summary."""
    total = len(threads)
    runnable = state_breakdown.get("RUNNABLE", 0)
    blocked = state_breakdown.get("BLOCKED", 0)
    waiting = state_breakdown.get("WAITING", 0) + state_breakdown.get("TIMED_WAITING", 0)

    parts: List[str] = []
    parts.append(
        f"This dump contains {total} threads: "
        f"{runnable} actively running, {blocked} blocked on locks, {waiting} waiting/idle."
    )

    if deadlocks:
        parts.append(
            f"⚠️ The JVM detected {len(deadlocks)} deadlock(s) — work in those threads will never complete."
        )

    crit = [f for f in findings if f.severity == Severity.CRITICAL]
    warn = [f for f in findings if f.severity == Severity.WARNING]
    if crit:
        parts.append(f"Found {len(crit)} critical issue(s) that likely explain the problem you're investigating.")
    elif warn:
        parts.append(f"Found {len(warn)} warning(s) worth investigating; no critical issues detected.")
    else:
        parts.append("No critical issues detected — the JVM appears healthy at this snapshot.")

    return " ".join(parts)


def build_pools(threads: List[ThreadInfo], min_size: int = 3) -> List[PoolInfo]:
    """Group threads into logical pools by name prefix and assess each pool's health.

    'http-nio-8080-exec-1..50' → pool 'http-nio-8080-exec' with a per-state
    breakdown. A pool where most threads are BLOCKED or RUNNABLE tells a very
    different story than one parked waiting for work.
    """
    groups: Dict[str, List[ThreadInfo]] = defaultdict(list)
    for t in threads:
        base = _normalize_thread_name(t.name)
        groups[base].append(t)

    pools: List[PoolInfo] = []
    for name, members in groups.items():
        if len(members) < min_size:
            continue
        states = Counter(m.state.value for m in members)
        total = len(members)
        dominant = states.most_common(1)[0][0]
        blocked = states.get("BLOCKED", 0)
        runnable = states.get("RUNNABLE", 0)
        busy = blocked + runnable
        busy_pct = busy / total * 100
        blocked_pct = blocked / total * 100

        if blocked_pct >= 50:
            health = "saturated"
            note = (f"{blocked}/{total} threads are blocked on locks — requests to this pool "
                    f"are queueing behind a contended resource.")
        elif busy_pct >= 80:
            health = "busy"
            note = (f"{busy}/{total} threads are active. The pool is near capacity; "
                    f"new work will wait if load increases.")
        elif busy_pct >= 50:
            health = "busy"
            note = f"{busy}/{total} threads active — moderate load."
        else:
            health = "ok"
            note = f"Most threads idle ({total - busy}/{total} waiting for work) — normal for a quiet pool."

        pools.append(PoolInfo(
            name=name, total=total, states=dict(states),
            dominant_state=dominant, busy_pct=round(busy_pct, 1),
            blocked_pct=round(blocked_pct, 1), health=health, note=note,
        ))

    # Saturated first, then busiest, then biggest
    order = {"saturated": 0, "busy": 1, "ok": 2}
    pools.sort(key=lambda p: (order[p.health], -p.busy_pct, -p.total))
    return pools


_GC_THREAD_HINTS = ("GC Thread", "G1 ", "ParGC", "CMS", "ZGC", "Shenandoah", "Concurrent Mark", "GC task")


def build_hot_threads(threads: List[ThreadInfo], top_n: int = 10) -> List[HotThread]:
    """Rank threads by CPU share of their lifetime (needs jstack's cpu=/elapsed= fields)."""
    hot: List[HotThread] = []
    for t in threads:
        if not t.cpu_ms or not t.elapsed_s or t.elapsed_s <= 0:
            continue
        cpu_pct = (t.cpu_ms / (t.elapsed_s * 1000.0)) * 100
        if cpu_pct < 1.0:   # ignore noise
            continue
        top_frame = None
        if t.stack:
            f = t.stack[0]
            top_frame = f"{f.class_name}.{f.method}"
        hot.append(HotThread(
            name=t.name, cpu_ms=round(t.cpu_ms, 1), elapsed_s=round(t.elapsed_s, 1),
            cpu_pct=round(cpu_pct, 1), state=t.state.value, top_frame=top_frame,
            is_gc=any(h in t.name for h in _GC_THREAD_HINTS),
        ))
    hot.sort(key=lambda h: -h.cpu_pct)
    return hot[:top_n]


def compute_verdict(findings: List[Finding]) -> str:
    if any(f.severity == Severity.CRITICAL for f in findings):
        return "critical"
    if any(f.severity == Severity.WARNING for f in findings):
        return "degraded"
    return "healthy"


def _pool_findings(pools: List[PoolInfo]) -> List[Finding]:
    """Turn saturated pools into first-class findings with plain-English context."""
    out: List[Finding] = []
    for p in pools:
        if p.health != "saturated":
            continue
        out.append(Finding(
            severity=Severity.WARNING,
            title=f"Thread pool '{p.name}' is saturated ({p.states.get('BLOCKED', 0)}/{p.total} blocked)",
            description=(
                f"The '{p.name}' pool has {p.total} threads and {p.blocked_pct:.0f}% of them are "
                f"BLOCKED waiting for locks. When most of a request-serving pool is blocked, incoming "
                f"requests queue up and users see timeouts or slow responses."
            ),
            impact="Requests handled by this pool are stalling; throughput is limited by lock contention, not CPU.",
            likely_cause="A shared resource (synchronized block, connection pool, cache) that every request needs is held too long by someone.",
            evidence=[f"{s}: {n} threads" for s, n in sorted(p.states.items(), key=lambda kv: -kv[1])],
            remediation=(
                "Find the lock these threads are waiting on (see the blocked-chains section), then either "
                "shorten the critical section, use a more granular lock, or replace it with a concurrent data structure."
            ),
            category="contention",
            affected_threads=[],
        ))
    return out


def _hot_thread_findings(hot: List[HotThread], total_threads: int) -> List[Finding]:
    out: List[Finding] = []
    gc_hot = [h for h in hot if h.is_gc and h.cpu_pct >= 25]
    if gc_hot:
        names = [h.name for h in gc_hot]
        out.append(Finding(
            severity=Severity.WARNING,
            title=f"GC threads consuming significant CPU ({len(gc_hot)} threads ≥25% of lifetime)",
            description=(
                "Garbage-collection threads have used a large share of CPU since JVM start. "
                "Heavy GC activity usually means the heap is under pressure — objects are being "
                "allocated and collected faster than is healthy, or the heap is simply too small."
            ),
            impact="Application threads are repeatedly paused or starved of CPU while GC runs; latency becomes spiky.",
            likely_cause="Heap too small for the live set, an allocation-heavy code path, or a memory leak pushing the heap toward its limit.",
            evidence=[f"{h.name}: {h.cpu_pct:.0f}% CPU over {h.elapsed_s:.0f}s" for h in gc_hot[:5]],
            remediation=(
                "Capture a heap dump and check what's filling the heap (use the Heap Dump analyzer here). "
                "Enable GC logging (-Xlog:gc*) to confirm collection frequency, and consider increasing -Xmx if the live set is legitimately large."
            ),
            category="gc",
            affected_threads=names,
        ))

    app_hot = [h for h in hot if not h.is_gc and h.cpu_pct >= 60]
    if app_hot:
        out.append(Finding(
            severity=Severity.INFO,
            title=f"{len(app_hot)} thread(s) running near-continuously since start",
            description=(
                "These threads have been on-CPU for most of their lifetime. That's expected for "
                "dedicated worker/polling loops, but for request threads it can indicate a spin "
                "loop or runaway computation."
            ),
            impact="If unintentional, these threads monopolize cores and starve other work.",
            likely_cause="Busy-wait loop, unbounded retry loop, very hot computation, or simply a legitimately busy worker.",
            evidence=[f"{h.name}: {h.cpu_pct:.0f}% CPU ({h.top_frame or 'no frame'})" for h in app_hot[:5]],
            remediation="Check each thread's top frame. Spin loops typically show the same frame in repeated dumps — take 2-3 dumps a few seconds apart and compare.",
            category="cpu",
            affected_threads=[h.name for h in app_hot],
        ))
    return out


_SOCKET_READ_HINTS = ("socketRead", "SocketDispatcher.read", "Net.poll", "SocketInputStream.read")


def _stuck_io_finding(threads: List[ThreadInfo]) -> Optional[Finding]:
    """Many RUNNABLE threads sitting in socket reads = a slow downstream dependency."""
    stuck = []
    for t in threads:
        if t.state != ThreadState.RUNNABLE or not t.stack:
            continue
        top3 = " ".join(f"{f.class_name}.{f.method}" for f in t.stack[:3])
        if any(h in top3 for h in _SOCKET_READ_HINTS):
            stuck.append(t.name)
    if len(stuck) < 3:
        return None
    return Finding(
        severity=Severity.WARNING,
        title=f"{len(stuck)} threads stuck reading from network sockets",
        description=(
            "These threads show as RUNNABLE but are actually parked inside a blocking socket read — "
            "the JVM reports native I/O waits as RUNNABLE, which is misleading. Many threads in this "
            "state means a downstream service (database, HTTP API, message broker) is responding slowly or not at all."
        ),
        impact="Requests are hanging on a slow external dependency; thread pools drain as more threads pile up here.",
        likely_cause="A slow/unresponsive downstream service, missing read timeouts, or network issues between this JVM and a dependency.",
        evidence=[f"{n}" for n in stuck[:8]],
        remediation=(
            "Identify the dependency from the stack frames below the socket read. Set explicit connect/read timeouts "
            "(e.g. socketTimeout on JDBC, readTimeout on HTTP clients) so threads fail fast instead of hanging."
        ),
        category="io",
        affected_threads=stuck,
    )


def _build_source_locations_for_finding(
    finding: Finding,
    threads_by_name: Dict[str, ThreadInfo],
    source: Optional[SourceIndex],
) -> List[SourceLocation]:
    """For each affected thread, find the most relevant user-code frame and
    (when a source index is attached) resolve it to a real file + snippet."""
    locations: List[SourceLocation] = []
    seen_keys = set()  # dedupe by (class, method, line)

    for name in finding.affected_threads[:6]:  # cap to keep payload bounded
        t = threads_by_name.get(name)
        if not t or not t.stack:
            continue

        # Choose which frame to report:
        # 1. For deadlocks/contention, the frame holding the lock op is most relevant
        # 2. Otherwise, the topmost user-code frame
        frame_idx: Optional[int] = None
        if finding.category in ("deadlock", "contention"):
            for lock in t.locks:
                if lock.op in ("waiting to lock", "locked"):
                    frame_idx = lock.frame_index
                    break
        if frame_idx is None:
            frame_idx = first_user_frame(t.stack)
        if frame_idx is None and t.stack:
            frame_idx = 0  # fall back to topmost

        if frame_idx is None or frame_idx >= len(t.stack):
            continue

        frame = t.stack[frame_idx]
        key = (frame.class_name, frame.method, frame.line)
        if key in seen_keys:
            continue
        seen_keys.add(key)

        loc = SourceLocation(
            class_name=frame.class_name,
            method=frame.method,
            file=frame.file,
            line=frame.line,
            is_user_code=is_user_code(frame.class_name),
        )

        # Resolve through the source index if attached
        if source and frame.line:
            resolved = source.lookup(frame.class_name, frame.line)
            if resolved:
                abs_path, snippet = resolved
                loc.repo_path = source.relative_path(abs_path)
                loc.snippet = snippet

        locations.append(loc)

    return locations


def analyze(text: str, source: Optional[SourceIndex] = None) -> ThreadDumpAnalysis:
    """Top-level entrypoint: text in, full analysis out.

    If a `source` index is provided, findings are enriched with the exact
    file + line + code snippet from the user's repo.
    """
    from .thread_dump import parse_thread_dump  # local import avoids circulars

    threads, deadlocks, timestamp, jvm = parse_thread_dump(text)

    state_breakdown = dict(Counter(t.state.value for t in threads))
    daemon_count = sum(1 for t in threads if t.daemon)

    stack_groups = build_stack_groups(threads, depth=5, min_size=2)
    blocked_chains = build_blocked_chains(threads)
    findings = detect_findings(threads, deadlocks, blocked_chains, stack_groups)

    # Insight layer: pools, hot threads, stuck I/O
    pools = build_pools(threads)
    hot_threads = build_hot_threads(threads)
    findings.extend(_pool_findings(pools))
    findings.extend(_hot_thread_findings(hot_threads, len(threads)))
    io_finding = _stuck_io_finding(threads)
    if io_finding:
        findings.append(io_finding)

    # De-noise: drop the generic "no major problems" info finding if we have real ones
    real = [f for f in findings if f.category != "none"]
    if real:
        findings = real

    summary = build_summary(threads, state_breakdown, findings, deadlocks)
    verdict = compute_verdict(findings)

    # Sort findings by severity (critical first)
    sev_order = {Severity.CRITICAL: 0, Severity.WARNING: 1, Severity.INFO: 2}
    findings.sort(key=lambda f: sev_order.get(f.severity, 99))

    # Enrich each finding with source locations
    threads_by_name = {t.name: t for t in threads}
    for f in findings:
        f.source_locations = _build_source_locations_for_finding(
            f, threads_by_name, source
        )

    return ThreadDumpAnalysis(
        timestamp=timestamp,
        jvm=jvm,
        total_threads=len(threads),
        state_breakdown=state_breakdown,
        daemon_count=daemon_count,
        deadlocks=deadlocks,
        findings=findings,
        stack_groups=stack_groups[:25],
        blocked_chains=blocked_chains,
        threads=threads,
        summary=summary,
        verdict=verdict,
        pools=pools,
        hot_threads=hot_threads,
    )
