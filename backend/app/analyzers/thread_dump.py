"""
Parser for HotSpot JVM thread dumps (jstack / kill -3 / jcmd Thread.print output).

Handles the standard format produced by Oracle/OpenJDK JVMs from Java 8 onward.
"""
from __future__ import annotations
import re
from typing import List, Optional, Tuple
from ..schemas import (
    ThreadInfo, StackFrame, LockOperation, ThreadState, DeadlockCycle
)


# --- Regex patterns ---

# Header example:
# "main" #1 prio=5 os_prio=0 cpu=234.56ms elapsed=10.30s tid=0x00007f8b4000c800 nid=0x1234 waiting on condition  [0x...]
# "Reference Handler" #2 daemon prio=10 os_prio=0 tid=0x... nid=0x... waiting on condition  [0x...]
THREAD_HEADER_RE = re.compile(
    r'^"(?P<name>(?:[^"\\]|\\.)*)"'
    r'(?:\s+#(?P<id>\d+))?'
    r'(?:\s+(?P<daemon>daemon))?'
    r'(?:\s+prio=(?P<prio>\d+))?'
    r'(?:\s+os_prio=\d+)?'
    r'(?:\s+cpu=(?P<cpu>[\d.]+)ms)?'
    r'(?:\s+elapsed=(?P<elapsed>[\d.]+)s)?'
    r'(?:\s+tid=(?P<tid>0x[0-9a-fA-F]+))?'
    r'(?:\s+nid=(?P<nid>0x[0-9a-fA-F]+))?'
    r'(?:\s+(?P<state_hint>[^\[]+?))?'
    r'(?:\s+\[(?P<addr>0x[0-9a-fA-F]+)\])?\s*$'
)

# java.lang.Thread.State: BLOCKED (on object monitor)
STATE_LINE_RE = re.compile(
    r'^\s*java\.lang\.Thread\.State:\s+(?P<state>\w+)(?:\s+\((?P<detail>[^)]+)\))?'
)

# Stack frames:
#   at com.example.Foo.bar(Foo.java:42)
#   at java.lang.Object.wait(java.base@17.0.6/Native Method)
#   at sun.misc.Unsafe.park(Native Method)
FRAME_RE = re.compile(
    r'^\s*at\s+(?P<fqcn>[\w$.<>]+)\.(?P<method>[\w$<>]+)'
    r'(?:\((?:[^@)]+@[\w.+]+/)?(?P<file>[^:)]+?)(?::(?P<line>\d+))?\))?\s*$'
)

# Lock operations within stack:
#   - locked <0x000000076b8b4928> (a java.util.HashMap)
#   - waiting to lock <0x...> (a java.lang.Object)
#   - waiting on <0x...> (a java.util.concurrent.locks.AbstractQueuedSynchronizer$ConditionObject)
#   - parking to wait for  <0x...> (a ...)
LOCK_RE = re.compile(
    r'^\s*-\s+(?P<op>locked|waiting to lock|waiting on|parking to wait for)'
    r'\s*<(?P<addr>0x[0-9a-fA-F]+|no\s+object\s+reference\s+available)>'
    r'(?:\s+\(a\s+(?P<cls>[^)]+)\))?'
)

# Locked ownable synchronizers section starts with this header
LOS_HEADER_RE = re.compile(r'^\s*Locked ownable synchronizers:')
# Within LOS section: "- <0x...> (a ...)" or "- None"
LOS_ITEM_RE = re.compile(
    r'^\s*-\s+<(?P<addr>0x[0-9a-fA-F]+)>(?:\s+\(a\s+(?P<cls>[^)]+)\))?'
)
LOS_NONE_RE = re.compile(r'^\s*-\s+None\s*$')

# Deadlock section
DEADLOCK_HEADER_RE = re.compile(r'^Found (?:one|\d+)\s+Java-level deadlock')
DEADLOCK_THREAD_RE = re.compile(r'^"(?P<name>[^"]+)":\s*$')
DEADLOCK_WAITING_RE = re.compile(
    r'^\s*waiting (?:to lock|for) (?:monitor )?(?P<addr>\S+)(?:.*?which is held by "(?P<holder>[^"]+)")?'
)
DEADLOCK_HELD_BY_RE = re.compile(r'.*which is held by "(?P<holder>[^"]+)"')


def _parse_state(hint: Optional[str]) -> Tuple[ThreadState, Optional[str]]:
    """Map the state hint at the end of the thread header to a ThreadState.

    Note: this is a heuristic. The authoritative state comes from the
    'java.lang.Thread.State:' line if present.
    """
    if not hint:
        return ThreadState.UNKNOWN, None
    hint_lower = hint.strip().lower()
    if "runnable" in hint_lower:
        return ThreadState.RUNNABLE, hint
    if "waiting on condition" in hint_lower:
        return ThreadState.WAITING, hint
    if "waiting for monitor entry" in hint_lower:
        return ThreadState.BLOCKED, hint
    if "in object.wait" in hint_lower:
        return ThreadState.WAITING, hint
    if "sleeping" in hint_lower:
        return ThreadState.TIMED_WAITING, hint
    if "terminated" in hint_lower:
        return ThreadState.TERMINATED, hint
    return ThreadState.UNKNOWN, hint


def _refine_state(state_line: str) -> Tuple[ThreadState, Optional[str]]:
    m = STATE_LINE_RE.match(state_line)
    if not m:
        return ThreadState.UNKNOWN, None
    try:
        return ThreadState(m.group("state")), m.group("detail")
    except ValueError:
        return ThreadState.UNKNOWN, m.group("detail")


def parse_thread_dump(text: str) -> Tuple[List[ThreadInfo], List[DeadlockCycle], Optional[str], Optional[str]]:
    """
    Parse a full thread dump text.

    Returns: (threads, deadlocks, timestamp, jvm_banner)
    """
    lines = text.splitlines()
    threads: List[ThreadInfo] = []
    deadlocks: List[DeadlockCycle] = []
    timestamp: Optional[str] = None
    jvm_banner: Optional[str] = None

    # First few non-empty lines often carry timestamp + JVM banner.
    # jcmd output prepends a "<PID>:" line, so we scan a small window
    # rather than only looking at the very first line.
    nonempty = [l for l in lines if l.strip()]
    if nonempty:
        for line in nonempty[:5]:
            if re.match(r'^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}', line):
                timestamp = line.strip()
                break
        for line in nonempty[:5]:
            if "Full thread dump" in line:
                jvm_banner = line.strip()
                break

    i = 0
    n = len(lines)
    in_deadlock_section = False
    deadlock_buffer: List[str] = []

    while i < n:
        line = lines[i]

        # Detect deadlock section
        if DEADLOCK_HEADER_RE.match(line):
            in_deadlock_section = True
            deadlock_buffer = []
            i += 1
            # consume "===" separator line
            if i < n and re.match(r'^=+\s*$', lines[i]):
                i += 1
            # Read until we hit "Java stack information" or another blank/non-deadlock block
            while i < n:
                if lines[i].startswith("Java stack information"):
                    # The rest of deadlock details follow; we already have the cycle info
                    break
                if re.match(r'^Found\s+\d*\s*deadlock', lines[i]):
                    i += 1
                    continue
                deadlock_buffer.append(lines[i])
                i += 1
            deadlocks.extend(_parse_deadlock_block(deadlock_buffer))
            in_deadlock_section = False
            continue

        # Try to start a new thread block
        m = THREAD_HEADER_RE.match(line)
        if m and line.startswith('"'):
            thread, consumed = _parse_thread_block(lines, i)
            if thread is not None:
                threads.append(thread)
                i += consumed
                continue

        i += 1

    return threads, deadlocks, timestamp, jvm_banner


def _parse_thread_block(lines: List[str], start: int) -> Tuple[Optional[ThreadInfo], int]:
    """Parse a single thread starting at `lines[start]`. Returns (thread, lines_consumed)."""
    header_line = lines[start]
    m = THREAD_HEADER_RE.match(header_line)
    if not m:
        return None, 1

    state_from_hint, detail_from_hint = _parse_state(m.group("state_hint"))

    thread = ThreadInfo(
        name=m.group("name") or "<unnamed>",
        id=m.group("id"),
        daemon=bool(m.group("daemon")),
        priority=int(m.group("prio")) if m.group("prio") else None,
        cpu_ms=float(m.group("cpu")) if m.group("cpu") else None,
        elapsed_s=float(m.group("elapsed")) if m.group("elapsed") else None,
        tid=m.group("tid"),
        nid=m.group("nid"),
        state=state_from_hint,
        state_detail=detail_from_hint,
    )

    raw_lines = [header_line]
    i = start + 1
    n = len(lines)
    frame_index = 0
    in_los = False

    while i < n:
        line = lines[i]

        # Blank line ends the thread block (but only if we've seen something beyond header)
        if not line.strip():
            # Look-ahead: if next non-blank starts another thread or a deadlock section, end here
            j = i + 1
            while j < n and not lines[j].strip():
                j += 1
            if j >= n:
                break
            nxt = lines[j]
            if nxt.startswith('"') and THREAD_HEADER_RE.match(nxt):
                break
            if DEADLOCK_HEADER_RE.match(nxt) or "JNI global ref" in nxt:
                break
            # Otherwise treat the blank as part of the block; continue
            raw_lines.append(line)
            i += 1
            continue

        raw_lines.append(line)

        # State line
        sm = STATE_LINE_RE.match(line)
        if sm:
            thread.state, thread.state_detail = _refine_state(line)
            i += 1
            continue

        # Locked ownable synchronizers section
        if LOS_HEADER_RE.match(line):
            in_los = True
            i += 1
            continue

        if in_los:
            if LOS_NONE_RE.match(line):
                i += 1
                continue
            losm = LOS_ITEM_RE.match(line)
            if losm:
                addr = losm.group("addr")
                cls = (losm.group("cls") or "").strip()
                thread.locked_synchronizers.append(f"{addr} ({cls})" if cls else addr)
                i += 1
                continue
            # End of LOS section if line doesn't match
            in_los = False

        # Lock operation
        lm = LOCK_RE.match(line)
        if lm:
            thread.locks.append(LockOperation(
                op=lm.group("op"),
                address=lm.group("addr"),
                class_name=(lm.group("cls") or "unknown").strip(),
                frame_index=max(0, frame_index - 1),
            ))
            i += 1
            continue

        # Stack frame
        fm = FRAME_RE.match(line)
        if fm:
            file_name = fm.group("file")
            is_native = file_name == "Native Method"
            thread.stack.append(StackFrame(
                class_name=fm.group("fqcn"),
                method=fm.group("method"),
                file=None if is_native else file_name,
                line=int(fm.group("line")) if fm.group("line") else None,
                is_native=is_native,
            ))
            frame_index += 1
            i += 1
            continue

        # "No compile task" or other diagnostic lines we ignore but keep in raw
        i += 1

    thread.raw = "\n".join(raw_lines)
    return thread, i - start


def _parse_deadlock_block(buffer: List[str]) -> List[DeadlockCycle]:
    """Parse the textual deadlock section from jstack. Returns one or more cycles."""
    if not buffer:
        return []

    # Walk through buffer collecting "ThreadA -> ThreadB" edges
    edges: List[Tuple[str, str]] = []
    current_thread: Optional[str] = None
    for line in buffer:
        tm = DEADLOCK_THREAD_RE.match(line)
        if tm:
            current_thread = tm.group("name")
            continue
        if current_thread:
            hm = DEADLOCK_HELD_BY_RE.search(line)
            if hm:
                edges.append((current_thread, hm.group("holder")))
                current_thread = None  # next thread will reset

    if not edges:
        return []

    # Find cycles via simple traversal
    cycles: List[List[str]] = []
    visited_edges = set()
    for start_a, start_b in edges:
        if (start_a, start_b) in visited_edges:
            continue
        path = [start_a]
        cursor = start_b
        seen = {start_a}
        while True:
            path.append(cursor)
            if cursor in seen:
                # cycle found - trim to the cycle
                idx = path.index(cursor)
                cycle = path[idx:-1]  # drop the duplicate at the end
                cycles.append(cycle)
                for a, b in zip(cycle, cycle[1:] + [cycle[0]]):
                    visited_edges.add((a, b))
                break
            seen.add(cursor)
            next_edge = next(((a, b) for a, b in edges if a == cursor), None)
            if not next_edge:
                break
            visited_edges.add(next_edge)
            cursor = next_edge[1]

    if not cycles and edges:
        # Fallback: just report the edge list as one cycle
        names = []
        for a, b in edges:
            if a not in names:
                names.append(a)
            if b not in names:
                names.append(b)
        cycles = [names]

    return [
        DeadlockCycle(
            threads=c,
            description=" → ".join(c) + f" → {c[0]} (cycle)"
        )
        for c in cycles if c
    ]
