"""Pydantic schemas for API requests/responses."""
from __future__ import annotations
from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field
from enum import Enum


class ThreadState(str, Enum):
    NEW = "NEW"
    RUNNABLE = "RUNNABLE"
    BLOCKED = "BLOCKED"
    WAITING = "WAITING"
    TIMED_WAITING = "TIMED_WAITING"
    TERMINATED = "TERMINATED"
    UNKNOWN = "UNKNOWN"


class Severity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class StackFrame(BaseModel):
    class_name: str
    method: str
    file: Optional[str] = None
    line: Optional[int] = None
    is_native: bool = False

    @property
    def signature(self) -> str:
        return f"{self.class_name}.{self.method}"


class LockOperation(BaseModel):
    op: str  # "locked", "waiting to lock", "waiting on", "parking to wait for"
    address: str
    class_name: str
    frame_index: int  # which stack frame this happened at


class ThreadInfo(BaseModel):
    name: str
    id: Optional[str] = None
    nid: Optional[str] = None  # native id (hex)
    tid: Optional[str] = None  # thread id (hex)
    daemon: bool = False
    priority: Optional[int] = None
    state: ThreadState = ThreadState.UNKNOWN
    state_detail: Optional[str] = None  # e.g., "on object monitor", "parking"
    cpu_ms: Optional[float] = None
    elapsed_s: Optional[float] = None
    stack: List[StackFrame] = Field(default_factory=list)
    locks: List[LockOperation] = Field(default_factory=list)
    locked_synchronizers: List[str] = Field(default_factory=list)
    raw: str = ""  # original text for display

    @property
    def held_locks(self) -> List[LockOperation]:
        return [l for l in self.locks if l.op == "locked"]

    @property
    def wanted_lock(self) -> Optional[LockOperation]:
        for l in self.locks:
            if l.op in ("waiting to lock", "waiting on", "parking to wait for"):
                return l
        return None


class DeadlockCycle(BaseModel):
    threads: List[str]  # ordered list of thread names in the cycle
    description: str


class StackGroup(BaseModel):
    """A group of threads sharing the same top-N stack frames."""
    signature: str
    top_frames: List[str]
    thread_names: List[str]
    count: int
    states: Dict[str, int]  # state -> count


class SourceSnippet(BaseModel):
    start_line: int
    highlight_line: int
    lines: List[str]


class SourceLocation(BaseModel):
    """A pointer into source code, optionally resolved to a file path within an uploaded repo."""
    class_name: str
    method: str
    file: Optional[str] = None
    line: Optional[int] = None
    is_user_code: bool = False
    # Set when a source repo is attached
    repo_path: Optional[str] = None   # file path relative to repo root
    snippet: Optional[SourceSnippet] = None


class Finding(BaseModel):
    """A single diagnostic observation."""
    severity: Severity
    title: str
    description: str
    affected_threads: List[str] = Field(default_factory=list)
    remediation: Optional[str] = None
    category: str = "general"  # deadlock, contention, exhaustion, gc, etc.
    source_locations: List[SourceLocation] = Field(default_factory=list)
    # Insight fields — plain-English structure for non-experts
    impact: Optional[str] = None        # what the user is experiencing because of this
    likely_cause: Optional[str] = None  # most probable root cause
    evidence: List[str] = Field(default_factory=list)  # concrete observations backing the finding


class PoolInfo(BaseModel):
    """A logical thread pool inferred from thread-name prefixes."""
    name: str                       # e.g. "http-nio-8080-exec"
    total: int
    states: Dict[str, int]          # state -> count within this pool
    dominant_state: str
    busy_pct: float                 # share of pool NOT idle (RUNNABLE/BLOCKED)
    blocked_pct: float              # share of pool BLOCKED
    health: str                     # "ok" | "busy" | "saturated"
    note: Optional[str] = None      # human-readable interpretation


class HotThread(BaseModel):
    """A thread consuming notable CPU relative to its lifetime."""
    name: str
    cpu_ms: float
    elapsed_s: float
    cpu_pct: float                  # cpu_ms / (elapsed_s*1000) * 100
    state: str
    top_frame: Optional[str] = None
    is_gc: bool = False


class ThreadDumpAnalysis(BaseModel):
    timestamp: Optional[str] = None
    jvm: Optional[str] = None
    total_threads: int
    state_breakdown: Dict[str, int]
    daemon_count: int
    deadlocks: List[DeadlockCycle] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    stack_groups: List[StackGroup] = Field(default_factory=list)
    blocked_chains: List[Dict[str, Any]] = Field(default_factory=list)
    threads: List[ThreadInfo] = Field(default_factory=list)
    summary: str = ""
    # Insight additions
    verdict: str = "healthy"        # "healthy" | "degraded" | "critical"
    pools: List[PoolInfo] = Field(default_factory=list)
    hot_threads: List[HotThread] = Field(default_factory=list)


# --- Heap dump schemas ---

class ClassReference(BaseModel):
    """A place in application source that names a histogram-topping class."""
    repo_path: str
    line: int
    method: Optional[str] = None
    kind: str = "type-use"   # new | field | type-use | import
    snippet: Optional[SourceSnippet] = None


class ClassHistogramEntry(BaseModel):
    class_name: str
    instance_count: int
    shallow_size_bytes: int
    pct_of_total_size: Optional[float] = None   # share of all measured shallow bytes
    explanation: Optional[str] = None           # what this class usually means when it tops a histogram
    references: List[ClassReference] = Field(default_factory=list)  # where app code uses this class


class HeapThread(BaseModel):
    """A java.lang.Thread found in the heap, attributed to the code that owns it.

    Unlike a jstack thread this has no stack trace — but it does carry something a
    thread dump cannot: which classloader (i.e. which deployed artifact) the thread
    belongs to, and whether it is still a live GC root.
    """
    name: Optional[str] = None
    class_name: str                         # the Thread subclass, e.g. com.acme.ReportThread
    live: bool = False                      # backed by a ROOT_THREAD_OBJ record
    daemon: Optional[bool] = None
    priority: Optional[int] = None
    deployment_id: Optional[str] = None     # Deployment.id this thread is attributed to
    attribution: str = "unknown"            # own-class | context-classloader | target | unattributed
    target_class: Optional[str] = None      # the Runnable it wraps, when it wraps one
    is_user_code: bool = False              # thread class or target is application code


class Deployment(BaseModel):
    """One classloader — in a servlet container, one deployed WAR/EAR."""
    id: str                                 # loader object id, hex (stable within a dump)
    loader_class: str                       # e.g. org.apache.catalina.loader.ParallelWebappClassLoader
    name: Optional[str] = None              # best label: war basename or context name
    code_source: Optional[str] = None       # file:/…/myapp.war!/WEB-INF/classes/
    artifact: Optional[str] = None          # myapp.war
    is_webapp: bool = False                 # loader looks container-managed (WAR/EAR), not system
    class_count: int = 0
    instance_count: int = 0
    shallow_size_bytes: int = 0
    packages: List[str] = Field(default_factory=list)   # top package prefixes it loaded
    thread_count: int = 0
    live_thread_count: int = 0
    stale: bool = False                     # another loader serves the same artifact


class ThreadOwnership(BaseModel):
    """Roll-up of who created the threads in this heap."""
    total_threads: int = 0
    live_threads: int = 0
    jvm_internal: int = 0                   # compiler/GC/finalizer — not yours
    application: int = 0                    # attributable to a deployment or user code
    by_deployment: Dict[str, int] = Field(default_factory=dict)   # deployment id -> live threads
    threads: List[HeapThread] = Field(default_factory=list)


class DominatorEntry(BaseModel):
    """One top-level entry of the dominator tree: an object no other single object
    retains. Collecting it would free exactly `retained_bytes` — the number MAT's
    'Biggest Objects' pie is made of."""
    class_name: str
    object_id: str                          # hex object id within this dump
    shallow_bytes: int
    retained_bytes: int
    pct_of_reachable: float                 # share of all reachable heap bytes
    chain: List[str] = Field(default_factory=list)  # accumulation path downward (class names)


class DuplicateClass(BaseModel):
    """The same class name loaded by more than one classloader — MAT's
    'Duplicate Classes' signal, the fingerprint of a redeploy/classloader leak."""
    class_name: str
    loader_count: int
    loaders: List[str] = Field(default_factory=list)


class SkippedAnalysis(BaseModel):
    """A stage that did not run on this dump, and why.

    Every heavyweight stage (dominator tree, retention tracing, duplicate-array
    scan) is gated by dump size or stream seekability. Without this list a
    partially-analysed 25GB dump is indistinguishable from a fully-analysed one —
    so the result always states which stages were skipped and how to enable them.
    """
    stage: str            # e.g. "dominator tree (exact retained sizes)"
    reason: str           # human-readable: what tripped the gate
    enable_hint: Optional[str] = None   # env var / capture change that would run it


class HeapDumpAnalysis(BaseModel):
    header: str
    identifier_size: int
    timestamp_ms: Optional[int] = None
    file_size_bytes: int
    # Bytes actually read. Below file_size_bytes in quick mode, where every count,
    # size and percentage below describes only the sampled prefix.
    analyzed_bytes: int = 0
    truncated: bool = False
    # Object layout used for shallow sizes — hprof records neither headers nor
    # reference width, so the model is inferred (see heap_sizing).
    sizing_model: str = ""
    skipped_analyses: List[SkippedAnalysis] = Field(default_factory=list)
    total_records: int
    record_type_counts: Dict[str, int]
    total_classes_loaded: int
    total_strings: int          # java.lang.String *instances* on the heap
    total_utf8_records: int = 0  # hprof symbol table (class/field names) — not heap data
    total_instances: Optional[int] = None
    top_classes_by_count: List[ClassHistogramEntry] = Field(default_factory=list)
    top_classes_by_size: List[ClassHistogramEntry] = Field(default_factory=list)
    suspicious_classes: List[str] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    wasted_bytes_estimate: Optional[int] = None   # reclaimable duplicate-array bytes
    deployments: List[Deployment] = Field(default_factory=list)
    thread_ownership: Optional[ThreadOwnership] = None
    # Dominator-tree results (exact retained sizes; gated by dump size)
    dominators: List[DominatorEntry] = Field(default_factory=list)
    reachable_bytes: Optional[int] = None
    unreachable_instances: Optional[int] = None   # objects in the dump no GC root reaches
    unreachable_bytes: Optional[int] = None
    duplicate_classes: List[DuplicateClass] = Field(default_factory=list)
    summary: str = ""
    verdict: str = "healthy"


# --- GC log schemas ---

class GCEvent(BaseModel):
    """One garbage-collection event extracted from a GC log line."""
    seq: int
    timestamp_s: float        # seconds from the start of the log (uptime or normalized)
    gc_id: int
    phase: str                # young | mixed | full | concurrent | stall | other
    cause: str = ""
    before_mb: float = 0.0    # heap used before the collection
    after_mb: float = 0.0     # heap used after the collection (the leak-trend series)
    total_mb: float = 0.0     # heap capacity at the time
    pause_ms: float = 0.0


class GCLogAnalysis(BaseModel):
    collector: str                       # G1 | Parallel | CMS | Serial | ZGC | Shenandoah | Unknown
    jdk_logging: str                     # "unified" | "legacy"
    duration_s: float
    total_pause_ms: float
    gc_count: int
    full_gc_count: int
    throughput_pct: float                # share of wall-clock spent in application (not GC)
    pause_p50_ms: float
    pause_p95_ms: float
    pause_p99_ms: float
    pause_max_ms: float
    alloc_rate_mb_s: float
    heap_after_trend_mb_per_min: float   # slope of post-GC occupancy — the leak signal
    events: List[GCEvent] = Field(default_factory=list)   # downsampled for charting
    findings: List[Finding] = Field(default_factory=list)
    summary: str = ""
    verdict: str = "healthy"             # healthy | degraded | critical


class CorrelationRequest(BaseModel):
    """Cross-reference a heap dump analysis with a thread dump analysis."""
    heap: Dict[str, Any]    # serialized HeapDumpAnalysis
    thread: Dict[str, Any]  # serialized ThreadDumpAnalysis
    gc: Optional[Dict[str, Any]] = None   # serialized GCLogAnalysis (optional third pillar)
    source_session: Optional[str] = None


class CorrelationResponse(BaseModel):
    findings: List[Finding] = Field(default_factory=list)
    summary: str = ""
    matched_classes: int = 0


# --- Comparison / delta schemas ---

class ClassDelta(BaseModel):
    class_name: str
    count_before: int
    count_after: int
    count_delta: int
    bytes_before: int
    bytes_after: int
    bytes_delta: int
    is_new: bool = False


class HeapComparison(BaseModel):
    total_bytes_before: int
    total_bytes_after: int
    bytes_growth: int
    growers: List[ClassDelta] = Field(default_factory=list)
    new_classes: List[ClassDelta] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    summary: str = ""
    verdict: str = "healthy"


class StuckThread(BaseModel):
    name: str
    state: str
    top_frame: str
    blocked: bool = False


class ThreadComparison(BaseModel):
    stuck_threads: List[StuckThread] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    summary: str = ""
    verdict: str = "healthy"


class HeapCompareRequest(BaseModel):
    before: Dict[str, Any]   # serialized HeapDumpAnalysis (the baseline)
    after: Dict[str, Any]    # serialized HeapDumpAnalysis (the later capture)
    source_session: Optional[str] = None


class ThreadCompareRequest(BaseModel):
    before: Dict[str, Any]   # serialized ThreadDumpAnalysis
    after: Dict[str, Any]


class LLMSummaryRequest(BaseModel):
    analysis: Dict[str, Any]  # serialized ThreadDumpAnalysis or HeapDumpAnalysis
    kind: str  # "thread" | "heap" | "gc" | "unified"
    api_key: Optional[str] = None  # user-supplied; optional
    # Override the backend default (ANTHROPIC_MODEL, else claude-opus-5) — useful
    # when the caller's organisation doesn't have access to the default model.
    model: Optional[str] = None


class LLMSummaryResponse(BaseModel):
    summary: str
    enabled: bool
    error: Optional[str] = None


class JobStatus(BaseModel):
    job_id: str
    status: str  # "queued" | "running" | "done" | "error"
    bytes_processed: int = 0
    bytes_total: int = 0
    records_seen: int = 0
    instances_seen: int = 0
    started_at: float = 0.0  # epoch seconds
    elapsed_seconds: float = 0.0
    eta_seconds: Optional[float] = None
    error: Optional[str] = None
    # Populated when status == "done"
    result: Optional[Dict[str, Any]] = None


class SourceUploadResponse(BaseModel):
    session_id: str
    files_indexed: int
    classes_indexed: int
    root_dir: str
    languages: Dict[str, int]  # extension -> count


class SourceLookupResponse(BaseModel):
    found: bool
    file_path: Optional[str] = None
    snippet: Optional[SourceSnippet] = None
