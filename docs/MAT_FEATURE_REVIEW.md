# Heap analysis review: Eclipse MAT and OpenJ9

Reviewed: 2026-09-26.

Update 2026-09-29: native dominators now use compact memory-mapped arrays and
Lengauer–Tarjan traversal; the default 512 MiB / one-million-object gates described
in the historical gap list below have been removed. Explicit operator budgets
remain. See [performance measurements](HEAP_PERFORMANCE.md).

## Recommendation

The user's primary objective is source-assisted diagnosis: identify the application code associated with observed retention and explain the next change to investigate. Native investigation features and source attribution should support that workflow.

The product goal is a standalone replacement for MAT. MAT is a feature and behavior reference, not a runtime dependency. Implement heap parsing, retention queries, source analysis and log correlation inside this application. OpenJ9 formats need native readers before the application can claim support for them.

This is a source and documentation review. No customer dump was supplied, MAT was not executed, and runtime or numerical parity has not been established. “Missing” below means no implementation was found in the reviewed backend and frontend. The inventory covers the documented feature families, including specialist features; it is not certification of every MAT query, plugin, or JVM version.

## Gaps found before implementation

1. **Most production heaps can exceed the deep-analysis defaults.** `heap_dump.py` limits automatic object indexing and dominator work separately to 512 MiB and 1,000,000 instances. The full histogram can finish while object exploration, retained sizes, and associated suspects are unavailable. The existing performance review records why these limits were introduced; raising them alone is not a demonstrated scaling solution.
2. **The complete histogram is stored but not exposed in the main tables.** The response includes `histogram`, but `top_classes_by_size` and `top_classes_by_count` contain only 30 entries each. `HeapAnalysis.jsx` renders those lists, initially ten at a time. “Show more” cannot reach classes outside those lists.
3. **The dominator section is a ranked summary.** The backend returns up to 25 children of the virtual root. The UI calls it a tree, but users cannot expand arbitrary immediate-dominator children. The SQLite `dom` table provides a foundation for that capability.
4. **Leak-suspect selection is narrow.** `compute_retained()` considers only the first three returned owners for findings and applies a threshold of at least 1 MiB and 20% of reachable modeled bytes. A distributed group of smaller owners can therefore be missed by this particular detector. Other heuristic findings still run.
5. **Useful information is difficult to read.** Object fields, collection metrics, heap threads, source context, and detailed coverage are partly rendered as JSON inside disclosure sections. This requires users to interpret the data themselves.
6. **Reference paths are deliberately bounded.** The indexed search returns up to five representative paths, with node/depth budgets. It does not provide a merged path tree for a selected object group.
7. **Sizes depend on assumptions.** The model uses fixed headers and alignment and does not model class-object shallow overhead. Its graph totals should not be presented as universally equal to MAT or live JVM sizes.

Code evidence:

- [Parser, limits, full histogram and top lists](../backend/app/analyzers/heap_dump.py)
- [Dominator findings](../backend/app/analyzers/heap_dominators.py)
- [Object index, paths and dominator storage](../backend/app/analyzers/heap_index.py)
- [Size model](../backend/app/analyzers/heap_sizing.py)
- [Heap report UI](../frontend/src/components/HeapAnalysis.jsx)
- [Object and thread investigation UI](../frontend/src/components/Investigation.jsx)
- [Existing performance investigation](HEAP_PERFORMANCE.md)

The existing `deep=true` option lifts size ceilings for the streaming retention tracer and duplicate-array scan. It does **not** remove the object-index and dominator limits.

## Feature inventory and gaps

### Core investigation

MAT supports histogram drill-down, grouped dominators, retained-set calculations, and root-path navigation. Its histogram retained size for a selected class/set requires a calculation; adding individual retained sizes can double-count shared objects. See the [MAT basic tutorial](https://help.eclipse.org/latest/topic/org.eclipse.mat.ui.help/gettingstarted/basictutorial.html).

| Capability | Current tool | Recommended work |
| --- | --- | --- |
| Class histogram | Full backend histogram; capped UI lists | Search and sort all classes; group by package and defining loader; paginate results |
| Shallow size | Modeled values | Display model and byte units; validate against matched JVM configurations |
| Retained size | Computed for indexed graph within limits | Expose per-object values and selected-set calculations with explicit semantics |
| Dominator tree | Stored parent relations; top-owner summary | Expand children lazily; navigate to parent; group by class/package/loader |
| Retained sets | Internal graph foundation | Add object list and histogram for a selected owner's retained set |
| Incoming/outgoing references | Paginated backend and basic UI | Typed columns, independent paging, filters and navigation history |
| GC roots and paths | Representative field-labelled paths | Add root browser, selected-group merged paths and separate reference exclusions |
| Unreachable objects | Aggregate count/bytes | Add histogram and explicit reachable/all-object scope |

MAT normally removes unreachable objects from its indexed snapshot and keeps a separate histogram. This is a potential explanation for count differences when comparing our full-dump histogram with MAT. Normalize the scope before judging correctness. See [unreachable objects](https://help.eclipse.org/latest/topic/org.eclipse.mat.ui.help/reference/inspections/unreachable_objects.html).

### Diagnosis and memory reduction

MAT's leak report considers both individual owners and groups of objects, finds accumulation points, and links to retained-object details and thread context. Its documented default suspect threshold is 10%. Our proposed detector should make thresholds configurable and preserve evidence for each candidate. See [Leak Suspects](https://help.eclipse.org/latest/topic/org.eclipse.mat.ui.help/tasks/runningleaksuspectreport.html).

| Capability | Current tool | Recommended work |
| --- | --- | --- |
| Automatic leak suspects | Threshold-based owners plus heuristics | Group suspects by class/loader; explain accumulation and application owner |
| Component report | Deployment attribution exists | Package/loader-scoped retained sets, consumers and waste report |
| Duplicate strings | Duplicate primitive-array content detection | Decode supported String layouts and link duplicates to retaining owners |
| Collection size/fill | Basic observations for recognized fields | JVM-version-aware collection adapters and aggregate distributions |
| Map contents/collisions | Occupancy and collision lower bound | Key/value inspection; semantic traversal of supported maps |
| Empty/sparse arrays and collections | Some metrics available | Dedicated queries, owner links and conservative potential savings |
| Constant primitive arrays | No dedicated query found | Add grouped query by type, length and constant value |
| Soft/weak reference leaks | Coarse referent exclusion | Detect strong alternative paths; separate reference statistics |
| Finalizers | Histogram explanations | Queue, processing thread, locals and retained-object inspection |
| Classloader analysis | Deployment and duplicate-class results | Full loader explorer with instance/retained-set drill-down |
| Heap threads and locals | Recorded HPROF stacks and roots | Thread/frame/local tree and retained-set details |
| ThreadLocal retention | Count-based hints and generic paths | Inspect thread → entry → key/value, including stale-key cases |

MAT's [component report](https://help.eclipse.org/latest/topic/org.eclipse.mat.ui.help/reference/inspections/component_report.html) combines retained consumers, duplicate strings, collection/array utilization, reference statistics, finalizers and collisions. Its collection queries cover many concrete layouts; see [collection analysis](https://help.eclipse.org/latest/topic/org.eclipse.mat.ui.help/tasks/analyzingjavacollectionusage.html). Reference leaks require checking strong alternative ownership, as described in [Reference Leak](https://help.eclipse.org/latest/topic/org.eclipse.mat.ui.help/reference/inspections/reference_leak.html).

Classloader and thread expectations are documented in [Class Loader Explorer](https://help.eclipse.org/latest/topic/org.eclipse.mat.ui.help/tasks/analyzingclassloader.html) and [thread analysis](https://help.eclipse.org/latest/topic/org.eclipse.mat.ui.help/tasks/analyzingthreads.html). ThreadLocal inspection above is our recommendation, not a claim that every MAT release has a dedicated stale-ThreadLocal detector.

### Expert workflows and platform features

| Capability | Current tool | Recommended work |
| --- | --- | --- |
| OQL | No engine/editor found | Implement a bounded native query language; document supported syntax |
| Query browser/history | No general query catalog | Searchable tasks with arguments, help and saved results |
| Snapshot comparison | Histogram deltas with provenance checks | Add component/dominator growth and comparative suspects |
| Reports and exports | HTML and complete JSON | CSV/text for selected tables; evidence links and per-query export |
| Batch analysis | HTTP jobs | Repeatable native jobs with versioned configuration |
| Notes/bookmarks | Capture metadata and saved history | Snapshot notes, pinned objects and saved investigation paths |
| Object display resolvers | Raw fields and selective decoding | Readable Strings, numbers and supported collection contents |
| Compressed HPROF | No gzip heap parser found | Detect gzip and expand with an explicit byte budget |
| OpenJ9 PHD/system dump | No parser/integration found | Native PHD reader and a separate system-dump reader |
| Live heap acquisition | Capture guidance/import workflows | Consider later; separate acquisition from analysis |
| Heap export/redaction | Analysis export only | Separate future scope with format and privacy validation |
| Specialist extensions | Application attribution only | Defer OSGi, JRuby and server-specific query compatibility until demanded |

Sources: [OQL](https://help.eclipse.org/latest/topic/org.eclipse.mat.ui.help/reference/oqlsyntax.html), [query selection](https://help.eclipse.org/latest/topic/org.eclipse.mat.ui.help/reference/selectingqueries.html), [batch operation](https://help.eclipse.org/latest/topic/org.eclipse.mat.ui.help/tasks/batch.html), [workbench and notes](https://help.eclipse.org/latest/topic/org.eclipse.mat.ui.help/reference/workbench.html), [feature index](https://help.eclipse.org/latest/topic/org.eclipse.mat.ui.help/welcome.html), and [extension packages](https://help.eclipse.org/latest/topic/org.eclipse.mat.ui.help/doc/index.html).

## Release review: what to learn from MAT

The official site lists 1.17.0, released June 10, 2026, as the current release at review time. See [MAT news](https://eclipse.dev/mat/).

| Release | Verified changes relevant here | Suggested application |
| --- | --- | --- |
| [1.10](https://eclipse.dev/mat/1.10.0/noteworthy.html) | Parallel HPROF parsing, gzip input, OQL and group-suspect improvements | Benchmark parsing stages; support compressed input and groups |
| [1.11](https://eclipse.dev/mat/1.11.0/noteworthy.html) | Tree/table comparison, suspects across snapshots, optional object discard for huge dumps, UI refinements | Add comparison workspace; label any discarded-object analysis explicitly |
| [1.12](https://eclipse.dev/mat/1.12.0/noteworthy.html) | OpenJDK 15+ compressed HPROF, better gzip performance, inspection of some discarded objects, richer accessible reports | Improve format coverage and keyboard/screen-reader access |
| [1.13](https://eclipse.dev/mat/1.13.0/noteworthy.html) | Inspector sorting by type/name/value and incremental expansion | Sortable field tables with controlled expansion |
| [1.14](https://eclipse.dev/mat/1.14.0/noteworthy.html) | Configurable table/tree expansion size; analyzer diagnostics collection | User-selected page sizes; downloadable analysis diagnostics |
| [1.15](https://eclipse.dev/mat/1.15.0/noteworthy.html) | More suspect paths/local-variable context, optional stack-frame pseudo-objects, BigInteger/BigDecimal display, snapshot descriptions and workspace-encoding exports | Prioritize richer suspect evidence, readable values, notes and Unicode exports |
| [1.16](https://eclipse.dev/mat/1.16.0/noteworthy.html) | Parsing/indexing parallelism, concurrent read I/O, DTFJ truncated-core checks and implementation choice, OQL shortcut fix, single-click mode | Improve stage throughput and input reliability; consistent selection and shortcuts |
| [1.17](https://eclipse.dev/mat/1.17.0/noteworthy.html) | Standalone Java 21 minimum; OQL escaping, zero-length-array component-report and selection fixes; ICU dependency removal | Pin and validate worker runtime/version; cover those regressions |

The linked 1.16 release is mainly a performance/reliability release. For the requested richer UI explanations, 1.13–1.15 provide more directly useful examples.

## OpenJ9 and DTFJ

OpenJ9 normally produces binary PHD heap dumps; it also documents a classic text format. PHD is a different format from HPROF. OpenJ9 recommends MAT with the DTFJ plugin for PHD analysis. See [OpenJ9 heap dumps](https://eclipse.dev/openj9/docs/dump_heapdump/).

DTFJ is a Java diagnostic API with format-specific implementations. Available data depends on the input; missing information may yield null or `DataUnavailable`. System dumps expose more information than Java dumps, including heap objects and native memory/thread data. See [OpenJ9 DTFJ](https://eclipse.dev/openj9/docs/interface_dtfj/).

| Input | Proposed treatment |
| --- | --- |
| HotSpot HPROF | Native parser, index and investigation queries |
| Gzip HPROF | Content detection with bounded decompression, then native analysis |
| OpenJ9 PHD | Recognize format; native parser remains to be implemented |
| PHD + matching javacore | Future native pairing and enrichment; preserve missing-data limits |
| OpenJ9 system/core dump | Separate future native reader; do not treat as HPROF |
| Javacore alone | Future OpenJ9 thread/VM input; not a complete heap graph |
| Classic OpenJ9 text heap | Recognize format; advertise support after a native reader is verified |

PHD lacks field names and primitive field/array contents and has less accurate GC-root information than system dumps. A matching javacore supplies additional thread details but does not restore absent object contents. See the [dump-format comparison](https://help.eclipse.org/latest/topic/org.eclipse.mat.ui.help/tasks/acquiringheapdump.html).

### Native architecture

1. Detect format from bytes and preserve original metadata and capture identity.
2. Use the application's HPROF reader for raw and gzip HPROF.
3. Serve paginated histogram, object, dominator, retained-set, root and waste queries from the persistent index.
4. Resolve recorded retaining fields and stack frames to matching application source; expose candidate writes and cleanup calls.
5. Join heap, thread, GC and server-log evidence through the existing incident analysis.
6. Build future OpenJ9 readers behind a common capability contract. Missing contents or root information remain unavailable.
7. Benchmark native parsing and graph work on representative files before raising default limits.

No MAT installation, MAT subprocess, DTFJ plugin, or external analysis service is required. The earlier optional MAT integration proposal was withdrawn at the user's direction. A local JDK is used only for Java source syntax parsing, without running application code.

## Proposed UI behavior

This is a functional UI proposal, not an implemented or rendered design.

Use a persistent snapshot header with filename, format, JVM, capture time, engine, heap bytes, object count and stage coverage. Show “Unavailable: indexing skipped due to configured limit” where the user expects a result, with the recorded reason.

Provide these workspaces:

- **Overview:** top owners, findings, comparison summary and coverage.
- **Leak suspects:** one evidence panel per suspect, including owner, retained bytes/percentage, accumulated classes, root path, source location when resolvable, and next verification step.
- **Histogram:** all classes, search, sorting, package/loader grouping, instances and shallow bytes; retained-set size on demand.
- **Dominators:** expandable tree with shallow/retained columns and retained-set drill-down.
- **Objects:** selected object, typed fields, readable values, incoming/outgoing references, root paths and navigation history.
- **Threads & loaders:** navigable thread/frame/local and loader/class relationships.
- **Memory waste:** duplicates, collection/array utilization and reference/finalizer queries, enabled according to capabilities.
- **Compare:** baseline/current capture metadata, class/component growth and supporting queries.
- **Queries:** query catalog first, OQL when a compatible engine is available.

Selecting a histogram row should offer **List instances → Inspect object → Show dominators / Paths to roots / Retained set** without requiring users to retype a class name. Keep an inspector beside the active result, allow it to be pinned, and preserve selection when moving between tabs. MAT's [workbench](https://help.eclipse.org/latest/topic/org.eclipse.mat.ui.help/reference/workbench.html) and [interaction tips](https://help.eclipse.org/latest/topic/org.eclipse.mat.ui.help/reference/tipsandtricks.html) are useful references.

Example suspect presentation, with deliberately illustrative values:

> `OrderCache.entries` retains 820 MiB (41% of reachable modeled heap). The retained set is dominated by order records and their byte arrays. A static field keeps the cache reachable. Inspect its eviction policy and compare a later capture under comparable load.

The detail panel should show the actual supporting object IDs, edge labels and captured source declaration. A source reference or retaining field does not establish an allocation site or prove unbounded growth.

## Source-assisted diagnosis: the main product improvement

The current implementation already resolves field-labelled heap edges to source declarations and recorded stack frames to source lines in `heap_trace.py`. It includes surrounding source context and build-verification metadata. However, histogram source references are attached only for the top eight entries of each ranking, and static-field findings identify declarations rather than proving which mutation introduced a retained object.

There is also a concrete diagnostic wording problem in `_build_static_field_findings()`: some messages say static fields are always GC roots and their objects can never be collected for the process lifetime. That is too strong. Reassigning or clearing a field can release its referent; class unloading and other reference paths also matter. The docstring incorrectly says heap dumps have no stack traces, despite this repository supporting recorded HPROF thread stacks. Correct these messages and ground static-collection findings in actual ownership evidence.

### What “exact code” should mean

| Result | Evidence required | Presentation |
| --- | --- | --- |
| Retaining field declaration | Recorded heap edge, resolved declaring class/field and matching source | “This field references the retained object”; file and line |
| Recorded frame | Captured stack frame and matching source line | “This frame was recorded at capture”; distinguish a local root from unrelated execution |
| Candidate insertion/removal code | Resolved symbol usages and available control/data flow | “Candidate mutation site”; show why it is relevant and unresolved aliases/calls |
| Allocation site | Allocation recording/profiling evidence with known coverage | Report captured allocation context; sampled data does not establish every object's origin |
| Confirmed faulty lifecycle | Ownership evidence plus lifecycle expectations, code review and suitable runtime comparison | Explain the missing eviction/cleanup condition and evidence supporting it |

A heap snapshot and source can often locate the retaining declaration precisely. They do not ordinarily reconstruct the exact historical `put()`, `add()` or `new` call for each object. MAT's [leak report documentation](https://help.eclipse.org/latest/topic/org.eclipse.mat.ui.help/tasks/runningleaksuspectreport.html) explicitly distinguishes snapshot analysis from allocation timing information.

### Recommended source investigation pipeline

1. Verify source fingerprint/build identity and account for duplicate class names across classloaders. Show unresolved identity rather than picking the first matching file.
2. Start from a measured retained owner or suspect group, then find the nearest relevant application field on its root path.
3. Resolve that field symbol and display the declaration with the actual heap edge and object identity.
4. Find assignments and supported mutation/cleanup operations on the same field: inserts, removals, clears, eviction configuration, listener registration/unregistration and ThreadLocal set/remove.
5. Show enclosing methods and bounded caller context. Track known aliases and explicitly report unsupported dispatch, reflection, generated code and external-library behavior. AST parsing alone is insufficient for whole-program proof.
6. Rank candidate explanations using retention size, observed contents, source evidence and compatible snapshot growth. Absence of a locally visible `remove()` is a lead, not proof that no cleanup occurs.
7. Produce a code-focused finding with separate sections for **Observed retention**, **Source declaration**, **Candidate writes**, **Cleanup paths**, **Suggested change**, and **How to verify**.

Illustrative investigation:

> Observed: `OrderCache.entries` is on a strong path to the suspect objects. Declaration: `OrderCache.java:42`. Candidate writer: `saveOrder()` calls `entries.put(...)`. Cleanup: no cleanup was resolved in the inspected scope; external mutation remains possible. Next step: verify the intended cache lifetime and eviction path, then compare captures after the relevant lifecycle event.

File names and line numbers in this example are fictional. Actual findings must use evidence from the uploaded build. The first implementation increment should join existing retention paths to readable source context, then add symbol-aware mutation and cleanup analysis with explicit coverage.

## Delivery order and acceptance criteria

### First: make existing results accessible

- Expose the full histogram with search, sorting and paging. A class outside the current top 30 must be discoverable.
- Replace raw object/thread JSON with structured tables and trees.
- Add dominator-child and retained-set endpoints over the existing index. Label the existing summary accurately until these exist.
- Keep skipped stages visible at the point of use. Deep mode must explain which limits it changes.
- Put retaining declarations and recorded frames directly in suspect details, and correct the static-field overclaims described above.

### Next: improve evidence and engine coverage

- Add configurable individual and group-suspect queries, retained-class breakdowns and merged paths.
- Implement native OpenJ9 readers after the HPROF investigation workflow is stable.
- Validate each implemented format separately; currently only HPROF and gzip HPROF are supported.
- Add collection/value adapters with explicit unsupported-layout results.

### Then: expert investigations and scaling

- Add component comparisons, native query syntax, query history, export and snapshot notes.
- Benchmark parser, indexing, dominators and each query separately, recording elapsed time, peak RAM, disk use and cancellation behavior.
- Establish supported dump sizes from real object/edge counts and hardware measurements.

### Validation before claiming MAT equivalence

Use the same captured files in both engines and record MAT version, JVM version/flags, reference exclusions, unreachable-object policy and parser options. Compare class identity by defining loader as well as name. Normalize byte units and selected-set semantics.

Include controlled cases for static caches, groups of small owners, shared references, cycles, thread locals, weak/soft references, duplicate strings, empty collections, classloader retention and unreachable objects. Include compressed input and incomplete dumps. Existing native synthetic tests are useful but do not establish MAT equivalence.

For OpenJ9, include PHD alone, PHD with matching javacore, full system dump, missing companions, and truncated core input. Missing capabilities must remain unavailable rather than becoming zero-valued results. Never require object-address equality across separate captures.

Success means users can trace **memory consumer → retained objects → owner → GC root → relevant source/context**, with visible evidence and data limitations, and can repeat that investigation on another capture.


## Implementation status (2026-09-26)

Implemented in this change:

- Full histogram search, sort, package grouping, paging and CSV export.
- Native dominator-child navigation and grouping by class or loader.
- Selected-object retained sets, including shared objects retained by a group.
- Configurable individual/group suspect queries and representative merged root paths.
- GC-root, unreachable-object and classloader result tables.
- Readable object fields, separate incoming/outgoing paging and object navigation.
- Java AST candidate field writes and cleanup calls, linked from retention evidence.
- Duplicate-array/String queries, empty/sparse/constant array queries, collection utilization, reference counts and ThreadLocal-entry inspection for supported layouts.
- ArrayList and HashMap/LinkedHashMap entry adapters; bounded String and big-number display resolvers.
- Snapshot notes, bookmarks, query navigation history and diagnostics.
- Gzip HPROF expansion with byte limits and explicit unsupported-format messages.
- Corrected static-field claims; preserved existing automatic incident/log correlation.

Still requires further implementation or validation:

- Native PHD, javacore and system-dump readers.
- General OQL compatibility, whole-program alias/call analysis and allocation-history attribution.
- Full reference-processing/finalizer simulation and adapters for every collection/JVM layout.
- Complete native component/dominator comparison across captures.
- Production-scale throughput and byte-for-byte MAT equivalence across JVM configurations.

This status does not certify full MAT feature parity. Existing saved indexes must be regenerated for new dominator completion markers and constant-array metadata. Histogram access remains available without reindexing when the saved analysis contains the full histogram.

Validation: the backend regression suite, 18 frontend tests and the production build pass. An isolated synthetic heap was checked in Chrome for full-histogram class drilldown, object inspection, dominator-child navigation and persisted notes. No page errors were observed; the checked mobile view had no page-level horizontal overflow. These checks do not replace production-scale or OpenJ9 validation.
