# Reference-to-source trace review

Reviewed the heap parser/index, root search, dominator report, source resolver,
source attachment endpoints, and the React investigation/report views.

## Confirmed defects corrected

- The dominator response already contained representative root paths for the top
  three entries, but the main report rendered only a short class chain. The report
  now exposes those paths with each object, field, reference strength, and source.
- The interactive root endpoint resolved declarations only. It now includes source
  method context and candidate methods referencing the retaining field, using the
  same enrichment as automatic reports.
- Java/JNI local roots carried thread and frame numbers without connecting those
  numbers to recorded stack traces. Enrichment now follows the thread-object
  root's stack-trace serial and marks the local root's actual frame index. Recorded
  frames resolve to source and method bodies where available.
- Attaching source after analysis refreshed histogram references but left saved
  object paths unenriched. Refresh now enriches stored paths and associated
  retention findings. Changing source removes stale path source locations.
- Source method lookup matched method names across the whole file, including
  sibling/nested classes. It now restricts lookup and field-method candidates to
  the declaring class. Line-only context requests can find the containing method.

## Limits that still explain incomplete traces

- Automatic indexing defaults to at most 512 MiB and one million objects. Quick
  analyses and skipped/failed indexing do not provide persistent object browsing.
  Raising `HEAP_INDEX_MAX_BYTES` and `HEAP_INDEX_MAX_OBJECTS` requires reanalysis;
  attaching source cannot reconstruct an index that was never built. Dominator
  analysis has separate byte/object limits. Benchmark higher limits before using
  them on production-size dumps.
- Root search returns at most five representative paths, with a global visited
  set, depth and node budgets. It does not enumerate every alternative retaining
  path. Automatic report paths cover the top three dominators; other objects can
  be queried through the object investigation panel.
- Field usage candidates are syntax/name matches. They are not a resolved call
  graph, and parameter shadowing or overloads can require manual verification.
  Java AST support requires a local JDK; lexical fallback provides less detail.
- Missing library source, duplicate class names, generated classes, and a source
  revision that differs from the captured build can prevent source resolution.
- A heap snapshot records retention, not the sequence of historical method calls
  that inserted an object into a collection. Recorded thread stacks are capture
  context, not allocation history. An allocation recording is needed for history.
- HTML export still summarizes heap findings rather than rendering the interactive
  trace component. Complete saved analysis JSON includes enriched stored paths.

## Using the corrected trace

Restart the backend and rebuild/reload the frontend. Attach the matching source
and select **Refresh source locations** for an existing indexed analysis. Expand
**Reference chain and source trace** in the dominator table. Use **Explore heap
objects and GC roots** for other objects. Expand field-method candidates or
recorded frame context to inspect code beyond the declaration snippet.

Validation covers static retention, local-root frame association, declaring-class
method selection, stale-source removal, late source attachment, frontend trace
rendering, and the existing real HotSpot heap integration test.
