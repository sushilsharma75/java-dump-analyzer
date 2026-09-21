# DBDoctor integration review

Reviewed upstream revision `59160ccb1878c8c3f3d355ed64abda2335dc4aa9` from
https://github.com/sushilsharma75/dbdoctor, downloaded on 2026-09-21.
The original checkout is in `integrations/dbdoctor/` (ignored by this repository).
The maintained runtime copy lives in `backend/app/vendor/dbdoctor/`.

## Architecture decision

DBDoctor has a useful separation: customer-run collectors → normalized Snapshot →
pure deterministic rules → reports. Embed the rules and Python collectors in the
existing FastAPI service. Use the existing React application and saved-analysis
store for both JVM and database investigations. No separate DBDoctor server,
billing service, app database, DB driver or AI provider is required to analyze a
snapshot. PostgreSQL, MySQL and MariaDB share the same snapshot schema.

DBDoctor's hosted auth/payment/review-hold workflow and placeholder Next.js frontend
serve a different deployment model; they are not mounted in this trusted-host
application. Its JDBC collector remains available in the downloaded original
checkout; the integrated download endpoints distribute the Python collectors.
The rule engine has no network access or database writes. Suggested SQL/config
changes remain recommendations for the operator to validate and execute.

## Findings and implemented improvements

| Review finding | Implemented change | Regression evidence |
|---|---|---|
| An empty snapshot could receive a 100 health score without coverage context | Section coverage distinguishes missing, empty, available and unverified data. Score explicitly ranks observed findings, not database health | Missing-data and baseline coverage tests |
| PostgreSQL missing index scan counters were treated as zero | Unknown counters no longer trigger unused-index findings | Unknown scans test |
| Unique indexes with longer covering prefixes could become drop candidates | Unique and primary indexes are excluded from redundancy candidates on all engines | Constraint-index regression |
| Prefix parsing ignored predicates, expressions, access methods, included columns and sort options | Prefix comparisons accept only plain complete btree definitions; recommendations are medium-confidence candidates | Five semantic counterexamples plus original index tests |
| First-FROM parsing could associate statistics with the wrong schema or joined table | Single-table attribution resolves qualified names; ambiguous unqualified names, joins and subqueries do not bind | Schema ambiguity test |
| Query share denominator only contains captured top statements | Evidence renamed to `pct_of_captured_query_time`; title and recommendation state this scope | Query wording and original query tests |
| Mean latency was presented as latency on every execution | Findings now report a high average, with individual latency uncertainty | Query tests |
| Baselines could be diffed across hosts or engines, or diffed repeatedly | Require matching engine/alias/server version, ordered timezone-aware times, original cumulative inputs and unambiguous digests | Delta identity, timestamp and duplicate-digest tests |
| Numeric fields accepted invalid measurements | Reject negative measurements, nonfinite values, invalid ratios and nonfinite numeric settings; bound input record counts | Invalid-number/config tests |
| Connection peak could understate a larger current count | Evaluate the larger observed current/peak count and label the basis | Original operational tests |
| Linear growth rates were compounded into a 90-day forecast | Use a consistent linear extrapolation; remove the unsupported “triples” claim | Updated numerical regression |
| Missing autovacuum history was called “never” | Report “not recorded”, preserving uncertainty about stats resets | Maintenance tests |
| Python `assert` guarded read-only verification | Explicit exceptions retain the check under `python -O` | Collector compilation; live collection not exercised |
| No shared investigation workflow | Database upload, optional baseline, collector downloads, saved history, finding filters, evidence, complete JSON and escaped HTML exports | API roundtrip and React rendering/export tests |
| JDBC stacks and DB findings could be mistaken for causality | Correlation requires explicit operator confirmation and captures within five minutes; results are stack-pattern leads, with no claim of request/session linkage | Correlation gating tests |

## Operational boundaries

- This remains a single-user trusted-host tool; it is not a multi-tenant SaaS
  deployment. Run it on a trusted machine/network as described in the root README.
- Collection is offline from the workbench. Collector SQL normalization is based
  on common literal patterns, not a complete SQL parser or a guarantee that all
  sensitive text is removed (for example SQL comments). Review snapshots before
  sharing. Upload validation does not promise additional redaction.
- Host aliases and server version checks cannot prove uninterrupted statistics.
  Counter decreases are flagged; resets followed by larger counters, digest
  eviction, source alias changes and truncated top-N captures remain limitations.
- Section coverage is not per-column/catalog completeness. A supplied empty list
  does not prove that collection succeeded or that no issue exists.
- Index recommendations still require catalog, constraint and execution-plan
  validation over a representative observation period. No DDL is executed.
- JVM/database matching does not map a Java thread to an exact SQL statement or
  transaction. That requires shared tracing/request/session metadata absent from
  this snapshot contract. Existing JVM source links remain available in its report.
- Validation uses upstream synthetic snapshots and deterministic rule tests.
  No live PostgreSQL/MySQL/MariaDB server or JDBC collector was run for this change.

## Maintaining the embedded copy

Imports are namespaced under `app.vendor.dbdoctor`, with no global `sys.path`
mutation. The original checkout is not needed at runtime. Upstream attribution and
revision are in `backend/app/vendor/dbdoctor/UPSTREAM.md`. The original revision has
no standalone LICENSE file; no new license is assigned to its code here.
Ported upstream rule tests are in `backend/tests/dbdoctor_rules`; expectations
changed only for intentionally corrected evidence names, qualified MySQL table
names and linear growth math. New integration/regression tests are in
`backend/tests/test_database.py` and `frontend/tests/evidence.test.cjs`.

To update, compare a new upstream revision against the pinned original, port
changes into the embedded namespace, preserve the fixes listed above, update the
provenance file, then run backend tests and frontend tests/build. Do not replace
the embedded directory wholesale with an unreviewed checkout.
