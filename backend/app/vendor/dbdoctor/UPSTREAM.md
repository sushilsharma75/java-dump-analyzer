# DBDoctor provenance

Source: https://github.com/sushilsharma75/dbdoctor/tree/fix/auth-nav-and-reviewer-access
Branch: fix/auth-nav-and-reviewer-access
Revision: 476fa2dd87f4299066599f9c93d67d169902468e
Integrated: 2026-09-30

The runtime embeds the branch's SQL lexer/parser, schema catalog, DDL ingestion,
index rules, deterministic reports and task exports under this namespace.
The PostgreSQL/MySQL collectors include the branch's runtime observations and
retain this application's optional --include-procedures capture. The existing
numeric validation, baseline identity checks, evidence wording and legacy
procedure/type diagnostics are preserved. Earlier saved reports remain usable.
Combined-file ingestion resets MySQL DELIMITER state after each routine so
subsequent table/index definitions and additional routines are all analyzed.
HTML reports include the application's full evidence coverage and findings.
PDF output uses the browser's print/save-PDF workflow.

The integrated runtime uses the host application's navigation, uploads and
persistent analysis history. It contains no JWT middleware, login/register
routes, account model, token storage or role-based report gate. DBDoctor's
standalone authenticated Next.js/FastAPI service is not started or imported;
no fixed user or fabricated token is used to bypass authentication. All local
analysis and report endpoints are directly accessible like the JVM workbench.

The historical upstream checkout remains in integrations/dbdoctor (ignored).
Runtime code does not depend on that checkout. Imports are namespaced to avoid
collisions. Local diagnostic fixes are documented in
../../../../../docs/DBDOCTOR_REVIEW.md. No standalone license file was present
in the downloaded revision; existing attribution is preserved. This file does
not introduce a new license for upstream code.
