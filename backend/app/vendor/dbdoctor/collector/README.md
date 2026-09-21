# collector/

Customer-run, single-file collection scripts (arriving in Phase 2):

- `pg_collect.py` — PostgreSQL adapter → Snapshot JSON
- `mysql_collect.py` — MySQL/MariaDB adapter → Snapshot JSON
- `delta.py` — two-snapshot diffing (growth, rates)

Contract (non-negotiable, see `docs/architecture.md` §5):

1. Single file, auditable in ~10 minutes; stdlib + one DB driver only.
2. No imports from the rest of this repository.
3. Read-only DB session; the code contains no write statements.
4. SQL literals are stripped **before** any byte leaves the customer machine.
5. Prints its own SHA256 when run so customers can verify what they execute.
