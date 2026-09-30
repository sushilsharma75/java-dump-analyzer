"""Conservative SQL AST helpers. Unsupported or ambiguous SQL yields no advice."""

from functools import lru_cache

import sqlglot
from sqlglot import exp
from sqlglot.errors import SqlglotError
from sqlglot.optimizer.scope import traverse_scope


def dialect(engine: str) -> str:
    return "mysql" if engine in {"mysql", "mariadb"} else "postgres"


def identifier(node: exp.Expression | None, engine: str = "postgres") -> str:
    if node is None:
        return ""
    # Preserve case for quoted PostgreSQL identifiers and for MySQL table names.
    return node.name if node.args.get("quoted") or engine != "postgres" else node.name.lower()


def table_name(table: exp.Table, engine: str = "postgres") -> str:
    return ".".join(identifier(part, engine) for part in table.parts)


@lru_cache(maxsize=2048)
def filter_candidates(
    sql: str, engine: str = "postgres"
) -> tuple[tuple[str, tuple[str, ...]], ...]:
    """Equality filters per physical table, resolving aliases within each SELECT scope.

    Derived-table lineage and ambiguous unqualified columns are deliberately skipped.
    Never combine columns from unrelated statements into a composite index.
    """
    if len(sql) > 100_000:
        return ()
    try:
        tree = sqlglot.parse_one(sql, read=dialect(engine), error_message_context=0)
        if not isinstance(tree, exp.Query):
            return ()
        found: dict[str, list[str]] = {}
        for scope in traverse_scope(tree):
            where = scope.expression.args.get("where")
            if where is None:
                continue
            for eq in where.find_all(exp.EQ):
                if eq.find_ancestor(exp.Select) is not scope.expression:
                    continue
                if eq.find_ancestor(exp.Or):
                    continue
                for column, value in [(eq.this, eq.expression), (eq.expression, eq.this)]:
                    if not isinstance(column, exp.Column) or not isinstance(
                        value, (exp.Placeholder, exp.Parameter, exp.Literal)
                    ):
                        continue
                    source = (
                        scope.sources.get(column.table)
                        if column.table
                        else (
                            next(iter(scope.sources.values())) if len(scope.sources) == 1 else None
                        )
                    )
                    if not isinstance(source, exp.Table):
                        continue
                    key = table_name(source, engine)
                    cols = found.setdefault(key, [])
                    name = identifier(column.this, engine)
                    if name not in cols:
                        cols.append(name)
        return tuple((table, tuple(cols)) for table, cols in found.items())
    except (SqlglotError, ValueError, RecursionError):
        return ()


@lru_cache(maxsize=2048)
def simple_index_columns(definition: str) -> tuple[str, ...]:
    """Only plain, full, ascending btree keys. All special semantics fail closed."""
    import re

    # Legacy collector fixtures carry only a column list. Accept plain identifiers only.
    match = re.fullmatch(r"\(\s*([a-z_][a-z_0-9]*(?:\s*,\s*[a-z_][a-z_0-9]*)*)\s*\)", definition)
    if match:
        return tuple(x.strip() for x in match[1].split(","))
    try:
        tree = sqlglot.parse_one(definition, read="postgres", error_message_context=0)
        if not isinstance(tree, exp.Create) or tree.args.get("kind") != "INDEX":
            return ()
        params = tree.this.args.get("params")
        if params is None or str(params.args.get("using") or "btree").lower() != "btree":
            return ()
        if any(value for key, value in params.args.items() if key not in {"using", "columns"}):
            return ()
        cols = []
        for ordered in params.args.get("columns") or []:
            col = ordered.this
            if (
                not isinstance(col, exp.Column)
                or ordered.args.get("desc")
                or ordered.args.get("nulls_first")
            ):
                return ()
            cols.append(identifier(col.this))
        return tuple(cols)
    except (SqlglotError, ValueError, RecursionError, AttributeError):
        return ()
