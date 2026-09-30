"""Bounded DDL ingestion and conservative PostgreSQL/MySQL routine inspection.

SQLGlot parses relational statements. Procedural syntax is inspected lexically;
unsupported statements and ambiguous scope are reported, never silently certified.
Raw DDL, literals and procedure bodies are not persisted in the catalog.
"""

from __future__ import annotations

import re
from bisect import bisect_right

import sqlglot
from sqlglot import exp
from sqlglot.errors import SqlglotError

from app.vendor.dbdoctor.engine.schema import (
    RoutineInfo,
    RoutineStatement,
    SchemaCatalog,
    SchemaColumn,
    SchemaIndex,
    SchemaTable,
    TempTableInfo,
    VariableInfo,
)
from app.vendor.dbdoctor.engine.sql_analysis import dialect, identifier, simple_index_columns, table_name
from app.vendor.dbdoctor.engine.sql_lexer import redact_sql, sql_tokens

MAX_DDL_BYTES = 5 * 1024 * 1024
MAX_DDL_FILES = 20
MAX_STATEMENTS = 10_000
MAX_TOKENS = 250_000


def _parse(sql: str, engine: str):
    # error_message_context=0 ensures parser fallback warnings never print customer SQL.
    return sqlglot.parse_one(sql, read=dialect(engine), error_message_context=0)


def _name(tokens, i, engine):
    parts = []
    while i < len(tokens) and tokens[i][0] in {"WORD", "IDENT"}:
        kind, text, *_ = tokens[i]
        if kind == "IDENT":
            quote = text[0]
            text = text[1:-1].replace(quote * 2, quote)
        elif engine == "postgres":
            text = text.lower()
        parts.append(text)
        i += 1
        if i >= len(tokens) or tokens[i][1] != ".":
            break
        i += 1
    return ".".join(parts), i


def _split(sql: str, engine: str):
    """Honor PG dollar bodies and MySQL DELIMITER directives without executing them."""
    tokens = list(sql_tokens(sql, mysql=engine != "postgres"))
    if len(tokens) > MAX_TOKENS:
        raise ValueError("DDL token limit exceeded")
    delimiter = ";"
    start = 0
    i = 0
    depth = 0
    routine = False
    statement_started = False
    while i < len(tokens):
        kind, text, begin, end = tokens[i]
        upper = text.upper() if kind == "WORD" else ""
        line_start = sql.rfind("\n", 0, begin) + 1
        if (engine != "postgres" and upper == "DELIMITER" and not statement_started
                and not sql[line_start:begin].strip()):
            line_end = sql.find("\n", end)
            if line_end < 0:
                line_end = len(sql)
            delimiter = sql[end:line_end].strip()
            if not delimiter or len(delimiter) > 16:
                raise ValueError("Invalid DELIMITER directive")
            start = line_end
            while i < len(tokens) and tokens[i][2] < line_end:
                i += 1
            continue
        statement_started = True
        if upper in {"PROCEDURE", "FUNCTION"}:
            routine = True
        # Without DELIMITER, preserve a simple BEGIN/END procedure body too.
        following = tokens[i + 1][1].upper() if i + 1 < len(tokens) else ""
        if routine and engine != "postgres" and upper == "BEGIN":
            depth += 1
        elif (
            routine
            and engine != "postgres"
            and upper == "END"
            and following not in {"IF", "LOOP", "WHILE", "REPEAT", "CASE"}
        ):
            depth = max(0, depth - 1)
        delimiter_at = begin
        if delimiter != ";" and kind == "WORD" and text.endswith(delimiter):
            delimiter_at = end - len(delimiter)
        if sql.startswith(delimiter, delimiter_at) and (delimiter != ";" or not depth):
            if sql[start:delimiter_at].strip():
                yield sql[start:delimiter_at], start
            stop = delimiter_at + len(delimiter)
            while i < len(tokens) and tokens[i][2] < stop:
                i += 1
            start = stop
            routine = False
            statement_started = False
            # END$$ is one lexer word, so BEGIN depth may still be nonzero.
            # The custom delimiter nevertheless completes the routine. Reset
            # its state so subsequent tables/indexes split normally after the
            # exporter restores DELIMITER ; in the same combined file.
            depth = 0
            continue
        i += 1
    if sql[start:].strip():
        yield sql[start:], start


def _column(column, engine):
    constraints = [c.args.get("kind") for c in column.args.get("constraints") or []]
    primary = any(isinstance(c, exp.PrimaryKeyColumnConstraint) for c in constraints)
    return SchemaColumn(
        name=identifier(column.this, engine),
        data_type=redact_sql(
            column.args["kind"].sql(dialect=dialect(engine)), mysql=engine != "postgres"
        )
        if column.args.get("kind")
        else "unknown",
        nullable=not primary
        and not any(isinstance(c, exp.NotNullColumnConstraint) for c in constraints),
        primary_key=primary,
        unique=primary or any(isinstance(c, exp.UniqueColumnConstraint) for c in constraints),
    )


def _table(tree, engine):
    schema = tree.this
    target = schema.this if isinstance(schema, exp.Schema) else schema
    if not isinstance(target, exp.Table):
        return None
    columns = [_column(c, engine) for c in schema.expressions if isinstance(c, exp.ColumnDef)]
    refs = sorted(
        {
            table_name(t, engine)
            for ref in tree.find_all(exp.Reference)
            for t in ref.find_all(exp.Table)
        }
    )
    return SchemaTable(name=table_name(target, engine), columns=columns, referenced_tables=refs)


def _index(tree, engine):
    if not isinstance(tree.this, exp.Index):
        return None
    idx = tree.this
    target = idx.args.get("table")
    if not isinstance(target, exp.Table):
        return None
    if engine == "postgres":
        cols = simple_index_columns(tree.sql(dialect="postgres"))
    else:
        params = idx.args.get("params")
        keys = params.args.get("columns") or [] if params else []
        plain = params is not None and not any(
            v for k, v in params.args.items() if k not in {"using", "columns"}
        )
        plain = plain and str(params.args.get("using") or "btree").lower() == "btree"
        cols = (
            tuple(identifier(k.this.this, engine) for k in keys)
            if plain
            and all(isinstance(k.this, exp.Column) and not k.args.get("desc") for k in keys)
            else ()
        )
    return SchemaIndex(
        name=identifier(idx.this, engine),
        table=table_name(target, engine),
        columns=list(cols),
        unique=bool(tree.args.get("unique")),
        plain_btree=bool(cols),
    )


def _constraints(catalog, table, expressions, engine):
    for constraint in expressions:
        items = constraint.expressions if isinstance(constraint, exp.Constraint) else [constraint]
        for item in items:
            if isinstance(item, exp.ForeignKey):
                table.referenced_tables.extend(
                    table_name(t, engine) for t in item.find_all(exp.Table)
                )
            if not isinstance(
                item, (exp.PrimaryKey, exp.UniqueColumnConstraint, exp.IndexColumnConstraint)
            ):
                continue
            cols = item.this.expressions if isinstance(item.this, exp.Schema) else item.expressions
            plain = bool(cols) and all(isinstance(c, (exp.Identifier, exp.Column)) for c in cols)
            plain = plain and not item.args.get("kind") and not item.args.get("index_type")
            names = (
                [identifier(c.this if isinstance(c, exp.Column) else c, engine) for c in cols]
                if plain
                else []
            )
            unique = isinstance(item, (exp.PrimaryKey, exp.UniqueColumnConstraint))
            primary = isinstance(item, exp.PrimaryKey)
            catalog.indexes.append(
                SchemaIndex(
                    name=constraint.name or "table_constraint",
                    table=table.name,
                    columns=names,
                    unique=unique,
                    primary=primary,
                    plain_btree=plain,
                )
            )
            for col in table.columns:
                if col.name in names and primary:
                    col.primary_key = True
                    col.nullable = False
                if col.name in names and unique and len(names) == 1:
                    col.unique = True
    table.referenced_tables = sorted(set(table.referenced_tables))


def _routine(sql, tokens, engine, base_line):
    words = [t[1].upper() if t[0] == "WORD" else "" for t in tokens]
    at = next((i for i, w in enumerate(words) if w in {"PROCEDURE", "FUNCTION"}), None)
    if at is None:
        return None
    name, after_name = _name(tokens, at + 1, engine)
    if not name:
        return None
    line_starts = [m.end() for m in re.finditer("\n", sql)]

    def line(offset):
        return base_line + bisect_right(line_starts, offset)

    language = "plpgsql" if engine == "postgres" else "sql"
    if "LANGUAGE" in words:
        i = words.index("LANGUAGE") + 1
        if i < len(tokens):
            language = tokens[i][1].strip("'\"").lower()
    routine = RoutineInfo(
        name=name, kind=words[at].lower(), language=language, line=line(tokens[at][2])
    )
    # Parameter definitions: retain names/types but never defaults.
    end_params = after_name
    if after_name < len(tokens) and tokens[after_name][1] == "(":
        level, group = 1, []
        for j in range(after_name + 1, len(tokens)):
            text = tokens[j][1]
            if text == "(":
                level += 1
            if text == ")":
                level -= 1
            if (text == "," and level == 1) or level == 0:
                _add_variable(routine.parameters, group, engine, line, "parameter")
                group = []
                if level == 0:
                    end_params = j + 1
                    break
            else:
                group.append(tokens[j])
    body_offset = 0
    if engine == "postgres":
        body_token = next((t for t in tokens[end_params:] if t[0] == "BODY"), None)
        if body_token:
            marker = re.match(r"\$[^$]*\$", body_token[1])[0]
            body = body_token[1][len(marker) : -len(marker)]
            body_offset = body_token[2] + len(marker)
        else:
            routine.limitations.append(
                "Only dollar-quoted PostgreSQL SQL/PLpgSQL bodies are inspected."
            )
            return routine
        if language not in {"plpgsql", "sql"}:
            routine.limitations.append("Routine language is unsupported; body was not analyzed.")
            return routine
    else:
        body_offset = tokens[end_params][2] if end_params < len(tokens) else len(sql)
        body = sql[body_offset:]
    body_tokens = [
        (k, v, a + body_offset, b + body_offset)
        for k, v, a, b in sql_tokens(body, mysql=engine != "postgres")
    ]
    body_words = [v.upper() if k == "WORD" else "" for k, v, *_ in body_tokens]
    # Declaration blocks: PG DECLARE var type; var type; BEGIN / MySQL DECLARE var type.
    declaring = False
    declaration = []
    for i, token in enumerate(body_tokens):
        word = body_words[i]
        if word == "DECLARE":
            declaring = True
            declaration = []
            continue
        if declaring and word == "BEGIN":
            declaring = False
            declaration = []
            continue
        if declaring and token[1] == ";":
            _add_variable(routine.variables, declaration, engine, line, "local")
            declaration = []
            if engine != "postgres":
                declaring = False
        elif declaring:
            declaration.append(token)
        prev = body_words[i - 1] if i else ""
        if word in {"LOOP", "WHILE", "REPEAT", "FOR", "FOREACH"} and prev != "END":
            routine.loop_lines.append(line(token[2]))
        if word in {"IF", "CASE"} and prev != "END":
            routine.branch_lines.append(line(token[2]))
        if word in {"EXECUTE", "PREPARE"}:
            routine.dynamic_sql_lines.append(line(token[2]))
    for var in routine.parameters + routine.variables:
        for i, token in enumerate(body_tokens):
            if token[0] not in {"WORD", "IDENT"}:
                continue
            token_name, _ = _name([token], 0, engine)
            if token_name == var.name:
                var.occurrences += 1
                tail = [x[1] for x in body_tokens[i + 1 : i + 3]]
                prev = body_words[i - 1] if i else ""
                if (
                    tail[:2] == [":", "="]
                    or (tail[:1] == ["="] and prev == "SET")
                    or prev == "INTO"
                ):
                    var.assignment_lines.append(line(token[2]))
    names = [v.name for v in routine.parameters + routine.variables]
    if len(names) != len(set(names)):
        routine.limitations.append(
            "Repeated variable names: nested scope/shadowing is not resolved."
        )
    routine.limitations.append(
        "Variable occurrences and assignments are lexical; runtime values and "
        "branch execution are unknown."
    )
    if routine.dynamic_sql_lines:
        routine.limitations.append(
            "Dynamic SQL dependencies and generated temporary tables cannot be resolved statically."
        )
    # Segment static SQL at semicolons; skip declarations/control prefixes up to first SQL verb.
    starts = {"SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "DROP", "TRUNCATE", "ALTER", "WITH"}
    segments, group = [], []
    for token in body_tokens:
        if token[1] == ";" and token[0] == "SYMBOL":
            if group:
                segments.append(group)
            group = []
        else:
            group.append(token)
    if group:
        segments.append(group)
    for group in segments:
        first = next(
            (i for i, t in enumerate(group) if t[0] == "WORD" and t[1].upper() in starts), None
        )
        if first is None:
            continue
        sql_group = group[first:]
        statement = sql[sql_group[0][2] : sql_group[-1][3]]
        record = RoutineStatement(
            line=line(sql_group[0][2]),
            kind=sql_group[0][1].upper(),
            normalized_sql=redact_sql(statement, mysql=engine != "postgres"),
        )
        try:
            tree = _parse(statement, engine)
            if isinstance(tree, exp.Command) or tree is None:
                raise ValueError
            record.tables = sorted(
                {
                    table_name(t, engine)
                    for t in tree.find_all(exp.Table)
                    if not (isinstance(t.parent, exp.Into) and table_name(t, engine) in names)
                }
            )
            record.parsed = True
            if isinstance(tree, exp.Create) and tree.args.get("kind") == "TABLE":
                if tree.find(exp.TemporaryProperty):
                    table = _table(tree, engine)
                    if table:
                        routine.temporary_tables.append(
                            TempTableInfo(
                                name=table.name,
                                creation_line=record.line,
                                columns=[c.name for c in table.columns],
                            )
                        )
            into = tree.args.get("into")
            if isinstance(into, exp.Into) and into.args.get("temporary"):
                routine.temporary_tables.append(
                    TempTableInfo(name=table_name(into.this, engine), creation_line=record.line)
                )
            for temp in routine.temporary_tables:
                if isinstance(tree, exp.Create) and tree.args.get("kind") == "INDEX":
                    idx = _index(tree, engine)
                    if idx and idx.table == temp.name:
                        temp.indexes.append(idx.name)
                if temp.name in record.tables:
                    if isinstance(tree, exp.Drop):
                        temp.drop_lines.append(record.line)
                    elif isinstance(tree, (exp.Insert, exp.Update, exp.Delete, exp.Create)):
                        temp.write_lines.append(record.line)
                    else:
                        temp.read_lines.append(record.line)
        except (SqlglotError, ValueError, AttributeError, RecursionError):
            routine.limitations.append(
                f"Statement at line {record.line} was not parsed; dependencies may be incomplete."
            )
        routine.statements.append(record)
    temps = {t.name for t in routine.temporary_tables}
    routine.dependencies = sorted(
        {t for s in routine.statements for t in s.tables if t not in temps}
    )
    routine.loop_lines = sorted(set(routine.loop_lines))
    routine.branch_lines = sorted(set(routine.branch_lines))
    routine.dynamic_sql_lines = sorted(set(routine.dynamic_sql_lines))
    return routine


def _add_variable(target, group, engine, line, kind):
    if not group:
        return
    if group[0][1].upper() in {"IN", "OUT", "INOUT", "VARIADIC"}:
        group = group[1:]
    if len(group) < 2 or group[0][0] not in {"WORD", "IDENT"}:
        return
    if group[0][1].upper() in {"CONTINUE", "EXIT", "UNDO"}:
        return
    name, _ = _name(group[:1], 0, engine)
    type_tokens = []
    for token in group[1:]:
        if token[1].upper() in {"DEFAULT", ":", "=", "CONSTANT", "NOT"}:
            break
        if token[0] in {"STRING", "BODY"}:
            break
        type_tokens.append(token[1])
    target.append(
        VariableInfo(
            name=name,
            data_type=" ".join(type_tokens) or "unknown",
            kind=kind,
            declaration_line=line(group[0][2]),
            assignment_lines=[line(group[0][2])]
            if any(t[1].upper() in {"DEFAULT", ":", "="} for t in group)
            else [],
        )
    )


def ingest_ddl(sources: list[str], engine: str, default_schema: str | None = None) -> SchemaCatalog:
    if engine not in {"postgres", "mysql", "mariadb"}:
        raise ValueError("DDL supports PostgreSQL, MySQL and MariaDB only")
    if len(sources) > MAX_DDL_FILES or sum(len(s.encode("utf-8")) for s in sources) > MAX_DDL_BYTES:
        raise ValueError("DDL exceeds the limit of 20 files / 5 MiB combined")
    catalog = SchemaCatalog(engine=engine, source_count=len(sources))

    def qualify(name, namespace):
        return f"{namespace}.{name}" if namespace and "." not in name else name

    count = 0
    for source_number, source in enumerate(sources, 1):
        namespace = default_schema
        for sql, offset in _split(source, engine):
            count += 1
            if count > MAX_STATEMENTS:
                raise ValueError("DDL statement limit exceeded")
            line = source.count("\n", 0, offset) + 1
            tokens = list(sql_tokens(sql, mysql=engine != "postgres"))
            if not tokens:
                continue
            words = [t[1].upper() if t[0] == "WORD" else "" for t in tokens]
            if words[0] == "USE" and engine != "postgres":
                namespace, end = _name(tokens, 1, engine)
                if end != len(tokens) or not namespace:
                    raise ValueError("Invalid USE schema directive")
                continue
            if words[0] == "CREATE" and any(w in {"PROCEDURE", "FUNCTION"} for w in words[:12]):
                routine = _routine(sql, tokens, engine, line)
                if routine:
                    routine.name = qualify(routine.name, namespace)
                    routine.dependencies = [qualify(t, namespace) for t in routine.dependencies]
                    routine.source_file = source_number
                    catalog.routines.append(routine)
                    continue
            try:
                if words[0] not in {"CREATE", "ALTER"}:
                    raise ValueError
                tree = _parse(sql, engine)
                if isinstance(tree, exp.Alter) and tree.args.get("kind") == "TABLE":
                    target = qualify(table_name(tree.this, engine), namespace)
                    matches = [t for t in catalog.tables if t.name == target]
                    actions = tree.args.get("actions") or []
                    if (
                        len(matches) != 1
                        or not actions
                        or not all(isinstance(a, exp.AddConstraint) for a in actions)
                    ):
                        raise ValueError
                    for action in actions:
                        _constraints(catalog, matches[0], action.expressions, engine)
                    continue
                if not isinstance(tree, exp.Create):
                    raise ValueError
                kind = tree.args.get("kind")
                if kind == "TABLE":
                    table = _table(tree, engine)
                    if table is None:
                        raise ValueError
                    table.name = qualify(table.name, namespace)
                    table.referenced_tables = [
                        qualify(t, namespace) for t in table.referenced_tables
                    ]
                    catalog.tables.append(table)
                    for col in table.columns:
                        if col.primary_key or col.unique:
                            catalog.indexes.append(
                                SchemaIndex(
                                    name=f"{table.name}_{col.name}_constraint",
                                    table=table.name,
                                    columns=[col.name],
                                    primary=col.primary_key,
                                    unique=True,
                                    plain_btree=True,
                                )
                            )
                    _constraints(catalog, table, tree.this.expressions, engine)
                elif kind == "INDEX":
                    idx = _index(tree, engine)
                    if idx is None:
                        raise ValueError
                    idx.table = qualify(idx.table, namespace)
                    catalog.indexes.append(idx)
                elif kind == "VIEW":
                    target = tree.this.this if isinstance(tree.this, exp.Schema) else tree.this
                    catalog.views.append(qualify(table_name(target, engine), namespace))
                else:
                    raise ValueError
            except (SqlglotError, ValueError, AttributeError, RecursionError):
                catalog.warnings.append(
                    f"File {source_number}, line {line}: unsupported statement; not analyzed."
                )
    if not (catalog.tables or catalog.indexes or catalog.routines or catalog.views):
        catalog.warnings.append(
            "No supported definitions found. Executable MySQL comments are not "
            "interpreted; export plain CREATE statements."
        )
    identities = [t.name for t in catalog.tables]
    if len(identities) != len(set(identities)):
        catalog.warnings.append(
            "Duplicate table names across DDL files: qualify database/schema names "
            "before relying on index advice."
        )
    return catalog
