"""Conservative source heuristics; never execute SQL or claim plan-level proof.

Definitions are routine bodies (not CREATE PROCEDURE wrappers). Only simple,
unquoted identifiers and single-query statements are bound to column metadata.
"""
import re

from .base import Finding, Rule, register

IDENT = r'[a-z_][a-z_0-9$]*'
QUALIFIED = rf'{IDENT}(?:\.{IDENT})?'
TYPE = (r'(?:character varying|double precision|timestamp(?:\s+with(?:out)? time zone)?|'
        r'varchar|nvarchar|char|bigint|smallint|tinyint|integer|int[248]?|numeric|decimal|'
        r'float[48]?|real|double|datetime|date|text|boolean|bool|uuid|binary|varbinary)'
        r'(?:\s*\(\s*\d+(?:\s*,\s*\d+)?\s*\))?(?:\s+unsigned)?(?![a-z_0-9])')
DECL = re.compile(rf'\b({IDENT})\s+({TYPE})', re.I)


def mask_sql(source):
    """Blank strings/comments/quoted names, preserving offsets and line numbers."""
    out = list(source)
    i = 0
    while i < len(source):
        start = i
        if source.startswith('--', i) or source[i] == '#':
            end = source.find('\n', i)
            i = len(source) if end < 0 else end
        elif source.startswith('/*', i):
            i += 2
            depth = 1
            while i < len(source) and depth:
                if source.startswith('/*', i):
                    depth += 1; i += 2
                elif source.startswith('*/', i):
                    depth -= 1; i += 2
                else:
                    i += 1
        elif source[i] in "'\"`":
            quote = source[i]; i += 1
            while i < len(source):
                if source[i] == '\\':
                    i += 2
                elif source[i] == quote:
                    i += 1
                    if i < len(source) and source[i] == quote:
                        i += 1
                    else:
                        break
                else:
                    i += 1
        elif source[i] == '$' and (m := re.match(r'\$(?:[a-zA-Z_][\w]*)?\$', source[i:])):
            end = source.find(m[0], i + len(m[0]))
            i = len(source) if end < 0 else end + len(m[0])
        else:
            i += 1
            continue
        for j in range(start, min(i, len(source))):
            if out[j] != '\n':
                out[j] = ' '
    return ''.join(out).lower()


def type_key(value, engine):
    value = re.sub(r'\s+', ' ', value.strip().lower())
    value = re.sub(r'\s*([(),])\s*', r'\1', value)
    aliases = {'integer': 'int', 'int4': 'int', 'int8': 'bigint', 'int2': 'smallint',
               'character varying': 'varchar', 'decimal': 'numeric', 'bool': 'boolean'}
    for old, new in aliases.items():
        value = re.sub(rf'^{old}(?=\(| |$)', new, value)
    if engine != 'postgres':
        value = re.sub(r'^(tinyint|smallint|int|bigint)\(\d+\)', r'\1', value)
    return value


def split_columns(text):
    return re.split(r',\s*(?![^()]*\))', text)


@register
class ProcedureReview(Rule):
    id = 'R-SP'
    title = 'Stored procedure review'
    category = 'procedures'

    def evaluate(self, snapshot):
        findings = []
        catalog = {}
        for col in snapshot.columns:
            key = f'{col.schema_name}.{col.table}'.lower()
            catalog.setdefault(key, {})[col.name.lower()] = col.data_type
        for routine in snapshot.procedures:
            if not routine.definition or routine.language.lower() not in {'sql', 'plpgsql'}:
                continue
            sql = mask_sql(routine.definition)
            target = routine.identity or f'{routine.schema_name}.{routine.name}'
            seen = set()

            def emit(code, title, action, offset, **evidence):
                key = (code, tuple(evidence.items()))
                if key in seen:
                    return
                seen.add(key)
                findings.append(Finding(
                    rule_id=f'R-SP{code}', title=title, category='procedures',
                    engine=snapshot.meta.engine, severity='LOW' if code in (3, 4, 5) else 'MEDIUM',
                    confidence='medium', affected_object=target,
                    evidence={'line': sql.count('\n', 0, offset) + 1,
                              'analysis': 'static source heuristic', **evidence},
                    suggested_action=action))

            variables = {p.name.lower(): p.data_type for p in routine.parameters}
            # MySQL DECLARE per variable; PostgreSQL DECLARE section before BEGIN.
            declarations = list(re.finditer(r'\bdeclare\s+([^;]+)', sql))
            if snapshot.meta.engine == 'postgres':
                block = re.search(r'\bdeclare\b(.*?)\bbegin\b', sql, re.S)
                if block:
                    declarations = list(re.finditer(r'(?:^|;)\s*([^;]+)', block[1]))
            for declaration in declarations:
                match = DECL.match(declaration[1].strip())
                if match:
                    name, dtype = match.groups()
                    # Anchored %TYPE and arrays are not scalar declarations.
                    rest = declaration[1].strip()[match.end():].lstrip()
                    if not rest.startswith(('%', '[', '.')):
                        if name in variables:
                            variables[name] = None  # shadowing needs scope analysis
                        else:
                            variables[name] = dtype
            temps = {}
            for match in re.finditer(rf'\bcreate\s+temp(?:orary)?\s+table\s+(?:if\s+not\s+exists\s+)?({IDENT})(?=\s*(?:\(|as\b|like\b))', sql):
                start = match.end()
                while start < len(sql) and sql[start].isspace():
                    start += 1
                body = ''
                if start < len(sql) and sql[start] == '(':
                    start += 1
                    depth = 1
                    end = start
                    while end < len(sql) and depth:
                        depth += (sql[end] == '(') - (sql[end] == ')')
                        end += 1
                    body = sql[start:end-1]
                cols = {}
                for part in split_columns(body):
                    col = DECL.match(part.strip())
                    if col:
                        cols[col[1]] = col[2]
                temps[match[1]] = cols
                indexed = re.search(r'\b(primary\s+key|unique|index|key)\b', body)
                indexed = indexed or re.search(rf'\bcreate\s+(?:unique\s+)?index\s+{IDENT}\s+on\s+{match[1]}\b', sql)
                indexed = indexed or re.search(rf'\balter\s+table\s+{match[1]}\b[^;]*\b(primary\s+key|unique|index|key)\b', sql)
                inherited = re.match(r'\s*(?:\(\s*)?like\b', sql[match.end():])
                if not indexed and not inherited and re.search(rf'\b(?:from|join)\s+{match[1]}\b[^;]*\b(?:where|on|group\s+by|order\s+by)\b', sql):
                    emit(2, 'Temporary table accessed without an explicit index',
                         'Review join/filter columns and row counts. Benchmark a suitable index against its build/write cost; small temporary tables may be faster without one.',
                         match.start(), temporary_table=match[1])

            def resolve_table(name):
                if name in temps:
                    return temps[name]
                if '.' in name:
                    return catalog.get(name)
                matches = [v for k, v in catalog.items() if k.rsplit('.', 1)[-1] == name]
                return matches[0] if len(matches) == 1 else None

            offset = 0
            for statement in sql.split(';'):
                # Nested queries, CTEs and comma joins require an actual scope parser.
                simple = len(re.findall(r'\bselect\b', statement)) <= 1 and not re.search(r'\bwith\b', statement)
                bindings = {}
                for match in re.finditer(rf'\b(?:from|join|update)\s+({QUALIFIED})(?:\s+(?:as\s+)?({IDENT}))?', statement):
                    name, alias = match.groups()
                    if alias in {'where', 'join', 'left', 'right', 'inner', 'outer', 'on', 'set', 'group', 'order', 'limit', 'having', 'cross', 'full'}:
                        alias = None
                    binding = alias or name.split('.')[-1]
                    if binding in bindings:
                        simple = False
                    bindings[binding] = resolve_table(name)
                if re.search(r'\bfrom\b[^;]*,', statement.split('where')[0]):
                    simple = False

                def operand_type(operand):
                    if '.' in operand:
                        alias, name = operand.split('.', 1)
                        cols = bindings.get(alias)
                        return cols.get(name) if cols else None
                    if operand in variables and not any(cols is None or operand in cols for cols in bindings.values()):
                        return variables[operand]
                    return None

                if simple:
                    for match in re.finditer(rf'(?<![\w.])({QUALIFIED})\s*(?:=|<>|!=|<=|>=|<|>)\s*({QUALIFIED})(?![\w.])', statement):
                        left, right = match.groups()
                        a, b = operand_type(left), operand_type(right)
                        if a and b and type_key(a, snapshot.meta.engine) != type_key(b, snapshot.meta.engine):
                            emit(1, 'Compared operands have different declared datatypes',
                                 'Align parameter/local/temp-column types with the source column, including length, precision and signedness. Check conversion direction and the execution plan before changing types.',
                                 offset + match.start(), left_operand=left, left_type=a, right_operand=right, right_type=b)
                if simple:
                    insert = re.search(rf'\binsert\s+into\s+({IDENT})\s*\(([^)]+)\)\s*select\s+(.*?)\s+from\b', statement, re.S)
                    if insert and insert[1] in temps:
                        destinations = [c.strip() for c in insert[2].split(',')]
                        sources = [c.strip() for c in insert[3].split(',')]
                        if len(destinations) == len(sources):
                            for dest, source in zip(destinations, sources):
                                if not re.fullmatch(QUALIFIED, source):
                                    continue
                                a = temps[insert[1]].get(dest)
                                b = operand_type(source)
                                if a and b and type_key(a, snapshot.meta.engine) != type_key(b, snapshot.meta.engine):
                                    emit(1, 'Temporary column differs from inserted source datatype',
                                         'Align temporary column definitions with source types, length and precision. Check for truncation/rounding and avoid conversions when joining back to the original table.',
                                         offset + insert.start(), left_operand=f'{insert[1]}.{dest}', left_type=a,
                                         right_operand=source, right_type=b)
                for code, pattern, title, action in [
                    (3, r'\b(cursor|loop|while)\b', 'Row-by-row processing candidate', 'Review work inside the cursor/loop for repeated queries. Consider a set-based operation and compare plans, locking and runtime.'),
                    (4, r'\bselect\s+(?:distinct\s+)?\*', 'SELECT * in stored procedure', 'Select only required columns to reduce row width, I/O and coupling to schema changes.'),
                    (5, r'\b(?:execute|prepare)\b', 'Dynamic SQL needs separate review', 'Dynamic SQL strings are not analysed. Capture generated statements and plans; use bound parameters where supported.'),
                    (6, rf'\b(?:where|and|or|on)\s+(?:cast|lower|upper|date|coalesce|ifnull)\s*\(\s*{IDENT}\.{IDENT}', 'Function applied to a predicate column', 'Check whether a matching expression index exists. Consider comparing the original column to a converted parameter or a range predicate, then validate the execution plan.'),
                ]:
                    match = re.search(pattern, statement)
                    if match:
                        emit(code, title, action, offset + match.start())
                offset += len(statement) + 1
        return findings
