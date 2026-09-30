"""Small lossless SQL lexer used for redaction and routine segmentation.

The marked block is copied into standalone collectors; a test prevents drift.
It does not interpret SQL or execute statements. Unterminated input fails closed.
"""

import re

# BEGIN SHARED SQL LEXER
_SQL_WORD = re.compile(r"[\w$]+", re.UNICODE)
_SQL_NUMBER = re.compile(
    r"[-+]?(?:0[xX][0-9a-fA-F]+|0[bB][01]+|(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?)"
)
_SQL_DOLLAR = re.compile(r"\$(?:[A-Za-z_][A-Za-z_0-9]*)?\$")


def sql_tokens(sql: str, mysql: bool = False):
    """Yield (kind, original text, start, end), omitting whitespace/comments."""
    i, n = 0, len(sql)
    while i < n:
        start = i
        c = sql[i]
        if c.isspace():
            i += 1
            continue
        if sql.startswith("--", i) or (mysql and c == "#"):
            end = sql.find("\n", i)
            i = n if end < 0 else end + 1
            continue
        if sql.startswith("/*", i):
            depth = 1
            i += 2
            while i < n and depth:
                if sql.startswith("/*", i):
                    depth += 1
                    i += 2
                elif sql.startswith("*/", i):
                    depth -= 1
                    i += 2
                else:
                    i += 1
            if depth:
                raise ValueError("Unterminated SQL comment")
            continue
        dollar = _SQL_DOLLAR.match(sql, i) if c == "$" and not mysql else None
        if dollar:
            end = sql.find(dollar[0], dollar.end())
            if end < 0:
                raise ValueError("Unterminated dollar-quoted SQL")
            i = end + len(dollar[0])
            yield "BODY", sql[start:i], start, i
            continue
        escaped = c in "eE" and i + 1 < n and sql[i + 1] == "'"
        quote = sql[i + 1] if escaped else c
        if quote in "'\"`":
            string = quote == "'" or escaped or (mysql and quote == '"')
            i += 2 if escaped else 1
            while i < n:
                if sql[i] == "\\" and string and (mysql or escaped):
                    i += 2
                elif sql[i] == quote:
                    i += 1
                    if i < n and sql[i] == quote:
                        i += 1
                    else:
                        break
                else:
                    i += 1
            else:
                raise ValueError("Unterminated quoted SQL")
            yield "STRING" if string else "IDENT", sql[start:i], start, i
            continue
        if c == "$" and i + 1 < n and sql[i + 1].isdigit():
            i += 2
            while i < n and sql[i].isdigit():
                i += 1
            yield "PARAM", sql[start:i], start, i
            continue
        number = _SQL_NUMBER.match(sql, i)
        if number:
            i = number.end()
            yield "NUMBER", sql[start:i], start, i
            continue
        word = _SQL_WORD.match(sql, i)
        if word:
            i = word.end()
            yield "WORD", sql[start:i], start, i
            continue
        i += 1
        yield "SYMBOL", c, start, i


def redact_sql(sql: str, mysql: bool = False) -> str:
    """Remove comments and literal values, preserving identifier spelling."""
    try:
        chunks = []
        end = 0
        for kind, value, start, stop in sql_tokens(sql, mysql):
            if start > end:
                chunks.append(" ")
            chunks.append("?" if kind in {"STRING", "BODY", "NUMBER", "PARAM"} else value)
            end = stop
        result = "".join(chunks).strip()
        return re.sub(
            r"(\b(?:IN|VALUES)\s*)\(\s*\?(?:\s*,\s*\?)*\s*\)", r"\1(?)", result, flags=re.IGNORECASE
        )
    except ValueError:
        return "[unparseable SQL redacted]"


# END SHARED SQL LEXER
