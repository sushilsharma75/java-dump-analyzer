"""Conservative lexical source symbols. No comment/string matches or compiler claims.

Brace-balanced scopes preserve offsets, including multiline Java declarations.
Unsupported language constructs remain unresolved instead of guessing a location.
"""

import re


def mask(text):
    pattern = (
        r'"""[\s\S]*?"""|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|//[^\n]*|/\*[\s\S]*?\*/'
    )
    return re.sub(
        pattern, lambda m: "".join("\n" if c == "\n" else " " for c in m[0]), text
    )


def scopes(text):
    clean = mask(text)
    pairs, stack = {}, []
    for i, c in enumerate(clean):
        if c == "{":
            stack.append(i)
        elif c == "}" and stack:
            pairs[stack.pop()] = i
    package = re.search(r"\bpackage\s+([\w.]+)", clean)
    package = package[1] if package else ""
    imports = re.findall(r"\bimport\s+(?:static\s+)?([\w.*]+)", clean)
    types = []
    for m in re.finditer(
        r"\b(?:class|interface|enum|record|object|trait)\s+(\w+)[^;{}]*\{", clean
    ):
        opening = m.end() - 1
        if opening not in pairs:
            continue
        parent = next(
            (t for t in reversed(types) if t["start"] < m.start() < t["end"]), None
        )
        fqcn = (
            parent["fqcn"] + "$" + m[1]
            if parent
            else ".".join(filter(None, (package, m[1])))
        )
        types.append(
            dict(
                name=m[1],
                fqcn=fqcn,
                start=opening,
                end=pairs[opening],
                line=text.count("\n", 0, m.start()) + 1,
            )
        )
    methods = []
    for m in re.finditer(
        r"\b(\w+)\s*\([^;{}]*\)\s*(?:throws\s+[\w.,\s]+)?\s*\{", clean
    ):
        if m[1] in ("if", "for", "while", "switch", "catch", "synchronized", "when"):
            continue
        opening = m.end() - 1
        if opening not in pairs:
            continue
        owner = next(
            (t for t in reversed(types) if t["start"] < m.start() < t["end"]), None
        )
        if not owner:
            continue
        # Only methods directly inside their type, not calls/lambdas in another method.
        depth = sum(1 for a, b in pairs.items() if a < m.start() < b)
        type_depth = sum(1 for a, b in pairs.items() if a <= owner["start"] < b)
        if depth != type_depth:
            continue
        methods.append(
            dict(
                name=m[1],
                start=m.start(),
                end=pairs[opening],
                line=text.count("\n", 0, m.start()) + 1,
                end_line=text.count("\n", 0, pairs[opening]) + 1,
                owner=owner["fqcn"],
            )
        )
    return dict(
        clean=clean, package=package, imports=imports, types=types, methods=methods
    )


def java_ast(paths):
    """JDK parser with no dependency resolution or annotation execution.

    Cache compiled helper by content hash, not by working directory or repo code.
    A missing JDK leaves callers with an explicitly labelled lexical fallback.
    """
    import hashlib
    import json
    import shutil
    import subprocess
    import tempfile
    from pathlib import Path

    if not paths or not shutil.which("javac") or not shutil.which("java"):
        return {}
    helper = Path(__file__).parent / "java" / "SourceSymbols.java"
    key = hashlib.sha256(helper.read_bytes()).hexdigest()[:16]
    cache = Path(tempfile.gettempdir()) / ("postmortem-javac-" + key)
    cache.mkdir(exist_ok=True)
    if not (cache / "SourceSymbols.class").exists():
        subprocess.run(
            ["javac", "-d", str(cache), str(helper)],
            check=True,
            capture_output=True,
            timeout=30,
        )
    results = {}
    for offset in range(0, len(paths), 500):
        # Close the manifest before Java opens it: NamedTemporaryFile's default
        # sharing flags prevent a second process from opening it on Windows.
        with tempfile.TemporaryDirectory(prefix="postmortem-source-") as work:
            manifest = Path(work) / "sources.txt"
            manifest.write_text(
                "\n".join(str(p.resolve()) for p in paths[offset : offset + 500]),
                encoding="utf-8",
            )
            run = subprocess.run(
                ["java", "-Xmx256m", "-cp", str(cache), "SourceSymbols", str(manifest)],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=60,
            )
        if run.returncode:
            continue
        for line in run.stdout.splitlines():
            item = json.loads(line)
            results[Path(item.pop("path"))] = item
    return results
