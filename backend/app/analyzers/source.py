"""
Source-code repository indexer.

Given a directory of Java/Kotlin/Scala source files, builds a map from
fully-qualified class names to file paths. Supports lookup of code snippets
around a specific line number.

Used to enrich diagnostic findings with the exact source location where
a deadlock, contention, or other issue is happening — translating a stack
frame's `com.example.OrderService:142` into a real file with surrounding code.
"""
from __future__ import annotations
import re
import os
from pathlib import Path
from typing import Dict, Optional, List, Tuple
from ..schemas import SourceSnippet
from .source_symbols import scopes, java_ast
import hashlib
import subprocess
import json


# Per-language settings: extensions, package regex, max scan lines for the package decl
LANG_SPECS = {
    ".java": {
        "package_re": re.compile(r"^\s*package\s+([\w.]+)\s*;"),
        "max_scan": 50,
    },
    ".kt": {
        "package_re": re.compile(r"^\s*package\s+([\w.]+)\s*$"),
        "max_scan": 50,
    },
    ".scala": {
        "package_re": re.compile(r"^\s*package\s+([\w.]+)\s*$"),
        "max_scan": 50,
    },
}

# Directories we never traverse — generated/external code that pollutes the index
SKIP_DIRS = {
    "target", "build", "out", "bin", "dist",
    "node_modules", ".gradle", ".idea", ".git", ".svn",
    "__pycache__", "venv", ".venv", "env", ".env",
    "generated-sources", "generated", "tmp", "temp",
}

# Cap to protect against tarbombs / huge repos
MAX_FILES = 50_000
MAX_FILE_BYTES = 5 * 1024 * 1024  # 5 MB per source file

# A declared type that looks like a growable container — the classic leak shape
# for a static field ("static Map cache = ..." that's only ever added to).
_COLLECTION_TYPE_RE = re.compile(
    r"\b(?:Concurrent\w*|Map|HashMap|LinkedHashMap|TreeMap|List|ArrayList|"
    r"LinkedList|Set|HashSet|LinkedHashSet|TreeSet|Collection|Queue|Deque|"
    r"ArrayDeque|Cache|LoadingCache|Multimap|Table|CopyOnWrite\w*|Vector|"
    r"Hashtable|Properties)\b|\[\s*\]"
)


class SourceIndex:
    """An in-memory index of source files keyed by fully-qualified class name."""

    def __init__(self, root: Path):
        self.root = root.resolve()
        # FQCN -> absolute Path
        self._fqcn_to_path: Dict[str, Path] = {}
        # Also support lookup by simple class name (no package) for files we couldn't FQ-resolve
        self._simple_to_paths: Dict[str, List[Path]] = {}
        # Every indexed source file, for reference / usage search
        self._all_files: List[Path] = []
        self.files_indexed = 0
        self.languages: Dict[str, int] = {}
        self._symbols = {}
        self._file_hashes = {}
        self._candidates = {}
        self.provenance = {"build_verified": False, "resolution": "lexical", "limitations": ["Java declarations use javac AST when available; imports are conservatively bound without a project classpath. Other languages use lexical scopes. Runtime build identity must be supplied."]}

    def build(self) -> None:
        """Walk the repo and populate the indexes."""
        count = 0
        for dirpath, dirnames, filenames in os.walk(self.root):
            if count >= MAX_FILES: break
            # In-place prune: skip uninteresting directories
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]

            for fname in filenames:
                ext = os.path.splitext(fname)[1].lower()
                if ext not in LANG_SPECS:
                    continue
                path = Path(dirpath) / fname
                try:
                    if path.stat().st_size > MAX_FILE_BYTES:
                        continue
                except OSError:
                    continue

                try:
                    content = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if not path.resolve().is_relative_to(self.root):
                    continue
                self._file_hashes[path] = hashlib.sha256(path.read_bytes()).hexdigest()
                symbols = scopes(content)
                self._symbols[path] = symbols
                names = [t["fqcn"] for t in symbols["types"]]
                if ext == ".kt":
                    names.append(".".join(filter(None, (symbols["package"], path.stem + "Kt"))))
                for fqcn in names:
                    self._candidates.setdefault(fqcn, []).append(path)
                    if len(self._candidates[fqcn]) == 1:
                        self._fqcn_to_path[fqcn] = path
                    else:
                        self._fqcn_to_path.pop(fqcn, None)
                    simple = fqcn.rsplit(".", 1)[-1]
                    self._simple_to_paths.setdefault(simple, []).append(path)
                self._all_files.append(path)

                self.languages[ext] = self.languages.get(ext, 0) + 1
                count += 1
                if count >= MAX_FILES:
                    self.files_indexed = count
                    self.provenance["truncated"] = True
                    break

        self.files_indexed = count
        try:
            parsed = java_ast([p for p in self._all_files if p.suffix == ".java"])
        except (OSError, subprocess.SubprocessError):
            parsed = {}
        for path, ast in parsed.items():
            if ast.get("valid"):
                self._symbols[path].update(ast, parser="javac")
            else:
                self._symbols[path].update(types=[], methods=[], parser="invalid_java")
        # Rebuild type maps from the compiler syntax tree where available.
        self._candidates.clear(); self._fqcn_to_path.clear(); self._simple_to_paths.clear()
        for path, symbols in self._symbols.items():
            names = [t["fqcn"] for t in symbols["types"]]
            if path.suffix == ".kt": names.append(".".join(filter(None, (symbols["package"], path.stem + "Kt"))))
            for name in names:
                self._candidates.setdefault(name, []).append(path)
                self._simple_to_paths.setdefault(name.rsplit(".", 1)[-1], []).append(path)
        self._fqcn_to_path.update({n: paths[0] for n, paths in self._candidates.items() if len(paths) == 1})
        self.provenance["java_ast_files"] = sum(s.get("parser") == "javac" for s in self._symbols.values())
        self.provenance["resolution"] = "javac AST with conservative import binding; lexical fallback for other languages"
        digest = hashlib.sha256()
        for path in sorted(self._all_files):
            digest.update(self.relative_path(path).encode())
            digest.update(path.read_bytes())
        self.provenance["content_sha256"] = digest.hexdigest()
        manifest = self.root / "postmortem-source.json"
        if manifest.is_file():
            try:
                declared = json.loads(manifest.read_text())
                valid = declared.get("source_sha256") == digest.hexdigest() and not self.provenance.get("truncated")
                self.provenance.update(manifest_valid=bool(valid), build_id=declared.get("build_id"))
            except (ValueError, OSError):
                self.provenance["manifest_valid"] = False
        try:
            proc = subprocess.run(["git", "-C", str(self.root), "rev-parse", "HEAD"], capture_output=True, text=True, timeout=3)
            if proc.returncode == 0:
                self.provenance["commit"] = proc.stdout.strip()
                status = subprocess.run(["git", "-C", str(self.root), "status", "--porcelain"], capture_output=True, text=True, timeout=3)
                self.provenance["working_tree_dirty"] = bool(status.stdout.strip())
        except (OSError, subprocess.TimeoutExpired):
            pass

    @property
    def classes_indexed(self) -> int:
        return len(self._fqcn_to_path)

    def find_references(self, class_name: str, max_results: int = 20,
                        context_lines: int = 3) -> List[dict]:
        """Find application code that references `class_name`.

        Heap dumps give us *what* is on the heap but not *who* put it there.
        When a class dominates the histogram, this scans the attached source for
        the places your own code names that class — the constructor calls, fields,
        and method signatures most likely responsible — and reports file, method,
        and line for each.

        Returns a list of dicts: {repo_path, line, method, kind, snippet}.
        `kind` is one of: new (constructor), field, type-use, import.
        """
        if not class_name:
            return []

        simple = re.split(r"[$]", class_name, maxsplit=1)[0].rsplit(".", 1)[-1]
        if not simple or len(simple) < 3:
            return []

        # A simple name is resolvable only when the index contains one declared type.
        if "." not in class_name:
            types = [n for n in self._candidates if n.rsplit(".", 1)[-1] == simple]
            if len(types) != 1:
                return []
            class_name = types[0]
        target_package = class_name.rsplit(".", 1)[0] if "." in class_name else ""
        results = []
        for path, symbols in self._symbols.items():
            if not self._unchanged(path): continue
            imports = symbols["imports"]
            explicit = [i for i in imports if i.rsplit(".", 1)[-1] == simple]
            unqualified_ok = (class_name in explicit or
                              (not explicit and symbols["package"] == target_package))
            # Wildcard imports cannot prove a unique binding; leave them unresolved.
            clean = symbols["clean"]
            pattern = rf"(?<![\w.]){re.escape(class_name)}\b"
            if unqualified_ok:
                pattern += rf"|(?<![\w.]){re.escape(simple)}\b"
            for match in re.finditer(pattern, clean):
                line = clean.count("\n", 0, match.start()) + 1
                start = clean.rfind("\n", 0, match.start()) + 1
                prefix = clean[start:match.start()]
                if re.search(r"\b(package|import|class|interface|record|enum)\s+$", prefix):
                    continue
                method = next((m for m in symbols["methods"] if m["start"] <= match.start() <= m["end"]), None)
                kind = "new" if re.search(r"\bnew\s*$", prefix) else ("type-use" if method else "field")
                results.append({"repo_path": self.relative_path(path), "line": line,
                                "method": method["name"] if method else None, "kind": kind,
                                "snippet": self._read_snippet(path, line, context_lines)})
        results.sort(key=lambda r: ({"new": 0, "field": 1, "type-use": 2}[r["kind"]], r["repo_path"], r["line"]))
        return results[:max_results]

    def find_static_field(self, class_name, field_name, context_lines=4):
        return self._field(class_name, field_name, context_lines, static=True)

    def find_field(self, class_name, field_name, context_lines=4):
        return self._field(class_name, field_name, context_lines)

    def _field(self, class_name, field_name, context_lines, static=False):
        resolved = self.lookup(class_name)
        if not resolved:
            return None
        path = resolved[0]
        symbols = self._symbols[path]
        if symbols.get("parser") == "javac":
            fields = [f for f in symbols["fields"] if f["owner"] == class_name and f["name"] == field_name and (not static or f["static"])]
            if len(fields) != 1: return None
            f = fields[0]
            return {"repo_path": self.relative_path(path), "line": f["line"], "snippet": self._read_snippet(path, f["line"], context_lines),
                    "type_hint": f["type"], "is_collection": bool(_COLLECTION_TYPE_RE.search(f["type"]))}
        clean = symbols["clean"]
        for m in re.finditer(rf"\b{re.escape(field_name)}\b\s*(?:[;=:])", clean):
            if any(x["start"] <= m.start() <= x["end"] for x in symbols["methods"]):
                continue
            owner = next((t for t in reversed(symbols["types"]) if t["start"] < m.start() < t["end"]), None)
            if not owner or owner["fqcn"] != class_name:
                continue
            start = max(clean.rfind(";", 0, m.start()), clean.rfind("{", 0, m.start()), clean.rfind("}", 0, m.start())) + 1
            declaration = clean[start:m.end()]
            if static and not re.search(r"\bstatic\b", declaration):
                continue
            if not re.search(r"[\w<>\[\]]+\s+" + re.escape(field_name), declaration):
                continue
            line = clean.count("\n", 0, m.start()) + 1
            return {"repo_path": self.relative_path(path), "line": line,
                    "snippet": self._read_snippet(path, line, context_lines),
                    "type_hint": declaration.strip(), "is_collection": bool(_COLLECTION_TYPE_RE.search(declaration))}
        return None

    def context(self, class_name, method=None, line=None):
        resolved = self.lookup(class_name, line)
        if not resolved:
            return {"resolution": "ambiguous_or_unresolved", "class_name": class_name}
        path, snippet = resolved
        methods = [m for m in self._symbols[path]["methods"] if m["name"] == method]
        if line:
            methods = [m for m in methods if m["line"] <= line <= m["end_line"]]
        result = {"resolution": self._symbols[path].get("parser", "lexical"), "repo_path": self.relative_path(path),
                  "build_verified": False, "source_provenance": self.provenance}
        if len(methods) == 1:
            m = methods[0]
            lines = path.read_text(errors="replace").splitlines()
            result["method"] = {"start_line": m["line"], "end_line": m["end_line"],
                                "lines": lines[m["line"] - 1:min(m["end_line"], m["line"] + 199)],
                                "truncated": m["end_line"] - m["line"] >= 200}
        elif snippet:
            result["snippet"] = snippet.model_dump()
        fields = self._symbols[path].get("fields", [])
        selected_fields = [f for f in fields if f["line"] == line] if line else []
        if selected_fields:
            clean = self._symbols[path]["clean"]
            lines = path.read_text(errors="replace").splitlines()
            related = []
            for m in self._symbols[path]["methods"]:
                body = clean[m["start"]:m["end"]]
                if any(re.search(r"\b" + re.escape(f["name"]) + r"\b", body) for f in selected_fields):
                    related.append({"method": m["name"], "start_line": m["line"],
                                    "lines": lines[m["line"]-1:min(m["end_line"],m["line"]+99)],
                                    "role": "candidate field usage; check shadowing and call paths"})
            result["related_field_methods"] = related[:8]
            result["related_methods_omitted"] = max(0, len(related)-8)
        return result

    def _infer_fqcn(self, path: Path, ext: str) -> Optional[str]:
        """Read the file's package declaration and combine with its filename to form an FQCN."""
        spec = LANG_SPECS[ext]
        pkg_re = spec["package_re"]
        max_scan = spec["max_scan"]
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for i, line in enumerate(f):
                    if i >= max_scan:
                        break
                    m = pkg_re.match(line)
                    if m:
                        return f"{m.group(1)}.{path.stem}"
            # No package declaration — assume default package
            return path.stem
        except OSError:
            return None

    def lookup(self, class_name: str, line: Optional[int] = None,
               context_lines: int = 4) -> Optional[Tuple[Path, Optional[SourceSnippet]]]:
        """
        Resolve a class name to a source file.

        Handles inner classes, lambdas, anonymous classes by stripping at `$`.
        Falls back to simple-name lookup if FQCN doesn't resolve.
        Returns (absolute_path, optional_snippet).
        """
        if not class_name:
            return None

        outer = class_name.split("$", 1)[0]
        # Exact declared symbol, then verified outer symbol for generated classes.
        path = self._fqcn_to_path.get(class_name) or self._fqcn_to_path.get(outer)
        if not path and "." not in class_name:
            candidates = list(set(self._simple_to_paths.get(class_name, [])))
            if len(candidates) == 1:
                path = candidates[0]

        if not path or not self._unchanged(path):
            return None

        snippet = None
        if line and line > 0:
            snippet = self._read_snippet(path, line, context_lines)

        return path, snippet

    def _unchanged(self, path):
        try:
            valid = hashlib.sha256(path.read_bytes()).hexdigest() == self._file_hashes.get(path)
        except OSError:
            valid = False
        if not valid:
            self.provenance["manifest_valid"] = False
            self.provenance["source_changed"] = True
        return valid

    def _read_snippet(self, path: Path, line: int, context: int) -> Optional[SourceSnippet]:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                all_lines = f.readlines()
        except OSError:
            return None

        if not all_lines or line > len(all_lines):
            return None

        start = max(1, line - context)
        end = min(len(all_lines), line + context)
        # Convert to 0-based indices
        slice_ = all_lines[start - 1: end]
        return SourceSnippet(
            start_line=start,
            highlight_line=line,
            lines=[l.rstrip("\n").rstrip("\r") for l in slice_],
        )

    def relative_path(self, abs_path: Path) -> str:
        try:
            return str(abs_path.relative_to(self.root))
        except ValueError:
            return str(abs_path)


# --- "User code" classification ---

# Frames whose fully-qualified class name starts with one of these are considered
# library/JDK code, not the user's own application code.
_NON_USER_PREFIXES = (
    "java.", "javax.", "jdk.", "sun.", "com.sun.",
    "kotlin.", "kotlinx.", "scala.",
    # Big frameworks
    "org.springframework.", "org.hibernate.", "org.apache.",
    "io.netty.", "io.micrometer.", "io.opentelemetry.",
    "ch.qos.logback.", "org.slf4j.", "org.jboss.",
    "com.zaxxer.hikari.",
    "reactor.", "rx.", "io.reactivex.",
    "feign.", "okhttp3.", "retrofit2.",
    "com.fasterxml.", "com.google.",
)


# Java primitive type names. These surface as the element base of primitive
# arrays (e.g. `byte[]` -> `byte`) and must never count as application code —
# otherwise a heap leaf picker would trace toward `byte[]` instead of the real
# user class that owns those bytes.
_PRIMITIVE_NAMES = frozenset(
    ("boolean", "byte", "char", "short", "int", "long", "float", "double", "void")
)


def is_user_code(class_name: str) -> bool:
    """Heuristic for whether a stack frame is application code vs framework/JDK."""
    if not class_name:
        return False
    if class_name in _PRIMITIVE_NAMES:
        return False
    return not class_name.startswith(_NON_USER_PREFIXES)


def first_user_frame(stack) -> Optional[int]:
    """Index of the first frame in user code, or None if all frames are library code.

    `stack` is a list of objects with `.class_name`. Accepts pydantic models or dicts.
    """
    for i, f in enumerate(stack):
        cn = getattr(f, "class_name", None) or (f.get("class_name") if isinstance(f, dict) else None)
        if cn and is_user_code(cn):
            return i
    return None
