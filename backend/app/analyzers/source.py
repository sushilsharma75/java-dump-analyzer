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

    def build(self) -> None:
        """Walk the repo and populate the indexes."""
        count = 0
        for dirpath, dirnames, filenames in os.walk(self.root):
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

                fqcn = self._infer_fqcn(path, ext)
                simple = path.stem  # filename without extension

                if fqcn:
                    self._fqcn_to_path[fqcn] = path
                # Always register simple-name fallback
                self._simple_to_paths.setdefault(simple, []).append(path)
                self._all_files.append(path)

                self.languages[ext] = self.languages.get(ext, 0) + 1
                count += 1
                if count >= MAX_FILES:
                    self.files_indexed = count
                    return

        self.files_indexed = count

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

        # Whole-word match on the simple class name
        word_re = re.compile(rf"\b{re.escape(simple)}\b")
        # Classify the kind of reference for ranking/labelling
        new_re = re.compile(rf"\bnew\s+{re.escape(simple)}\b")
        import_re = re.compile(rf"\bimport\s+.*\b{re.escape(simple)}\b")
        # A method/ctor signature line (very rough): visibility/return ... name( ... )
        method_sig_re = re.compile(
            r"^\s*(?:public|private|protected|static|final|synchronized|abstract|\s)*"
            r"[\w<>\[\],.\s?&]+\s+(\w+)\s*\([^;]*\)\s*(?:throws[\w,\s.]*)?\{?\s*$"
        )

        results: List[dict] = []
        for path in self._all_files:
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    lines = f.readlines()
            except OSError:
                continue

            for i, line in enumerate(lines):
                if not word_re.search(line):
                    continue
                # Skip the class's own declaration file noise: a line that's just
                # 'package' or the class definition itself is low-value.
                stripped = line.strip()
                if stripped.startswith("package "):
                    continue

                if import_re.search(line):
                    kind = "import"
                elif new_re.search(line):
                    kind = "new"
                elif re.search(rf"\b{re.escape(simple)}\s*<", line) or \
                        re.search(rf"\b{re.escape(simple)}\s+\w+\s*[;=]", line):
                    kind = "field"
                else:
                    kind = "type-use"

                # Walk backward to find the enclosing method signature
                method = None
                for j in range(i, max(-1, i - 80), -1):
                    m = method_sig_re.match(lines[j])
                    if m and m.group(1) not in ("if", "for", "while", "switch", "catch", "return"):
                        method = m.group(1)
                        break

                lineno = i + 1
                start = max(1, lineno - context_lines)
                end = min(len(lines), lineno + context_lines)
                snippet = {
                    "start_line": start,
                    "highlight_line": lineno,
                    "lines": [l.rstrip("\n").rstrip("\r") for l in lines[start - 1:end]],
                }
                results.append({
                    "repo_path": self.relative_path(path),
                    "line": lineno,
                    "method": method,
                    "kind": kind,
                    "snippet": snippet,
                })

        # Rank: constructor calls first (most likely the allocator), then fields,
        # then other type uses, then imports. Cap the result set.
        kind_rank = {"new": 0, "field": 1, "type-use": 2, "import": 3}
        results.sort(key=lambda r: kind_rank.get(r["kind"], 9))
        return results[:max_results]

    def find_static_field(self, class_name: str, field_name: str,
                          context_lines: int = 4) -> Optional[dict]:
        """Resolve a class's static field to its declaration line in source.

        Heap dumps tell us a static field holds a live object, but not *where*
        it's declared. This opens the class's own file, finds the line that
        declares `field_name`, and reports the file, line, a code snippet, and
        whether the declared type looks like a collection/cache (the strong
        leak signal). Returns None if the class or field can't be located.

        Result dict: {repo_path, line, snippet, type_hint, is_collection}.
        """
        if not class_name or not field_name:
            return None
        resolved = self.lookup(class_name)  # (path, snippet) — snippet None w/o line
        if not resolved:
            return None
        path = resolved[0]
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except OSError:
            return None

        field_re = re.compile(rf"\b{re.escape(field_name)}\b")
        decl_line: Optional[int] = None    # a line that also declares the field
        fallback_line: Optional[int] = None  # first mention, if no clear decl found
        for i, line in enumerate(lines):
            if not field_re.search(line):
                continue
            stripped = line.lstrip()
            if stripped.startswith(("//", "*", "/*", "@")):
                continue  # comment / annotation noise
            if fallback_line is None:
                fallback_line = i + 1
            # A declaration line: Java `static`, or Kotlin/Scala `val`/`var`/`object`.
            if re.search(r"\bstatic\b", line) or re.search(r"\b(?:val|var|object)\b", line):
                decl_line = i + 1
                break

        lineno = decl_line or fallback_line
        if lineno is None:
            return None

        type_hint = lines[lineno - 1].strip()
        return {
            "repo_path": self.relative_path(path),
            "line": lineno,
            "snippet": self._read_snippet(path, lineno, context_lines),
            "type_hint": type_hint,
            "is_collection": bool(_COLLECTION_TYPE_RE.search(type_hint)),
        }

    def find_field(self, class_name: str, field_name: str,
                   context_lines: int = 4) -> Optional[dict]:
        """Resolve any field (static OR instance) of a class to its declaration.

        Like `find_static_field`, but recognizes plain instance-field declarations
        (`private Map<...> sessions = ...`) as well as `static`/`val`/`var`. Used by
        the retention tracer, which surfaces instance fields that hold a leak.

        Result dict: {repo_path, line, snippet, type_hint, is_collection}.
        """
        if not class_name or not field_name:
            return None
        resolved = self.lookup(class_name)
        if not resolved:
            return None
        path = resolved[0]
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except OSError:
            return None

        field_re = re.compile(rf"\b{re.escape(field_name)}\b")
        # A field declaration: ... <field> <;|=>  — a type precedes the name and a
        # terminator/initializer follows. Excludes method calls and parameters.
        decl_re = re.compile(
            rf"^\s*(?:@\w+[^\n]*\s+)?(?:public|private|protected|static|final|"
            rf"volatile|transient|val|var|\s)*[\w.$<>,\[\]\s?]+\b{re.escape(field_name)}\b\s*[;=]"
        )
        decl_line: Optional[int] = None
        fallback_line: Optional[int] = None
        for i, line in enumerate(lines):
            if not field_re.search(line):
                continue
            stripped = line.lstrip()
            if stripped.startswith(("//", "*", "/*")):
                continue
            if fallback_line is None:
                fallback_line = i + 1
            if decl_re.match(line):
                decl_line = i + 1
                break

        lineno = decl_line or fallback_line
        if lineno is None:
            return None
        type_hint = lines[lineno - 1].strip()
        return {
            "repo_path": self.relative_path(path),
            "line": lineno,
            "snippet": self._read_snippet(path, lineno, context_lines),
            "type_hint": type_hint,
            "is_collection": bool(_COLLECTION_TYPE_RE.search(type_hint)),
        }

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

        # Strip inner class suffix: com.example.Foo$Bar -> com.example.Foo, Foo$$Lambda$1 -> Foo
        outer = re.split(r"[$]", class_name, maxsplit=1)[0]
        path = self._fqcn_to_path.get(outer)

        if not path:
            # Fallback to simple name (just the last segment)
            simple = outer.rsplit(".", 1)[-1]
            candidates = self._simple_to_paths.get(simple, [])
            if len(candidates) == 1:
                path = candidates[0]
            elif len(candidates) > 1:
                # Ambiguous — pick the one whose path segments most overlap with the FQCN
                want_segments = outer.split(".")
                best = max(candidates, key=lambda p: sum(
                    1 for s in want_segments if s in p.parts
                ))
                path = best

        if not path:
            return None

        snippet = None
        if line and line > 0:
            snippet = self._read_snippet(path, line, context_lines)

        return path, snippet

    def _read_snippet(self, path: Path, line: int, context: int) -> Optional[SourceSnippet]:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                all_lines = f.readlines()
        except OSError:
            return None

        if not all_lines:
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
