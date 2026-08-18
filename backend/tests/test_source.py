"""Source indexer: FQCN resolution, field/reference lookup, user-code heuristic."""
from app.analyzers.source import is_user_code, first_user_frame


def test_indexes_java_and_kotlin(source_index):
    assert source_index.files_indexed >= 8
    assert source_index.classes_indexed >= 8
    assert ".java" in source_index.languages
    assert ".kt" in source_index.languages


def test_lookup_resolves_fqcn_to_file(source_index):
    resolved = source_index.lookup("com.example.Order")
    assert resolved is not None
    path, _ = resolved
    assert path.name == "Order.java"


def test_lookup_strips_inner_class_suffix(source_index):
    resolved = source_index.lookup("com.example.Order$Builder")
    assert resolved is not None and resolved[0].name == "Order.java"


def test_lookup_returns_snippet_around_line(source_index):
    path, snippet = source_index.lookup("com.example.Order", 8, context_lines=2)
    assert snippet is not None
    assert snippet.highlight_line == 8
    assert 6 <= snippet.start_line <= 8
    assert len(snippet.lines) >= 1


def test_kotlin_package_resolves(source_index):
    resolved = source_index.lookup("com.example.util.Cache")
    assert resolved is not None and resolved[0].name == "Cache.kt"


def test_find_static_field_detects_collection(source_index):
    info = source_index.find_static_field("com.example.SessionRegistry", "SESSIONS")
    assert info is not None
    assert info["is_collection"] is True
    assert info["repo_path"].endswith("SessionRegistry.java")
    assert "SESSIONS" in info["snippet"].lines[info["snippet"].highlight_line - info["snippet"].start_line]


def test_find_static_field_logger_is_not_collection(source_index):
    info = source_index.find_static_field("com.example.SessionRegistry", "LOG")
    assert info is not None
    assert info["is_collection"] is False


def test_find_field_resolves_instance_field(source_index):
    info = source_index.find_field("com.example.OrderCache", "entries")
    assert info is not None
    assert info["is_collection"] is True
    assert info["repo_path"].endswith("OrderCache.java")


def test_find_references_finds_constructor(source_index):
    refs = source_index.find_references("Order")
    assert refs, "expected Order to be referenced in the fixture repo"
    # OrderService.loadAll does `new Order(...)` — a constructor (kind=new) hit.
    kinds = {r["kind"] for r in refs}
    assert "new" in kinds
    paths = {r["repo_path"] for r in refs}
    assert any(p.endswith("OrderService.java") for p in paths)


def test_user_code_heuristic():
    assert is_user_code("com.example.Order") is True
    assert is_user_code("java.util.HashMap") is False
    assert is_user_code("org.springframework.web.X") is False
    assert is_user_code("io.netty.Foo") is False
    assert is_user_code("") is False
    # Bare primitive names (the element base of primitive arrays like `byte[]`)
    # must never count as user code, or the retention tracer's leaf picker would
    # trace toward `byte[]` instead of the real user class that owns those bytes.
    for prim in ("byte", "int", "long", "char", "boolean", "short", "float", "double", "void"):
        assert is_user_code(prim) is False


def test_first_user_frame_skips_library():
    class F:
        def __init__(self, cn):
            self.class_name = cn
    stack = [F("java.lang.Thread"), F("jdk.internal.X"), F("com.example.OrderService")]
    assert first_user_frame(stack) == 2
    assert first_user_frame([F("java.lang.Object")]) is None
