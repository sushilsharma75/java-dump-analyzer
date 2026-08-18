"""
Tests for deployment (classloader / WAR) and thread attribution.

These construct exact .hprof byte streams with `HprofBuilder` — classes carrying
a classloader id and protection domain, a resolvable CodeSource `.war` URL, and
live thread objects — then assert the parser attributes each thread to the right
deployment and flags a stale, thread-pinned classloader.
"""
import io

from app.analyzers.heap_dump import parse_heap_dump
from tests.hprof_builder import HprofBuilder, OBJECT, INT, BOOLEAN, BYTE


# java.lang.Thread field layout we emit (pre-JDK-19: fields live directly on Thread).
_THREAD_FIELDS = [
    ("name", OBJECT),
    ("priority", INT),
    ("daemon", BOOLEAN),
    ("target", OBJECT),
    ("contextClassLoader", OBJECT),
]


def _scaffold(b: HprofBuilder):
    """Emit the common JDK classes and return their ids."""
    obj = b.load_class("java.lang.Object")
    b.class_dump(obj)

    string_cls = b.load_class("java.lang.String")
    b.class_dump(string_cls, super_id=obj,
                 instance_fields=[("value", OBJECT), ("coder", BYTE)])

    classloader = b.load_class("java.lang.ClassLoader")
    b.class_dump(classloader, super_id=obj)

    thread = b.load_class("java.lang.Thread")
    b.class_dump(thread, super_id=obj, instance_fields=_THREAD_FIELDS)

    # protection-domain chain classes
    pd_cls = b.load_class("java.security.ProtectionDomain")
    b.class_dump(pd_cls, super_id=obj, instance_fields=[("codesource", OBJECT)])
    cs_cls = b.load_class("java.security.CodeSource")
    b.class_dump(cs_cls, super_id=obj, instance_fields=[("location", OBJECT)])
    url_cls = b.load_class("java.net.URL")
    b.class_dump(url_cls, super_id=obj, instance_fields=[("file", OBJECT)])

    return obj, string_cls, classloader, thread, pd_cls, cs_cls, url_cls


def _code_source(b, pd_cls, cs_cls, url_cls, string_cls, war_url: str):
    """Build ProtectionDomain -> CodeSource -> URL -> String(war path). Returns pd oid."""
    file_str = b.java_string(war_url, string_cls)
    url = b.instance(url_cls, body=b.pack_fields([(OBJECT, file_str)]))
    cs = b.instance(cs_cls, body=b.pack_fields([(OBJECT, url)]))
    pd = b.instance(pd_cls, body=b.pack_fields([(OBJECT, cs)]))
    return pd


def _webapp_loader(b, classloader, string_cls, context_name: str):
    """A Tomcat-style named webapp classloader instance. Returns (class_id, oid)."""
    wcls = b.load_class("org.apache.catalina.loader.ParallelWebappClassLoader")
    b.class_dump(wcls, super_id=classloader, instance_fields=[("contextName", OBJECT)])
    ctx = b.java_string(context_name, string_cls)
    oid = b.instance(wcls, body=b.pack_fields([(OBJECT, ctx)]))
    return wcls, oid


def _thread(b, thread_cls, string_cls, name, *, daemon, target=0, tccl=0,
            live=True, class_id=None):
    class_id = class_id or thread_cls
    name_str = b.java_string(name, string_cls)
    oid = b.instance(class_id, body=b.pack_fields([
        (OBJECT, name_str), (INT, 5), (BOOLEAN, daemon), (OBJECT, target), (OBJECT, tccl),
    ]))
    if live:
        b.gc_root(oid, kind="thread_obj")
    return oid


def _parse(b: HprofBuilder):
    return parse_heap_dump(io.BytesIO(b.build()))


def test_thread_attributed_to_war_by_own_class():
    b = HprofBuilder()
    _obj, string_cls, classloader, thread, pd_cls, cs_cls, url_cls = _scaffold(b)

    pd = _code_source(b, pd_cls, cs_cls, url_cls, string_cls,
                      "file:/opt/tomcat/webapps/billing.war!/WEB-INF/classes/")
    _wcls, loader = _webapp_loader(b, classloader, string_cls, "billing")

    # A Thread subclass loaded BY the webapp loader — attribution via own-class.
    report = b.load_class("com.acme.billing.ReportThread")
    b.class_dump(report, super_id=thread, loader_id=loader, protection_domain_id=pd)
    _thread(b, thread, string_cls, "billing-report-0", daemon=False, class_id=report)

    a = _parse(b)

    assert len(a.deployments) == 1
    dep = a.deployments[0]
    assert dep.is_webapp
    assert dep.artifact == "billing.war"
    assert dep.name == "billing"
    assert dep.code_source.endswith("billing.war!/WEB-INF/classes/")
    assert dep.live_thread_count == 1

    th = a.thread_ownership
    assert th.live_threads == 1
    assert th.application == 1
    assert th.by_deployment == {dep.id: 1}
    t0 = th.threads[0]
    assert t0.name == "billing-report-0"
    assert t0.attribution == "own-class"
    assert t0.deployment_id == dep.id
    assert t0.is_user_code


def test_thread_attributed_by_context_classloader():
    b = HprofBuilder()
    _obj, string_cls, classloader, thread, pd_cls, cs_cls, url_cls = _scaffold(b)
    pd = _code_source(b, pd_cls, cs_cls, url_cls, string_cls,
                      "file:/opt/tomcat/webapps/reporting.war!/WEB-INF/classes/")
    _wcls, loader = _webapp_loader(b, classloader, string_cls, "reporting")
    # give the loader at least one class so it becomes a deployment
    user = b.load_class("com.acme.reporting.Service")
    b.class_dump(user, loader_id=loader, protection_domain_id=pd)

    # A plain java.lang.Thread whose *context* classloader is the webapp loader.
    _thread(b, thread, string_cls, "reporting-pool-1", daemon=True, tccl=loader)

    a = _parse(b)
    t0 = a.thread_ownership.threads[0]
    assert t0.attribution == "context-classloader"
    assert a.deployments[0].artifact == "reporting.war"
    assert t0.deployment_id == a.deployments[0].id


def test_system_tccl_does_not_attribute():
    """A thread whose TCCL is the AppClassLoader must NOT be swept into a deployment
    — every thread inherits that loader by default, so it carries no signal."""
    b = HprofBuilder()
    _obj, string_cls, classloader, thread, *_ = _scaffold(b)
    app = b.load_class("jdk.internal.loader.ClassLoaders$AppClassLoader")
    b.class_dump(app, super_id=classloader)
    app_oid = b.instance(app)
    # A class loaded by the app loader so it registers as a (non-webapp) deployment.
    main_cls = b.load_class("com.acme.Main")
    b.class_dump(main_cls, loader_id=app_oid)

    _thread(b, thread, string_cls, "main", daemon=False, tccl=app_oid)

    a = _parse(b)
    t0 = a.thread_ownership.threads[0]
    assert t0.attribution == "unattributed"
    assert t0.deployment_id is None


def test_stale_classloader_pinned_by_thread_is_critical():
    """Two live loaders for the same WAR, the older pinned by a running thread —
    the redeploy leak. Must surface as a CRITICAL classloader-leak finding."""
    b = HprofBuilder()
    _obj, string_cls, classloader, thread, pd_cls, cs_cls, url_cls = _scaffold(b)

    war = "file:/opt/tomcat/webapps/billing.war!/WEB-INF/classes/"
    for ctx_label, live_thread in (("v1", True), ("v2", True)):
        pd = _code_source(b, pd_cls, cs_cls, url_cls, string_cls, war)
        _wcls, loader = _webapp_loader(b, classloader, string_cls, "billing")
        rt = b.load_class(f"com.acme.billing.Worker_{ctx_label}")
        b.class_dump(rt, super_id=thread, loader_id=loader, protection_domain_id=pd)
        _thread(b, thread, string_cls, f"billing-{ctx_label}-worker",
                daemon=False, class_id=rt, live=live_thread)

    a = _parse(b)

    stale = [d for d in a.deployments if d.stale]
    assert len(stale) == 2, "both loaders serving billing.war should be marked stale"

    crit = [f for f in a.findings
            if f.severity.value == "critical" and f.category == "classloader-leak"]
    assert crit, "expected a CRITICAL classloader-leak finding"
    assert "pinned" in crit[0].title.lower()


def test_no_deployments_when_all_bootstrap():
    """A plain dump with no user classloaders yields no deployments and no crash —
    this is the common case and must stay quiet."""
    b = HprofBuilder()
    leaf = b.load_class("com.example.Leaf")
    b.class_dump(leaf)                      # loader_id defaults to 0 (bootstrap)
    for _ in range(5):
        b.instance(leaf)
    a = _parse(b)
    assert a.deployments == []
    assert a.thread_ownership is not None
    assert a.thread_ownership.total_threads == 0
