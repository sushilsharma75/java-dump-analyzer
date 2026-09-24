"""What the server log adds to a heap dump: OOMs, lifecycle, heap-derived matching, timeline."""
import io
from datetime import datetime, timedelta

from app.analyzers import server_log
from app.analyzers.incident import analyze_incident
from app.analyzers.source import SourceIndex


def _log():
    lines = [
        '2026-09-23 08:00:00.000+00:00 INFO [main] org.apache.catalina.startup.HostConfig - Deploying web application archive [/opt/tomcat/webapps/orders.war]',
        '2026-09-23 08:00:05.000+00:00 INFO [main] org.apache.catalina.startup.Catalina - Server startup in [5123] milliseconds',
        '2026-09-23 08:30:00.000+00:00 INFO [main] org.apache.catalina.startup.HostConfig - Undeploying context [/orders]',
        '2026-09-23 08:30:02.000+00:00 INFO [main] org.apache.catalina.startup.HostConfig - Deploying web application archive [/opt/tomcat/webapps/orders.war]',
    ]
    # A quiet baseline, then an error burst in the 30 minutes before the 10:00 capture.
    for step in range(9):
        at = datetime(2026, 9, 23, 8, 0, 30) + timedelta(minutes=10 * step)
        lines.append(f'{at:%Y-%m-%d %H:%M:%S}.000+00:00 ERROR [worker-9] com.acme.Web - baseline')
    for minute in range(30, 60):
        lines.append(f'2026-09-23 09:{minute:02d}:10.000+00:00 ERROR [http-nio-8080-exec-7] com.acme.Web - request failed')
    lines += [
        '2026-09-23 09:57:00.000+00:00 ERROR [http-nio-8080-exec-7] com.acme.Web - request failed',
        'javax.servlet.ServletException: handler failed',
        'Caused by: java.lang.OutOfMemoryError: Java heap space',
        '\tat java.util.Arrays.copyOf(Arrays.java:3512)',
        '\tat com.acme.OrderCache.put(OrderCache.java:4)',
        '\tat com.acme.OrderService.save(OrderService.java:10)',
        '2026-09-23 09:57:01.000+00:00 INFO [main] java.lang.Runtime - Dumping heap to /tmp/java_pid42.hprof ...',
        '2026-09-23 09:58:00.000+00:00 INFO [report-thread] com.acme.Report - report generated',
    ]
    return ('\n'.join(lines) + '\n').encode()


def _heap():
    return {'analysis_id': 'c' * 32, 'capture': {'captured_at': '2026-09-23T10:00:00Z'},
            'top_classes_by_size': [{'class_name': 'byte[]', 'instance_count': 10}],
            'findings': [{'title': 'Retention path: OrderCache.entries holds 80% of the heap', 'evidence_id': 'E-1',
                          'source_locations': [{'class_name': 'com.acme.OrderCache', 'method': 'entries'}]}],
            'thread_ownership': {'threads': [{'name': 'report-thread', 'class_name': 'com.acme.ReportThread', 'live': True}]},
            'deployments': [{'id': '0x1', 'artifact': 'orders.war', 'name': '/orders', 'is_webapp': True, 'stale': True, 'live_thread_count': 1},
                            {'id': '0x2', 'artifact': 'orders.war', 'name': '/orders', 'is_webapp': True, 'stale': True}]}


def _run(tmp_path, raw=None, heap=None, source=None, name='log.sqlite'):
    path = tmp_path / name
    report = server_log.build_log_index(io.BytesIO(raw or _log()), path)
    report['analysis_id'] = 'a' * 32
    return report, analyze_incident(report, path, heap=heap or _heap(), source=source, window_seconds=7200)


def _titled(result, text):
    return [f for f in result['findings'] if text in f['title']]


def test_oom_finding_names_kind_timing_and_application_frame(tmp_path):
    src = tmp_path / 'src'
    src.mkdir()
    (src / 'OrderCache.java').write_text('package com.acme;\nclass OrderCache {\n java.util.List<byte[]> entries;\n void put(byte[] b) { entries.add(b); }\n}\n')
    source = SourceIndex(src)
    source.build()
    report, result = _run(tmp_path, source=source)
    assert report['markers'] == {'deploy': 2, 'undeploy': 1, 'server_start': 1, 'oom': 1, 'heap_dump': 1}
    oom = _titled(result, 'OutOfMemoryError: Java heap space')[0]
    assert oom['severity'] == 'critical'
    assert '3 min before the heap capture' in oom['title']
    assert any('com.acme.OrderCache.put:4' in e for e in oom['evidence'])
    assert any('com.acme.OrderCache (heap finding)' in e for e in oom['evidence'])
    loc = oom['source_locations'][0]
    assert loc['repo_path'] == 'OrderCache.java' and loc['snippet'] and loc['role'] == 'oom_stack_frame'
    assert result['memory_events'][0]['count'] == 1
    assert result['summary'].startswith('1 OutOfMemoryError (Java heap space) in the log')


def test_redeploy_leak_and_automatic_dump_are_corroborated(tmp_path):
    _, result = _run(tmp_path)
    leak = _titled(result, 'Redeploy leak corroborated by the log: orders deployed 2×')[0]
    assert leak['severity'] == 'critical'
    assert _titled(result, 'automatic heap dump at the time of this capture')


def test_restart_between_oom_and_capture_is_flagged(tmp_path):
    raw = _log() + b'2026-09-23 09:59:00.000+00:00 INFO [main] org.apache.catalina.startup.Catalina - Server startup in [4000] milliseconds\n'
    _, result = _run(tmp_path, raw=raw)
    assert _titled(result, 'Server restarted after the OutOfMemoryError')
    heap = {**_heap(), 'deployments': [{'artifact': 'orders.war', 'is_webapp': True}]}
    _, clean = _run(tmp_path, heap=heap, name='clean.sqlite')
    assert not _titled(clean, 'Server restarted')
    assert _titled(clean, 'orders was redeployed 2× and the heap holds a single classloader')


def test_heap_finding_classes_and_heap_threads_rank_matches(tmp_path):
    _, result = _run(tmp_path)
    top = result['matches'][0]
    assert top['event']['exception'] == 'java.lang.OutOfMemoryError'
    assert any('OutOfMemoryError' in text for text in top['explanation'])
    assert any('named by the heap finding' in text for text in top['explanation'])
    thread_match = next(m for m in result['matches'] if m['event']['thread'] == 'report-thread')
    assert any(l['kind'] == 'heap_thread_name' for l in thread_match['links'])
    scores = [m['score'] for m in result['matches']]
    assert scores == sorted(scores, reverse=True)


def test_timeline_buckets_and_error_rise(tmp_path):
    _, result = _run(tmp_path)
    line = result['timeline']
    assert line['basis'] == 'UTC' and line['bucket_minutes'] == 10
    assert line['captures'][0]['bucket'].startswith('2026-09-23T10:00')
    oom_bucket = next(b for b in line['buckets'] if b['start'].startswith('2026-09-23T09:50'))
    assert oom_bucket['oom'] == 1 and oom_bucket['errors'] >= 10
    assert _titled(result, 'Errors rose to')


def test_unaligned_log_still_yields_oom_and_local_timeline(tmp_path):
    raw = _log().replace(b'.000+00:00', b'.000')
    _, result = _run(tmp_path, raw=raw)
    oom = _titled(result, 'OutOfMemoryError: Java heap space')[0]
    assert 'capture' not in oom['title']
    assert result['timeline']['basis'].startswith('log local time')
    assert not _titled(result, 'Errors rose to')


def test_legacy_index_without_markers_recovers_oom(tmp_path):
    path = tmp_path / 'log.sqlite'
    report = server_log.build_log_index(io.BytesIO(_log()), path)
    report['analysis_id'] = 'a' * 32
    db = server_log.connect(path)
    db.execute('DROP TABLE markers')
    db.commit()
    db.close()
    result = analyze_incident(report, path, heap=_heap(), window_seconds=7200)
    assert _titled(result, 'OutOfMemoryError: Java heap space')
    assert _titled(result, 'Redeploy leak corroborated')
    assert any('indexed before memory/lifecycle event extraction' in n for n in result['limitations'])
