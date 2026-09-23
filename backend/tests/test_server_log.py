import hashlib
import io
import json

import pytest

from app.analyzers import server_log
from app.analyzers.incident import analyze_incident
from app.analyzers.source import SourceIndex

LOG = b'''2026-09-22 12:00:00.000+00:00 INFO [worker-1] com.example.Cache - requestId=r1 traceId=t1 started
2026-09-22 12:00:01.000+00:00 ERROR [worker-1] com.example.Cache - requestId=r1 failed
java.lang.IllegalStateException: failed
    at com.example.Cache.put(Cache.java:4) ~[app.jar:1.0]
Caused by: java.io.IOException: broken
    at java.base/java.io.Reader.read(Reader.java:10)
    ... 2 more
2026-09-22 12:01:00.000+00:00 WARN [worker-2] com.example.Other - retry
'''


@pytest.fixture
def indexed(tmp_path):
    path = tmp_path / 'log.sqlite'
    result = server_log.build_log_index(io.BytesIO(LOG), path)
    result['analysis_id'] = 'a' * 32
    return result, path


def test_multiline_and_filters(indexed):
    result, path = indexed
    assert result['counts']['lines'] == 8
    assert result['counts']['events'] == 3
    assert result['sha256'] == hashlib.sha256(LOG).hexdigest()
    events = server_log.search_events(path, result['analysis_id'], level='ERROR')['events']
    assert len(events) == 1
    event = events[0]
    assert event['start_line'] == 2 and event['end_line'] == 7
    assert event['exception'] == 'java.io.IOException'
    assert event['frames'][0]['class_name'] == 'com.example.Cache'
    assert event['frames'][1]['class_name'] == 'java.io.Reader'
    assert event['request_id'] == 'r1'
    assert event['logger'] == 'com.example.Cache'
    assert event['thread'] == 'worker-1'
    page = server_log.search_events(path, result['analysis_id'], limit=1)
    assert page['next_cursor'] == 1
    assert server_log.search_events(path, result['analysis_id'], after=1, limit=1)['events'][0]['id'] == 2
    assert len(server_log.search_events(path, result['analysis_id'], request_id='r1')['events']) == 2
    assert not server_log.search_events(path, result['analysis_id'], query='%')['events']


def test_json_lines_and_timezone(tmp_path):
    raw = json.dumps({'timestamp': '2026-09-22T12:00:00', 'level': 'error', 'thread_name': 'pool-1',
                      'traceId': 'abc', 'message': 'broken', 'stack_trace': 'java.io.IOException: bad\n\tat com.example.Cache.put(Cache.java:4)'}).encode() + b'\n'
    path = tmp_path / 'a.sqlite'
    report = server_log.build_log_index(io.BytesIO(raw), path)
    assert report['counts']['unaligned_timestamps'] == 1
    event = server_log.search_events(path, 'abc')['events'][0]
    assert event['trace_id'] == 'abc' and len(event['frames']) == 1
    assert event['timestamp'] is None
    assert server_log.parse_time('2026-09-22T12:00:00', '+05:30') == '2026-09-22T06:30:00.000+00:00'
    assert server_log.parse_time('2026-09-22T12:00:00Z') == '2026-09-22T12:00:00.000+00:00'


def test_bounded_reads_and_oversized_lines(tmp_path):
    class Bounded(io.BytesIO):
        def readline(self, n=-1):
            assert 0 < n <= server_log.LINE_BYTES
            return super().readline(n)
    raw = b'x' * (server_log.LINE_BYTES * 3) + b'\n' + LOG
    result = server_log.build_log_index(Bounded(raw), tmp_path / 'log.sqlite')
    assert result['counts']['bytes'] == len(raw)
    assert result['sha256'] == hashlib.sha256(raw).hexdigest()
    assert result['counts']['oversized_lines'] == 1
    assert result['counts']['truncated_events'] == 1
    assert result['counts']['events'] == 4


def test_cancellation_closes_index(tmp_path):
    with pytest.raises(server_log.Cancelled):
        server_log.build_log_index(io.BytesIO(LOG), tmp_path / 'log.sqlite', cancelled=lambda: True)
    (tmp_path / 'log.sqlite').unlink()  # Windows also requires closed handles.


def test_frame_and_event_limits_are_visible(tmp_path):
    raw = b'ERROR failed\n' + b'\tat a.b.C.run(C.java:1)\n' * 300
    result = server_log.build_log_index(io.BytesIO(raw), tmp_path / 'log.sqlite')
    assert result['counts']['omitted_frames'] > 0
    assert result['counts']['truncated_events'] > 0
    assert result['counts']['lines'] == 301


def test_incident_matches_recorded_frames_to_dump_and_source(indexed, tmp_path):
    report, path = indexed
    src = tmp_path / 'src'
    src.mkdir()
    (src / 'Cache.java').write_text('package com.example;\nclass Cache {\n Object value;\n void put() { value = new Object(); }\n}\n')
    source = SourceIndex(src)
    source.build()
    capture = {'process_id': 'jvm1', 'build_id': 'v1', 'process_start': '2026-09-22T10:00:00Z', 'captured_at': '2026-09-22T12:00:02Z'}
    report['capture'] = capture
    thread = {'analysis_id': 'b' * 32, 'capture': capture, 'threads': [{'name': 'worker-1', 'stack': [
        {'class_name': 'com.example.Cache', 'method': 'put', 'line': 4}]}]}
    heap = {'analysis_id': 'c' * 32, 'capture': capture, 'top_classes_by_size': [{'class_name': 'com.example.Cache', 'instance_count': 10}], 'findings': []}
    combined = analyze_incident(report, path, heap=heap, thread=thread, source=source)
    assert combined['status'] == 'completed'
    event = next(m for m in combined['matches'] if m['event']['id'] == 2)
    assert any(link['kind'] == 'same_class_and_method' for link in event['links'])
    assert any(link['kind'] == 'heap_class_overlap' for link in event['links'])
    assert event['event']['frames'][0]['source']['repo_path'] == 'Cache.java'
    assert event['aligned_with'] == ['heap', 'thread']
    assert combined['coverage']['time_filter_applied']
    thread['capture'] = {**capture, 'process_id': 'other'}
    assert analyze_incident(report, path, thread=thread)['status'] == 'incompatible'


def test_out_of_window_events_are_labelled_unaligned(indexed):
    report, path = indexed
    thread = {'capture': {'captured_at': '2026-09-23T12:00:00Z'}, 'threads': [{'name': 'worker-1', 'stack': []}]}
    combined = analyze_incident(report, path, thread=thread)
    assert combined['coverage']['time_filter_fallback']
    assert not combined['coverage']['time_filter_applied']
    assert combined['matches'], 'whole-log matches are shown instead of an empty report'
    assert all(m['aligned_with'] == [] and m['confidence'] == 'low' for m in combined['matches'])
    assert any('±300 s' in note for note in combined['limitations'])


def test_log_without_timezone_offset_still_correlates(tmp_path):
    """Default Logback/Log4j timestamps carry no offset; they must not be filtered out."""
    raw = LOG.replace(b'.000+00:00', b'.000')
    report = server_log.build_log_index(io.BytesIO(raw), tmp_path / 'log.sqlite')
    report['analysis_id'] = 'a' * 32
    assert report['time_range']['aligned_events'] == 0
    heap = {'analysis_id': 'c' * 32, 'capture': {'captured_at': '2026-09-22T12:00:02Z'},
            'top_classes_by_size': [{'class_name': 'com.example.Cache', 'instance_count': 10}]}
    combined = analyze_incident(report, tmp_path / 'log.sqlite', heap=heap)
    assert combined['coverage']['matching_events'] == 2
    assert not combined['coverage']['time_filter_applied']
    assert any('timezone-aligned' in note for note in combined['limitations'])
    assert all(m['confidence'] == 'low' for m in combined['matches'])


def test_jdk_histogram_classes_do_not_match_log_frames(tmp_path):
    raw = b'2026-09-22 12:00:01.000+00:00 ERROR [w] com.example.Svc - failed\n\tat java.lang.String.format(String.java:1)\n'
    report = server_log.build_log_index(io.BytesIO(raw), tmp_path / 'log.sqlite')
    report['analysis_id'] = 'a' * 32
    heap = {'analysis_id': 'c' * 32, 'capture': {'captured_at': '2026-09-22T12:00:02Z'},
            'top_classes_by_size': [{'class_name': 'java.lang.String', 'instance_count': 10**6}, {'class_name': 'byte[]'}]}
    assert analyze_incident(report, tmp_path / 'log.sqlite', heap=heap)['coverage']['matching_events'] == 0
