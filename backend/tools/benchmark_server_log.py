"""Exercise the production streaming upload + index path with generated data.

Run from the repository root:
  backend/.venv/bin/python backend/tools/benchmark_server_log.py --gib 5

Uses actual temporary upload/index files, never a giant in-memory payload. This
synthetic large-line workload is a capacity check, not a production throughput SLA.
"""
import argparse
import asyncio
import json
import os
from pathlib import Path
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from starlette.requests import Request
from app import artifacts, server_logs
from app.sessions import JOBS


async def run(gib):
    total = int(gib * 1024 ** 3)
    if not 0 < total <= server_logs.MAX_LOG_BYTES:
        raise ValueError('Choose a size greater than zero and no larger than 5 GiB')
    line_size = 32768
    prefix = b'2026-09-22T12:00:00Z INFO [bench] com.example.Cache - '
    line = prefix + b'x' * (line_size - len(prefix) - 1) + b'\n'
    block = line * 32
    sent = 0
    with tempfile.TemporaryDirectory(prefix='server-log-capacity-') as temp:
        os.environ['DUMP_TMP_DIR'] = temp
        artifacts.ROOT = Path(temp)
        async def receive():
            nonlocal sent
            chunk = block[:min(len(block), total - sent)]
            sent += len(chunk)
            return {'type': 'http.request', 'body': chunk, 'more_body': sent < total}
        req = Request({'type': 'http', 'method': 'POST', 'headers': [
            (b'content-type', b'application/octet-stream'), (b'content-length', str(total).encode())]}, receive)
        started = time.monotonic()
        response = await server_logs.upload_log(req, filename='synthetic-server.log')
        uploaded = time.monotonic()
        print(json.dumps({'uploaded_bytes': sent, 'upload_seconds': round(uploaded - started, 2)}), flush=True)
        while True:
            await asyncio.sleep(1)
            job = JOBS.get(response['job_id'])
            print(json.dumps({'stage': job['stage'], 'bytes_processed': job['bytes_processed'], 'events': job['records_seen']}), flush=True)
            if job['status'] in ('done', 'error'):
                break
        assert job['status'] == 'done', job['error']
        report = job['result']
        expected = (total + line_size - 1) // line_size
        assert report['counts']['bytes'] == total
        assert report['counts']['events'] == expected, report['counts']
        identifier = report['analysis_id']
        assert artifacts.read(identifier)['analysis']['sha256'] == report['sha256']
        page = server_logs.server_log.search_events(artifacts.path_for(identifier, '.log.sqlite'), identifier, after=expected - 1)
        assert page['events'][0]['id'] == expected
        assert not list(Path(temp).glob('*.upload'))
        output = {'input_bytes': total, 'events': expected, 'upload_seconds': round(uploaded - started, 2),
                  'scan_seconds': round(time.monotonic() - uploaded, 2),
                  'index_bytes': artifacts.path_for(identifier, '.log.sqlite').stat().st_size,
                  'verified': ['full byte count', 'event count', 'saved report', 'last event query', 'upload cleanup']}
        try:
            import resource
            output['max_rss_kib_linux'] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        except ImportError:
            pass
        artifacts.remove(identifier)
        JOBS.remove(response['job_id'])
        print(json.dumps(output, indent=2), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--gib', type=float, default=0.0625)
    asyncio.run(run(parser.parse_args().gib))
