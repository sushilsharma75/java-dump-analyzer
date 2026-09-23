# Server-log capacity validation

The production raw-upload and background-index functions were exercised with
**5,368,709,120 bytes (5 GiB)** of generated UTF-8 log data on the development
Linux host on 2026-09-23.

Command:

```bash
backend/.venv/bin/python backend/tools/benchmark_server_log.py --gib 5
```

Observed results:

| Measurement | Result |
|---|---:|
| Input size | 5,368,709,120 bytes |
| Indexed events | 163,840 |
| Synthetic event size | 32,768 bytes |
| Upload function duration | 17.26 seconds |
| Scan, index and report duration | 225.46 seconds |
| SQLite index size | 6,148,476,928 bytes |
| Process peak RSS | 350,812 KiB (about 343 MiB) |

The check verified the full scanned byte count, event count, persisted report,
query of the final event, and removal of the raw upload after completion. Its
temporary index and saved report were removed after verification.

This is a capacity check using an ASGI request stream and actual disk files. It
is not a browser/proxy transport benchmark. Long repetitive synthetic events are
not representative of every production log: many short events, large numbers of
stack frames, disk speed, and concurrent heap analysis can change runtime and
index size substantially. Configure proxy limits and allow enough storage for
the raw upload and the growing index together.
