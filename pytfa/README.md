# tfa (Python) — Thread Flow Analyzer

A pure-Python port of the Java Thread Flow Analyzer. Reconstructs per-thread
execution flows from an offline log dump, compares flows of the same kind against
each other, and ranks the deviations. **The population is the baseline** — no
golden path is authored. Runs locally and offline, streaming, with flat memory.

This is a faithful, feature-complete port of the Java implementation under
`../tfa`: the same pipeline, the same config format, the same CLI commands, the
same detectors and ranking, and the same local web UI. It produces the same
findings (verified against the Java build on the sample corpus).

## Install

```bash
cd pytfa
python -m pip install -e .          # installs the `tfa` console script + PyYAML
# or, without installing:  run `python -m tfa.cli ...` from this directory
```

Requires Python 3.10+. Dev/test extra: `pip install -e ".[test]"`.

## Commands

```bash
tfa parse <dir> [--threshold 0.95] [--sample 1000]     # ingestion statistics
tfa detect-format <file> [--sample 500]                # infer a format profile
tfa segment  <dir> --config <yaml>                      # episode distributions
tfa cluster  <dir> --config <yaml>                      # flow-cluster distribution
tfa baseline <dir> --config <yaml>                      # consensus baseline per cluster
tfa detect   <dir> --config <yaml>                      # raw (unranked) findings
tfa analyze  <dir> --config <yaml> [--out report.json] [--suppressions <yaml>]
tfa validate <dir> --config <yaml> --ground-truth <yaml>
tfa explain  <dir> --config <yaml> --thread <id> --at <timestamp>
tfa compare  <dir> --good <refId> --bad <refId> [--config <yaml>] [--all] [--out <file>]
tfa serve [--port 8080]                                 # local web UI
```

(Without installing, replace `tfa` with `python -m tfa.cli`.)

## Package layout

| Module | Java counterpart |
|---|---|
| `tfa/model.py` | `tfa.model` — LogRecord, Episode, FlowCluster, Baseline, Finding, enums |
| `tfa/ingest.py` | `tfa.ingest` — FormatProfile, RecordParser, FileSetReader, FormatDetector |
| `tfa/config.py` | `tfa.config` — AnalysisConfig + sub-configs, YAML loading |
| `tfa/segment.py` | `tfa.segment` — FlowKeyStrategy + Entry/IdleGap/CorrelationId, StreamingSegmenter |
| `tfa/cluster.py` | `tfa.cluster` — SignatureClusterer |
| `tfa/baseline.py` | `tfa.baseline` — ConsensusBuilder |
| `tfa/detect.py` | `tfa.detect` — SequenceDiff, detectors, Censor, DetectionEngine |
| `tfa/rank.py` | `tfa.rank` — FindingRanker, Suppressions |
| `tfa/report.py` | `tfa.report` — CorpusFingerprint, LogContext, text + JSON reporters |
| `tfa/validate.py` | `tfa.validate` — GroundTruth, RankIndex, Explainer, Validator |
| `tfa/testkit.py` | `tfa.testkit` — SyntheticLogGenerator, Scenario, Defects |
| `tfa/__init__.py` | `tfa.Analysis` — the public `analyze(dir, config)` entry point |
| `tfa/cli.py` | `tfa.cli.Main` |
| `tfa/web.py` + `tfa/webui/` | `tfa.cli.WebServer` + `webui/` |

## Tests

```bash
python -m pytest
```

## Extras

- `recon_profile_corpus.py` — the Phase 0 throwaway corpus profiler (same script
  as the Java project's `recon/`), for choosing the segmentation config.
- `report-viewer.html` — standalone, no-server viewer: open it and load a
  `report.json` produced by `tfa analyze --out`.
- `tools/make_demo.py` — generates a demo corpus + config + ground truth with
  injected defects (a slow flow, a truncated flow, a wrong-branch flow), so you
  can prove the pipeline end to end before pointing it at real logs:
  ```bash
  python tools/make_demo.py demo
  python -m tfa.cli analyze  demo/logs --config demo/config.yaml
  python -m tfa.cli validate demo/logs --config demo/config.yaml --ground-truth demo/ground-truth.yaml
  ```
  Edit the `FLOWS` / timings at the top of the script to model your own flows.

### Two things that matter for it to "identify processes" correctly

1. **The population is the baseline.** A slow/odd flow is only flagged when there
   are *several normal examples of the same flow* to compare against (default:
   ≥10, `clustering.minClusterSize`). One-vs-one can't self-flag — a lone outlier
   defines its own baseline.
2. **A divergence must occur *after* the first-K call sites** (`clustering.signatureK`),
   because flows are grouped by that prefix. A flow that branches *within* the
   first K call sites forms its own (often under-sampled) cluster and gets no
   baseline. Lower K, or make sure your entry markers sit before the branch point.

## Notes

- Config YAML is identical to the Java project (`profile`, `segmentation`,
  `clustering`, `baseline`, `detection`, `ranking`, plus optional `profiles:`).
- The web UI is bound to `127.0.0.1` and has no authentication — run it only on a
  machine you control. It shells out to `python -m tfa.cli` locally and reads only
  the folder you name; nothing is uploaded.

## Cross-service flows (correlation id)

If one logical flow spans several services/threads joined by a trace id — the
common microservice case — segment by `CORRELATION_ID` instead of by thread:

```yaml
segmentation:
  strategy: CORRELATION_ID
  correlationIdPattern: 'trace_id=([0-9a-f]+)'   # regex, id in group 1
  terminalCallSites: [OrderController:38]        # how a flow is known to have completed
```

Every record sharing an id becomes one episode, in true time order, across all
service log files. Records with no id are dropped. `tools/make_microservice_demo.py`
generates an order/inventory/payment corpus with a payment-service-down defect and
proves detection end to end.

## Comparing two reference flows (no population needed)

`analyze` needs a population ("what did the other N runs do?"). When you have
exactly **one known-good and one known-bad reference id**, use `compare` instead:

```bash
tfa compare /path/to/logs --good 4f3a9c2e...  --bad 8b1d5f7a...
```

No `--config` is needed or used.

**The log format does not matter.** `compare` uses no format profile, no config
and no match-rate check - it reads raw lines from every file and derives what it
needs best-effort: the timestamp (several common layouts; file order otherwise),
the step identity (`Class:line` when present, otherwise a normalised message
template with values masked), and payload fields (`key=value` and `"key": value`,
including nested `{a=1, b=2}` blocks). Plain text, JSON lines and syslog-style
files can even be mixed in the same folder and still stitch into one flow.

Reference ids are matched as **exact whole tokens** (no spaces, no partial
matches), across every log file. The report gives:

- **THE BREAK** — the first step where the two flows part company, whether that
  is a different branch or the same step with different data.
- **PAYLOAD / PARAMETER DIFFERENCES** — per shared step: a field missing in the
  bad flow, an extra field, or a differing value.
- **ERRORS / EXCEPTIONS IN THE BAD FLOW** — with stack traces.
- **ALIGNED FLOW** — the two call-site sequences diffed side by side
  (`=` same, `-` only in good, `+` only in bad, `~` payload differs), so a whole
  missing interface call (e.g. the payment leg) is visible at a glance.

This covers the four ways a flow breaks: business-logic branch, exception,
missing request parameter, and wrong payload value. Exit code is 5 when a break
is found, 0 when the flows match. `--out` writes the same data as JSON.
