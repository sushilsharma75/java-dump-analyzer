"""Local persistent analyses and object indexes; no API credentials are stored."""

import json
import os
import re
import uuid
from pathlib import Path

ROOT = Path(os.environ.get("ANALYSIS_DIR", "/tmp/postmortem/analyses"))
ROOT.mkdir(parents=True, exist_ok=True)


def path_for(identifier, suffix=".json"):
    if not re.fullmatch(r"[a-f0-9]{16,64}", identifier):
        raise ValueError("Invalid analysis identifier")
    return ROOT / (identifier + suffix)


def save(result, kind):
    data = result.model_dump() if hasattr(result, "model_dump") else dict(result)
    identifier = data.get("analysis_id") or uuid.uuid4().hex
    data["analysis_id"] = identifier
    path = path_for(identifier)
    tmp = path.with_suffix("." + uuid.uuid4().hex + ".tmp")
    tmp.write_text(json.dumps({"kind": kind, "analysis": data}), encoding="utf-8")
    tmp.replace(path)
    if hasattr(result, "analysis_id"):
        result.analysis_id = identifier
    return data


def read(identifier):
    return json.loads(path_for(identifier).read_text(encoding="utf-8"))


def remove(identifier):
    path = path_for(identifier)
    if not path.exists():
        return False
    path.unlink()
    path_for(identifier, ".sqlite").unlink(missing_ok=True)
    return True
