"""Platform-native storage defaults, with explicit deployment overrides."""

import os
import tempfile
from pathlib import Path


def dump_directory() -> Path:
    return Path(os.environ.get("DUMP_TMP_DIR") or Path(tempfile.gettempdir()) / "postmortem")


def analysis_directory() -> Path:
    return Path(os.environ.get("ANALYSIS_DIR") or Path(tempfile.gettempdir()) / "postmortem" / "analyses")
