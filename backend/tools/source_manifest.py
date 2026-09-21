"""Run at build/package time to bind the distributed source tree to a build ID.

Usage: python tools/source_manifest.py /path/to/source build-id
Attach this manifest with the same source tree; record that build ID with captures.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.analyzers.source import SourceIndex

if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    root = Path(sys.argv[1]).resolve()
    index = SourceIndex(root)
    index.build()
    path = root / "postmortem-source.json"
    path.write_text(
        json.dumps(
            {
                "build_id": sys.argv[2],
                "source_sha256": index.provenance["content_sha256"],
            },
            indent=2,
        )
        + "\n"
    )
    print(path)
