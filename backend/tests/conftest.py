"""Shared pytest fixtures and path setup for the backend test suite."""
import sys
from pathlib import Path

import pytest

# Make `import app...` work when running pytest from anywhere.
BACKEND = Path(__file__).resolve().parent.parent
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.analyzers.source import SourceIndex  # noqa: E402

FIXTURE_SRC = Path(__file__).resolve().parent / "fixtures" / "src"
SAMPLES = Path(__file__).resolve().parent


@pytest.fixture(scope="session")
def source_index():
    """A SourceIndex built over the synthetic Java/Kotlin fixture repo."""
    idx = SourceIndex(FIXTURE_SRC)
    idx.build()
    return idx


@pytest.fixture
def fixture_src_path():
    return str(FIXTURE_SRC)


@pytest.fixture
def samples_dir():
    return SAMPLES
