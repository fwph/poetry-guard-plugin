import os
from pathlib import Path

import pytest


@pytest.fixture
def test_data() -> Path:
    return Path(__file__).parent / "test_data"


@pytest.fixture(autouse=True)
def semgrep_on_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure the project venv's semgrep binary is on PATH so guarddog can find it."""
    venv_bin = Path(__file__).parent.parent / ".venv" / "bin"
    if venv_bin.is_dir():
        monkeypatch.setenv("PATH", f"{venv_bin}{os.pathsep}{os.environ.get('PATH', '')}")
