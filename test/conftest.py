import os
from pathlib import Path

import pytest


@pytest.fixture
def test_data() -> Path:
    return Path(__file__).parent / "test_data"


@pytest.fixture(autouse=True)
def semgrep_on_path(monkeypatch: pytest.MonkeyPatch, tmp_path_factory: pytest.TempPathFactory) -> None:
    """Provide guarddog with a writable Semgrep environment during tests."""
    env_root = tmp_path_factory.mktemp("semgrep-env")
    home_dir = env_root / "home"
    xdg_config_dir = env_root / "config"
    xdg_cache_dir = env_root / "cache"
    xdg_data_dir = env_root / "data"
    shim_bin_dir = env_root / "bin"
    home_dir.mkdir()
    xdg_config_dir.mkdir()
    xdg_cache_dir.mkdir()
    xdg_data_dir.mkdir()
    shim_bin_dir.mkdir()
    (home_dir / ".semgrep").mkdir()

    venv_bin = Path(__file__).parent.parent / ".venv" / "bin"
    if venv_bin.is_dir():
        semgrep_target = venv_bin / "pysemgrep"
        if not semgrep_target.is_file():
            semgrep_target = venv_bin / "semgrep"
        if semgrep_target.is_file():
            shim_path = shim_bin_dir / "semgrep"
            shim_path.write_text(
                "\n".join(
                    [
                        "#!/bin/sh",
                        f'export HOME="{home_dir}"',
                        f'export XDG_CONFIG_HOME="{xdg_config_dir}"',
                        f'export XDG_CACHE_HOME="{xdg_cache_dir}"',
                        f'export XDG_DATA_HOME="{xdg_data_dir}"',
                        f'exec "{semgrep_target}" --metrics off "$@"',
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            shim_path.chmod(0o755)
        monkeypatch.setenv("PATH", f"{shim_bin_dir}{os.pathsep}{venv_bin}{os.pathsep}{os.environ.get('PATH', '')}")
    monkeypatch.setenv("HOME", str(home_dir))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg_config_dir))
    monkeypatch.setenv("XDG_CACHE_HOME", str(xdg_cache_dir))
    monkeypatch.setenv("XDG_DATA_HOME", str(xdg_data_dir))
