import json
import subprocess
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from poetry_guard_plugin.config import GuardConfig
from poetry_guard_plugin.validators.base import PackageRef, Severity
from poetry_guard_plugin.validators.guarddog import GuardDogValidator


def _tool_is_usable(name: str, *args: str) -> bool:
    try:
        proc = subprocess.run(
            [name, *args],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return False
    return proc.returncode == 0


@pytest.mark.asyncio
async def test_no_binary_returns_empty(tmp_path: Path) -> None:
    artifact = tmp_path / "x.tar.gz"
    artifact.write_bytes(b"x")
    v = GuardDogValidator(config=GuardConfig())
    with patch("poetry_guard_plugin.validators.guarddog.shutil.which", return_value=None):
        out = await v.validate(PackageRef("p", "1"), artifact)
    assert out == ()


@pytest.mark.asyncio
async def test_parses_v3_risk_finding(tmp_path: Path) -> None:
    artifact = tmp_path / "x.tar.gz"
    artifact.write_bytes(b"x")
    payload = json.dumps(
        {
            "issues": 3,
            "errors": {},
            "results": {},
            "risk_score": {"score": 8.2, "label": "high_risk", "findings_count": 2},
            "risks": [
                {
                    "name": "risk.process.spawn",
                    "category": "process",
                    "severity": "high",
                    "threat_rule": "threat-process-download-exec",
                    "threat_description": "Detects download-and-execute patterns",
                    "threat_location": "x/setup.py:3",
                    "file_path": "x/setup.py",
                }
            ],
        }
    ).encode()

    proc = AsyncMock()
    proc.communicate = AsyncMock(return_value=(payload, b""))
    with patch("poetry_guard_plugin.validators.guarddog.shutil.which", return_value="/usr/bin/guarddog"), patch(
        "poetry_guard_plugin.validators.guarddog.asyncio.create_subprocess_exec", new=AsyncMock(return_value=proc)
    ):
        v = GuardDogValidator(config=GuardConfig())
        out = await v.validate(PackageRef("p", "1"), artifact)
    assert len(out) == 1
    assert out[0].rule_id == "threat-process-download-exec"
    assert out[0].severity is Severity.HIGH


@pytest.mark.asyncio
async def test_real_fixture_code_execution(test_data: Path) -> None:
    """Real guarddog run on the bundled evil-pkg fixture."""
    import shutil

    fixture = test_data / "evil-pkg-1.0.0.tar.gz"
    if shutil.which("guarddog") is None:
        pytest.skip("guarddog must be available")
    if not _tool_is_usable("guarddog", "--version"):
        pytest.skip("guarddog is installed but not runnable in this environment")
    v = GuardDogValidator(config=GuardConfig())
    out = await v.validate(PackageRef("evil-pkg", "1.0.0"), fixture)
    rule_ids = {f.rule_id for f in out}
    assert "threat-process-download-exec" in rule_ids
    hit = next(f for f in out if f.rule_id == "threat-process-download-exec")
    assert hit.severity is Severity.HIGH


@pytest.mark.asyncio
async def test_errors_field_raises(tmp_path: Path) -> None:
    artifact = tmp_path / "x.tar.gz"
    artifact.write_bytes(b"x")
    payload = json.dumps(
        {
            "issues": 0,
            "errors": {"rules-all": "failed to run rule set"},
            "results": {},
        }
    ).encode()

    proc = AsyncMock()
    proc.communicate = AsyncMock(return_value=(payload, b""))
    with patch("poetry_guard_plugin.validators.guarddog.shutil.which", return_value="/usr/bin/guarddog"), patch(
        "poetry_guard_plugin.validators.guarddog.asyncio.create_subprocess_exec", new=AsyncMock(return_value=proc)
    ):
        v = GuardDogValidator(config=GuardConfig())
        with pytest.raises(RuntimeError, match="guarddog scan incomplete"):
            await v.validate(PackageRef("p", "1"), artifact)


@pytest.mark.asyncio
async def test_risk_threshold_filters_lower_scores(tmp_path: Path) -> None:
    artifact = tmp_path / "x.tar.gz"
    artifact.write_bytes(b"x")
    payload = json.dumps(
        {
            "issues": 1,
            "errors": {},
            "results": {},
            "risk_score": {"score": 3.0, "label": "low_risk", "findings_count": 1},
            "risks": [
                {
                    "name": "risk.metadata.typosquat",
                    "category": "metadata",
                    "severity": "low",
                    "threat_rule": "threat-pypi-typosquatting",
                }
            ],
        }
    ).encode()

    proc = AsyncMock()
    proc.communicate = AsyncMock(return_value=(payload, b""))
    with patch("poetry_guard_plugin.validators.guarddog.shutil.which", return_value="/usr/bin/guarddog"), patch(
        "poetry_guard_plugin.validators.guarddog.asyncio.create_subprocess_exec", new=AsyncMock(return_value=proc)
    ):
        v = GuardDogValidator(config=GuardConfig())
        out = await v.validate(PackageRef("p", "1"), artifact)
    assert out == ()
