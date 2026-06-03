import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from poetry_guard_plugin.config import GuardConfig
from poetry_guard_plugin.validators.base import PackageRef, Severity
from poetry_guard_plugin.validators.guarddog import GuardDogValidator


@pytest.mark.asyncio
async def test_no_binary_returns_empty(tmp_path: Path) -> None:
    artifact = tmp_path / "x.tar.gz"
    artifact.write_bytes(b"x")
    v = GuardDogValidator(config=GuardConfig())
    with patch("poetry_guard_plugin.validators.guarddog.shutil.which", return_value=None):
        out = await v.validate(PackageRef("p", "1"), artifact)
    assert out == ()


@pytest.mark.asyncio
async def test_parses_v2_source_rule_finding(tmp_path: Path) -> None:
    artifact = tmp_path / "x.tar.gz"
    artifact.write_bytes(b"x")
    payload = json.dumps(
        {
            "issues": 1,
            "errors": {},
            "results": {
                "exec-base64": [
                    {"location": "x/setup.py:3", "code": "exec(...)", "message": "bad"},
                ],
                "typosquatting": None,
                "empty_information": None,
            },
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
    assert out[0].rule_id == "exec-base64"
    assert out[0].severity is Severity.HIGH


@pytest.mark.asyncio
async def test_real_fixture_code_execution(test_data: Path) -> None:
    """Real guarddog run on the bundled evil-pkg fixture — requires semgrep on PATH."""
    import shutil

    fixture = test_data / "evil-pkg-1.0.0.tar.gz"
    if shutil.which("guarddog") is None or shutil.which("semgrep") is None:
        pytest.skip("guarddog and semgrep must both be available")
    v = GuardDogValidator(config=GuardConfig())
    out = await v.validate(PackageRef("evil-pkg", "1.0.0"), fixture)
    rule_ids = {f.rule_id for f in out}
    assert "code-execution" in rule_ids
    hit = next(f for f in out if f.rule_id == "code-execution")
    assert hit.severity is Severity.HIGH


@pytest.mark.asyncio
async def test_errors_field_raises(tmp_path: Path) -> None:
    artifact = tmp_path / "x.tar.gz"
    artifact.write_bytes(b"x")
    payload = json.dumps(
        {
            "issues": 0,
            "errors": {"rules-all": "failed to run rule: unable to find semgrep binary"},
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
async def test_metadata_rule_lower_severity(tmp_path: Path) -> None:
    artifact = tmp_path / "x.tar.gz"
    artifact.write_bytes(b"x")
    payload = json.dumps(
        {
            "issues": 1,
            "errors": {},
            "results": {"empty_information": True},
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
    assert out[0].rule_id == "empty_information"
    assert out[0].severity is Severity.LOW
