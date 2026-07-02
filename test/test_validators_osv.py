from collections.abc import Mapping
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from poetry_guard_plugin.config import GuardConfig
from poetry_guard_plugin.validators.base import PackageRef, Severity
from poetry_guard_plugin.validators.osv import OsvValidator


def _mock_session(payload: Mapping[str, object]) -> MagicMock:
    response = MagicMock()
    response.json = AsyncMock(return_value=payload)
    response.raise_for_status = MagicMock()
    response.__aenter__ = AsyncMock(return_value=response)
    response.__aexit__ = AsyncMock(return_value=None)

    session = MagicMock()
    session.post = MagicMock(return_value=response)
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=None)
    return session


@pytest.mark.asyncio
async def test_offline_returns_empty() -> None:
    v = OsvValidator(config=GuardConfig(offline=True))
    out = await v.validate((PackageRef("a", "1"),), {})
    assert out == ()


@pytest.mark.asyncio
async def test_malicious_id_is_critical() -> None:
    payload = {"results": [{"vulns": [{"id": "MAL-2026-1234", "modified": "2026-01-01"}]}]}
    with patch("poetry_guard_plugin.validators.osv.aiohttp.ClientSession", return_value=_mock_session(payload)):
        v = OsvValidator(config=GuardConfig())
        out = await v.validate((PackageRef("evil", "1.0"),), {})
    assert len(out) == 1
    assert out[0].rule_id == "malicious"
    assert out[0].severity is Severity.CRITICAL


@pytest.mark.asyncio
async def test_ghsa_uses_configured_severity() -> None:
    payload = {"results": [{"vulns": [{"id": "GHSA-xxxx", "modified": "2026-01-01"}]}]}
    with patch("poetry_guard_plugin.validators.osv.aiohttp.ClientSession", return_value=_mock_session(payload)):
        v = OsvValidator(config=GuardConfig(osv_severity=Severity.LOW))
        out = await v.validate((PackageRef("x", "1"),), {})
    assert len(out) == 1
    assert out[0].rule_id == "vulnerable"
    assert out[0].severity is Severity.LOW


@pytest.mark.asyncio
async def test_clean_packages_no_findings() -> None:
    payload: dict[str, object] = {"results": [{}, {}]}
    with patch("poetry_guard_plugin.validators.osv.aiohttp.ClientSession", return_value=_mock_session(payload)):
        v = OsvValidator(config=GuardConfig())
        out = await v.validate((PackageRef("a", "1"), PackageRef("b", "2")), {})
    assert out == ()


def test_cache_context_changes_with_config() -> None:
    base = OsvValidator(config=GuardConfig())
    severity_changed = OsvValidator(config=GuardConfig(osv_severity=Severity.HIGH))
    url_changed = OsvValidator(config=GuardConfig(osv_url="https://osv.example.test/querybatch"))

    assert base.lockfile_cache_context_hash() != severity_changed.lockfile_cache_context_hash()
    assert base.lockfile_cache_context_hash() != url_changed.lockfile_cache_context_hash()
