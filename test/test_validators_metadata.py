from pathlib import Path
from unittest.mock import patch

import pytest

from poetry_guard_plugin.config import GuardConfig
from poetry_guard_plugin.validators.base import PackageRef, Severity
from poetry_guard_plugin.validators.metadata import MetadataValidator


def _meta(
    *,
    author_email: str | None = None,
    maintainer_email: str | None = None,
    home_page: str | None = None,
    project_urls: dict[str, str] | None = None,
    upload_iso: str | None = None,
) -> dict[str, object]:
    return {
        "info": {
            "author_email": author_email,
            "maintainer_email": maintainer_email,
            "home_page": home_page,
            "project_urls": project_urls,
        },
        "urls": [{"upload_time_iso_8601": upload_iso}] if upload_iso else [],
    }


@pytest.mark.asyncio
async def test_offline_short_circuits(tmp_path: Path) -> None:
    v = MetadataValidator(config=GuardConfig(offline=True, cache_dir=tmp_path))
    assert await v.validate((PackageRef("x", "1"),), {}) == ()


@pytest.mark.asyncio
async def test_repo_url_missing(tmp_path: Path) -> None:
    pkg = PackageRef("p", "1")
    metas = {pkg.key: _meta(author_email="a@b.com")}

    async def fake_fetch(self, session, p):  # type: ignore[no-untyped-def]
        return metas.get(p.key)

    with patch.object(MetadataValidator, "_fetch", fake_fetch):
        v = MetadataValidator(config=GuardConfig(cache_dir=tmp_path))
        out = await v.validate((pkg,), {})
    rule_ids = {f.rule_id for f in out}
    assert "repo_url_missing" in rule_ids


@pytest.mark.asyncio
async def test_maintainer_change_flagged(tmp_path: Path) -> None:
    pkg = PackageRef("p", "2")
    prior = {"p": PackageRef("p", "1")}
    metas = {
        pkg.key: _meta(author_email="new@evil.example", project_urls={"Source": "https://github.com/p/p"}),
        prior["p"].key: _meta(author_email="orig@good.example", project_urls={"Source": "https://github.com/p/p"}),
    }

    async def fake_fetch(self, session, p):  # type: ignore[no-untyped-def]
        return metas.get(p.key)

    with patch.object(MetadataValidator, "_fetch", fake_fetch):
        v = MetadataValidator(config=GuardConfig(cache_dir=tmp_path))
        out = await v.validate((pkg,), prior)
    rule_ids = {f.rule_id for f in out}
    assert "maintainer_changed" in rule_ids
    f = next(f for f in out if f.rule_id == "maintainer_changed")
    assert f.severity is Severity.HIGH


@pytest.mark.asyncio
async def test_maintainer_roster_overlap_flagged_separately(tmp_path: Path) -> None:
    pkg = PackageRef("p", "2")
    prior = {"p": PackageRef("p", "1")}
    metas = {
        pkg.key: _meta(
            author_email="alice@example.com, carol@example.com",
            maintainer_email="dave@example.com",
            project_urls={"Source": "https://github.com/p/p"},
        ),
        prior["p"].key: _meta(
            author_email="alice@example.com, bob@example.com",
            maintainer_email="dave@example.com",
            project_urls={"Source": "https://github.com/p/p"},
        ),
    }

    async def fake_fetch(self, session, p):  # type: ignore[no-untyped-def]
        return metas.get(p.key)

    with patch.object(MetadataValidator, "_fetch", fake_fetch):
        v = MetadataValidator(config=GuardConfig(cache_dir=tmp_path))
        out = await v.validate((pkg,), prior)
    rule_ids = {f.rule_id for f in out}
    assert "maintainer_roster_changed" in rule_ids
    assert "maintainer_changed" not in rule_ids
    f = next(f for f in out if f.rule_id == "maintainer_roster_changed")
    assert f.severity is Severity.MODERATE
    assert f.detail["overlap"] == ["alice@example.com", "dave@example.com"]
    assert f.detail["added"] == ["carol@example.com"]
    assert f.detail["removed"] == ["bob@example.com"]
