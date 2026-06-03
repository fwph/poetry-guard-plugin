import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import aiohttp

from poetry_guard_plugin.config import GuardConfig
from poetry_guard_plugin.http_cache import fetch_json
from poetry_guard_plugin.validators.base import Finding, PackageRef, RuleSpec, Severity

_RULES = (
    RuleSpec(
        rule_id="maintainer_changed",
        default_severity=Severity.HIGH,
        description="Maintainer/author email differs from prior lock entry",
    ),
    RuleSpec(
        rule_id="too_new",
        default_severity=Severity.MODERATE,
        description="Package version was uploaded fewer than min_age_days ago",
    ),
    RuleSpec(
        rule_id="repo_url_missing",
        default_severity=Severity.LOW,
        description="No source-repo URL in PyPI metadata",
    ),
)

_PYPI_JSON = "https://pypi.org/pypi/{name}/{version}/json"


@dataclass
class MetadataValidator:
    config: GuardConfig
    name: str = "metadata"
    rules_version: str = "1"
    rules: tuple[RuleSpec, ...] = _RULES

    async def validate(
        self,
        resolved: tuple[PackageRef, ...],
        prior: dict[str, PackageRef],
    ) -> tuple[Finding, ...]:
        if self.config.offline or not resolved:
            return ()
        prior_to_fetch = tuple(
            prior[p.name] for p in resolved if p.name in prior and prior[p.name].version != p.version
        )
        async with aiohttp.ClientSession() as session:
            current_metas = await asyncio.gather(
                *(self._fetch(session, p) for p in resolved),
                return_exceptions=True,
            )
            prior_metas = await asyncio.gather(
                *(self._fetch(session, p) for p in prior_to_fetch),
                return_exceptions=True,
            )
        prior_email_by_name: dict[str, str] = {}
        for prior_pkg, meta in zip(prior_to_fetch, prior_metas, strict=True):
            if isinstance(meta, BaseException) or meta is None:
                continue
            email = _email_from(meta)
            if email:
                prior_email_by_name[prior_pkg.name] = email
        now = datetime.now(timezone.utc)
        findings: list[Finding] = []
        for pkg, meta in zip(resolved, current_metas, strict=True):
            if isinstance(meta, BaseException) or meta is None:
                continue
            findings.extend(self._check(pkg, meta, prior, prior_email_by_name, now))
        return tuple(findings)

    async def _fetch(self, session: aiohttp.ClientSession, pkg: PackageRef) -> dict[str, Any] | None:
        url = _PYPI_JSON.format(name=pkg.name, version=pkg.version)
        return await fetch_json(session, url, self.config.cache_dir / "pypi-json")

    def _check(
        self,
        pkg: PackageRef,
        meta: dict[str, Any],
        prior: dict[str, PackageRef],
        prior_email_by_name: dict[str, str],
        now: datetime,
    ) -> list[Finding]:
        info = meta.get("info") or {}
        urls = meta.get("urls") or []
        out: list[Finding] = []

        upload_iso = next((u.get("upload_time_iso_8601") for u in urls if u.get("upload_time_iso_8601")), None)
        if self.config.min_age_days > 0 and upload_iso:
            uploaded = datetime.fromisoformat(upload_iso)
            age_days = (now - uploaded).total_seconds() / 86400
            if age_days < self.config.min_age_days:
                out.append(
                    self._finding(
                        pkg,
                        "too_new",
                        Severity.MODERATE,
                        f"{pkg.key} uploaded {age_days:.1f} days ago (< {self.config.min_age_days})",
                        {"uploaded": upload_iso, "age_days": round(age_days, 2)},
                    )
                )

        if not _has_repo_url(info):
            out.append(
                self._finding(
                    pkg,
                    "repo_url_missing",
                    Severity.LOW,
                    f"{pkg.key} has no source-repo URL on PyPI",
                    {"home_page": info.get("home_page"), "project_urls": info.get("project_urls")},
                )
            )

        prior_pkg = prior.get(pkg.name)
        if prior_pkg and prior_pkg.version != pkg.version:
            current_email = (info.get("author_email") or info.get("maintainer_email") or "").strip().lower()
            prior_email = prior_email_by_name.get(pkg.name)
            if current_email and prior_email and current_email != prior_email:
                out.append(
                    self._finding(
                        pkg,
                        "maintainer_changed",
                        Severity.HIGH,
                        (
                            f"{pkg.key}: author email changed since {prior_pkg.version}"
                            f" ({prior_email!r} -> {current_email!r})"
                        ),
                        {
                            "prior_version": prior_pkg.version,
                            "prior_email": prior_email,
                            "current_email": current_email,
                        },
                    )
                )
        return out

    def _finding(
        self,
        pkg: PackageRef,
        rule_id: str,
        severity: Severity,
        message: str,
        detail: dict[str, Any],
    ) -> Finding:
        return Finding(
            validator=self.name,
            rule_id=rule_id,
            severity=severity,
            package_name=pkg.name,
            package_version=pkg.version,
            message=message,
            detail=detail,
        )


def _has_repo_url(info: dict[str, Any]) -> bool:
    project_urls = info.get("project_urls") or {}
    keys = {k.lower() for k in project_urls.keys()}
    if keys & {"source", "repository", "source code", "homepage"}:
        return True
    home = (info.get("home_page") or "").lower()
    return "github.com" in home or "gitlab.com" in home or "bitbucket.org" in home


def _email_from(meta: dict[str, Any]) -> str | None:
    info = meta.get("info") or {}
    email = (info.get("author_email") or info.get("maintainer_email") or "").strip().lower()
    return email or None
