import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import getaddresses
from typing import Any

import aiohttp

from poetry_guard_plugin.config import GuardConfig
from poetry_guard_plugin.http_cache import fetch_json
from poetry_guard_plugin.validators.base import Finding, PackageRef, RuleSpec, Severity

_RULES = (
    RuleSpec(
        rule_id="maintainer_changed",
        default_severity=Severity.HIGH,
        description="Maintainer/author roster has no overlap with the prior release",
    ),
    RuleSpec(
        rule_id="maintainer_roster_changed",
        default_severity=Severity.MODERATE,
        description="Maintainer/author roster changed but still overlaps with the prior release",
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
            current_metas = await asyncio.gather(*(self._fetch(session, p) for p in resolved))
            prior_metas = await asyncio.gather(*(self._fetch(session, p) for p in prior_to_fetch))
        prior_emails_by_name: dict[str, frozenset[str]] = {}
        for prior_pkg, meta in zip(prior_to_fetch, prior_metas, strict=True):
            if meta is None:
                continue
            emails = _emails_from(meta)
            if emails:
                prior_emails_by_name[prior_pkg.name] = emails
        now = datetime.now(timezone.utc)
        findings: list[Finding] = []
        for pkg, meta in zip(resolved, current_metas, strict=True):
            if meta is None:
                continue
            findings.extend(self._check(pkg, meta, prior, prior_emails_by_name, now))
        return tuple(findings)

    async def _fetch(self, session: aiohttp.ClientSession, pkg: PackageRef) -> dict[str, Any] | None:
        url = _PYPI_JSON.format(name=pkg.name, version=pkg.version)
        return await fetch_json(session, url, self.config.cache_dir / "pypi-json")

    def _check(
        self,
        pkg: PackageRef,
        meta: dict[str, Any],
        prior: dict[str, PackageRef],
        prior_emails_by_name: dict[str, frozenset[str]],
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
                out.append(Finding(
                    validator=self.name, rule_id="too_new", severity=Severity.MODERATE,
                    package_name=pkg.name, package_version=pkg.version,
                    message=f"{pkg.key} uploaded {age_days:.1f} days ago (< {self.config.min_age_days})",
                    detail={"uploaded": upload_iso, "age_days": round(age_days, 2)},
                ))

        if not _has_repo_url(info):
            out.append(Finding(
                validator=self.name, rule_id="repo_url_missing", severity=Severity.LOW,
                package_name=pkg.name, package_version=pkg.version,
                message=f"{pkg.key} has no source-repo URL on PyPI",
                detail={"home_page": info.get("home_page"), "project_urls": info.get("project_urls")},
            ))

        prior_pkg = prior.get(pkg.name)
        if prior_pkg and prior_pkg.version != pkg.version:
            current_emails = _emails_from(meta)
            prior_emails = prior_emails_by_name.get(pkg.name)
            if current_emails and prior_emails and current_emails != prior_emails:
                overlap = sorted(current_emails & prior_emails)
                added = sorted(current_emails - prior_emails)
                removed = sorted(prior_emails - current_emails)
                if overlap:
                    out.append(Finding(
                        validator=self.name,
                        rule_id="maintainer_roster_changed",
                        severity=Severity.MODERATE,
                        package_name=pkg.name,
                        package_version=pkg.version,
                        message=(
                            f"{pkg.key}: maintainer roster changed since {prior_pkg.version}"
                            f" (+{len(added)} / -{len(removed)}; {len(overlap)} unchanged)"
                        ),
                        detail={
                            "prior_version": prior_pkg.version,
                            "prior_emails": sorted(prior_emails),
                            "current_emails": sorted(current_emails),
                            "overlap": overlap,
                            "added": added,
                            "removed": removed,
                        },
                    ))
                else:
                    out.append(Finding(
                        validator=self.name,
                        rule_id="maintainer_changed",
                        severity=Severity.HIGH,
                        package_name=pkg.name,
                        package_version=pkg.version,
                        message=(
                            f"{pkg.key}: maintainer roster changed completely since {prior_pkg.version}"
                            f" ({len(prior_emails)} prior -> {len(current_emails)} current)"
                        ),
                        detail={
                            "prior_version": prior_pkg.version,
                            "prior_emails": sorted(prior_emails),
                            "current_emails": sorted(current_emails),
                            "overlap": overlap,
                            "added": added,
                            "removed": removed,
                        },
                    ))
        return out


def _has_repo_url(info: dict[str, Any]) -> bool:
    project_urls = info.get("project_urls") or {}
    keys = {k.lower() for k in project_urls.keys()}
    if keys & {"source", "repository", "source code", "homepage"}:
        return True
    home = (info.get("home_page") or "").lower()
    return "github.com" in home or "gitlab.com" in home or "bitbucket.org" in home


def _emails_from(meta: dict[str, Any]) -> frozenset[str]:
    info = meta.get("info") or {}
    raw_values = [str(info.get("author_email") or ""), str(info.get("maintainer_email") or "")]
    parsed = {
        email.strip().lower()
        for _name, email in getaddresses(raw_values)
        if email and "@" in email
    }
    return frozenset(parsed)
