import asyncio
from dataclasses import dataclass, field
from importlib.metadata import entry_points
from pathlib import Path
from typing import Any, Callable, Sequence

from poetry_guard_plugin.cache import VerdictCache
from poetry_guard_plugin.config import GuardConfig
from poetry_guard_plugin.exceptions import ArtifactValidationError, LockValidationError
from poetry_guard_plugin.validators.base import (
    ArtifactValidator,
    Finding,
    LockfileValidator,
    PackageRef,
    Severity,
)

HARD_FAIL_MIN = Severity.HIGH


@dataclass
class PipelineResult:
    findings: tuple[Finding, ...]
    blocked: tuple[Finding, ...]
    accepted: tuple[Finding, ...]


@dataclass
class Pipeline:
    config: GuardConfig
    cache: VerdictCache
    lockfile_validators: tuple[LockfileValidator, ...] = field(default_factory=tuple)
    artifact_validators: tuple[ArtifactValidator, ...] = field(default_factory=tuple)
    fetch_artifact: Callable[[PackageRef], Path | None] | None = None

    @classmethod
    def from_entry_points(
        cls,
        config: GuardConfig,
        cache: VerdictCache,
        fetch_artifact: Callable[[PackageRef], Path | None] | None,
    ) -> "Pipeline":
        return cls(
            config=config,
            cache=cache,
            lockfile_validators=_load_lockfile_validators(config),
            artifact_validators=_load_artifact_validators(config),
            fetch_artifact=fetch_artifact,
        )

    async def run_lockfile(
        self,
        resolved: Sequence[PackageRef],
        prior: dict[str, PackageRef],
    ) -> tuple[Finding, ...]:
        if not self.config.enabled or not resolved:
            return ()
        results = await asyncio.gather(
            *(self._run_lockfile_one(v, tuple(resolved), prior) for v in self.lockfile_validators),
            return_exceptions=True,
        )
        findings: list[Finding] = []
        for r in results:
            if isinstance(r, BaseException):
                continue
            findings.extend(r)
        return tuple(findings)

    async def _run_lockfile_one(
        self,
        validator: LockfileValidator,
        resolved: tuple[PackageRef, ...],
        prior: dict[str, PackageRef],
    ) -> tuple[Finding, ...]:
        cached: list[Finding] = []
        to_run: list[PackageRef] = []
        for pkg in resolved:
            hit = self.cache.get_lockfile(validator.name, validator.rules_version, pkg)
            if hit is not None:
                cached.extend(hit)
            else:
                to_run.append(pkg)
        if not to_run:
            return tuple(cached)
        fresh = await validator.validate(tuple(to_run), prior)
        by_pkg: dict[str, list[Finding]] = {p.key: [] for p in to_run}
        for f in fresh:
            by_pkg.setdefault(f"{f.package_name}@{f.package_version}", []).append(f)
        for pkg in to_run:
            self.cache.put_lockfile(
                validator.name,
                validator.rules_version,
                pkg,
                tuple(by_pkg.get(pkg.key, [])),
            )
        return tuple(cached) + fresh

    async def run_artifact(self, packages: Sequence[PackageRef]) -> tuple[Finding, ...]:
        if not self.config.enabled or not self.artifact_validators or self.fetch_artifact is None:
            return ()
        results = await asyncio.gather(
            *(self._run_artifact_one(p) for p in packages),
            return_exceptions=True,
        )
        findings: list[Finding] = []
        for r in results:
            if isinstance(r, BaseException):
                continue
            findings.extend(r)
        return tuple(findings)

    async def run_artifact_at_path(self, pkg: PackageRef, path: Path) -> tuple[Finding, ...]:
        if not self.config.enabled or not self.artifact_validators:
            return ()
        try:
            return await self._run_artifact_one_at_path(pkg, path)
        except BaseException:
            return ()

    async def _run_artifact_one(self, pkg: PackageRef) -> tuple[Finding, ...]:
        if self.fetch_artifact is None:
            return ()
        path = self.fetch_artifact(pkg)
        if path is None or not path.is_file():
            return ()
        return await self._run_artifact_one_at_path(pkg, path)

    async def _run_artifact_one_at_path(self, pkg: PackageRef, path: Path) -> tuple[Finding, ...]:
        if not path.is_file():
            return ()
        sha = VerdictCache.sha256_of(path)
        out: list[Finding] = []
        for validator in self.artifact_validators:
            hit = self.cache.get_artifact(validator.name, validator.rules_version, sha)
            if hit is not None:
                out.extend(hit)
                continue
            fresh = await validator.validate(pkg, path)
            self.cache.put_artifact(validator.name, validator.rules_version, sha, fresh)
            out.extend(fresh)
        return tuple(out)

    def aggregate(self, findings: tuple[Finding, ...]) -> PipelineResult:
        blocked: list[Finding] = []
        accepted: list[Finding] = []
        for f in findings:
            if self._is_ignored(f) or self._is_accepted(f):
                accepted.append(f)
                continue
            if self._blocks(f):
                blocked.append(f)
            else:
                accepted.append(f)
        return PipelineResult(findings=findings, blocked=tuple(blocked), accepted=tuple(accepted))

    def _is_ignored(self, f: Finding) -> bool:
        return f.rule_id in self.config.ignore_rules or f"{f.validator}/{f.rule_id}" in self.config.ignore_rules

    def _is_accepted(self, f: Finding) -> bool:
        key = f"{f.package_name}@{f.package_version}"
        return key in self.config.accept_risk

    def _blocks(self, f: Finding) -> bool:
        if f.severity is Severity.CRITICAL:
            return True
        if f.validator == "osv":
            return f.severity.at_least(self.config.osv_severity)
        if f.validator == "guarddog":
            return f.severity.at_least(self.config.guarddog_severity)
        return f.severity.at_least(HARD_FAIL_MIN)


def raise_for_lock(result: PipelineResult) -> None:
    if result.blocked:
        raise LockValidationError(result.blocked)


def raise_for_artifact(result: PipelineResult) -> None:
    if result.blocked:
        raise ArtifactValidationError(result.blocked)


def _load_lockfile_validators(config: GuardConfig) -> tuple[LockfileValidator, ...]:
    return tuple(_load_group("poetry_guard.validators.lockfile", config))


def _load_artifact_validators(config: GuardConfig) -> tuple[ArtifactValidator, ...]:
    return tuple(_load_group("poetry_guard.validators.artifact", config))


def _load_group(group: str, config: GuardConfig) -> list[Any]:
    out: list[Any] = []
    for ep in entry_points(group=group):
        try:
            cls = ep.load()
            out.append(cls(config=config))
        except Exception:
            continue
    return out
