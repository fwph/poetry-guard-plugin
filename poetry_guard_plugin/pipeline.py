import asyncio
import json
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
        return await _gather_findings(
            self._run_lockfile_one(v, tuple(resolved), prior) for v in self.lockfile_validators
        )

    def lockfile_check_count(self, packages: Sequence[PackageRef]) -> int:
        return len(packages) * len(self.lockfile_validators)

    def lockfile_validator_names(self) -> tuple[str, ...]:
        return tuple(v.name for v in self.lockfile_validators)

    async def _run_lockfile_one(
        self,
        validator: LockfileValidator,
        resolved: tuple[PackageRef, ...],
        prior: dict[str, PackageRef],
    ) -> tuple[Finding, ...]:
        cached: list[Finding] = []
        to_run: list[PackageRef] = []
        skip_rule_ids = validator.non_cacheable_rule_ids()
        cache_context_hash = validator.lockfile_cache_context_hash()
        for pkg in resolved:
            hit = self.cache.get_lockfile(
                validator.name,
                validator.rules_version,
                pkg,
                cache_context_hash=cache_context_hash,
                skip_rule_ids=skip_rule_ids,
            )
            if hit is not None:
                cached.extend(hit)
            if self.config.offline and skip_rule_ids:
                continue
            if hit is None or skip_rule_ids:
                to_run.append(pkg)
        if not to_run:
            return tuple(cached)
        fresh = await validator.validate(tuple(to_run), prior)
        by_pkg: dict[str, list[Finding]] = {}
        for f in fresh:
            by_pkg.setdefault(f.key, []).append(f)
        for pkg in to_run:
            self.cache.put_lockfile(
                validator.name,
                validator.rules_version,
                pkg,
                tuple(by_pkg.get(pkg.key, [])),
                cache_context_hash=cache_context_hash,
            )
        return _dedupe_findings(tuple(cached) + fresh)

    async def run_artifact(self, packages: Sequence[PackageRef]) -> tuple[Finding, ...]:
        if not self.config.enabled or not self.artifact_validators or self.fetch_artifact is None:
            return ()
        return await _gather_findings(self._run_artifact_one(p) for p in packages)

    async def run_artifact_at_path(self, pkg: PackageRef, path: Path) -> tuple[Finding, ...]:
        if not self.config.enabled or not self.artifact_validators:
            return ()
        return await self._run_artifact_one_at_path(pkg, path)

    def artifact_check_count(self) -> int:
        return len(self.artifact_validators)

    def artifact_validator_names(self) -> tuple[str, ...]:
        return tuple(v.name for v in self.artifact_validators)

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
        # Strict gather: validator errors propagate rather than silently passing.
        results = await asyncio.gather(
            *(self._run_one_artifact_validator(v, pkg, path, sha) for v in self.artifact_validators)
        )
        return tuple(f for r in results for f in r)

    async def _run_one_artifact_validator(
        self,
        validator: ArtifactValidator,
        pkg: PackageRef,
        path: Path,
        sha: str,
    ) -> tuple[Finding, ...]:
        cache_context_hash = validator.artifact_cache_context_hash()
        hit = self.cache.get_artifact(
            validator.name, validator.rules_version, sha, cache_context_hash=cache_context_hash
        )
        if hit is not None:
            return hit
        fresh = await validator.validate(pkg, path)
        self.cache.put_artifact(
            validator.name, validator.rules_version, sha, fresh, cache_context_hash=cache_context_hash
        )
        return fresh

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
        return f.key in self.config.accept_risk

    def _blocks(self, f: Finding) -> bool:
        if f.severity is Severity.CRITICAL:
            return True
        if f.validator == "osv":
            return f.severity >= self.config.osv_severity
        if f.validator == "guarddog":
            return f.severity >= self.config.guarddog_severity
        return f.severity >= HARD_FAIL_MIN


def raise_for_lock(result: PipelineResult) -> None:
    if result.blocked:
        raise LockValidationError(result.blocked)


def raise_for_artifact(result: PipelineResult) -> None:
    if result.blocked:
        raise ArtifactValidationError(result.blocked)


async def _gather_findings(
    coros: Any,
) -> tuple[Finding, ...]:
    results = await asyncio.gather(*coros)
    findings: list[Finding] = []
    for result in results:
        findings.extend(result)
    return tuple(findings)


def _dedupe_findings(findings: tuple[Finding, ...]) -> tuple[Finding, ...]:
    seen: set[str] = set()
    deduped: list[Finding] = []
    for finding in findings:
        detail = json.dumps(finding.detail, sort_keys=True, separators=(",", ":"))
        key = (
            f"{finding.validator}\0{finding.rule_id}\0{finding.severity.value}\0"
            f"{finding.package_name}\0{finding.package_version}\0{finding.message}\0{detail}"
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return tuple(deduped)


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
        except Exception as e:
            raise RuntimeError(f"poetry-guard: failed to load validator {ep.name!r}: {e}") from e
    return out
