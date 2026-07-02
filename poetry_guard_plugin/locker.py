"""GuardLocker: subclass of poetry.packages.locker.Locker.

Overrides set_lock_data to validate new-or-upgraded packages against the prior
lock before delegating to the parent. On validation failure, raises and the
lockfile is never written.
"""

import asyncio
from pathlib import Path
from typing import Any, Callable

from poetry.core.packages.package import Package
from poetry.packages.locker import Locker
from poetry.packages.transitive_package_info import TransitivePackageInfo

from poetry_guard_plugin.config import GuardConfig
from poetry_guard_plugin.pipeline import Pipeline, raise_for_lock
from poetry_guard_plugin.validators.base import PackageRef


class GuardLocker(Locker):
    def __init__(
        self,
        lock: Path,
        pyproject_data: dict[str, Any],
        *,
        config: GuardConfig,
        pipeline: Pipeline,
        report: Callable[[str], None] = print,
        verbose_report: Callable[[str], None] = print,
    ) -> None:
        super().__init__(lock, pyproject_data)
        self._guard_config = config
        self._guard_pipeline = pipeline
        self._guard_report = report
        self._guard_verbose_report = verbose_report

    @classmethod
    def wrap(
        cls,
        existing: Locker,
        config: GuardConfig,
        pipeline: Pipeline,
        report: Callable[[str], None] = print,
        verbose_report: Callable[[str], None] = print,
    ) -> "GuardLocker":
        return cls(
            lock=existing.lock,
            pyproject_data=existing._pyproject_data,
            config=config,
            pipeline=pipeline,
            report=report,
            verbose_report=verbose_report,
        )

    def set_lock_data(
        self,
        root: Package,
        packages: dict[Package, TransitivePackageInfo],
    ) -> bool:
        if self._guard_config.enabled:
            self._validate(packages)
        return super().set_lock_data(root, packages)

    def _validate(self, packages: dict[Package, TransitivePackageInfo]) -> None:
        resolved = tuple(PackageRef(name=p.name, version=str(p.version)) for p in packages)
        prior = self._prior_lock_map()
        new_or_upgraded = tuple(p for p in resolved if prior.get(p.name) is None or prior[p.name].version != p.version)
        if not new_or_upgraded:
            self._guard_report("poetry-guard: no new or upgraded packages")
            return

        check_count = self._guard_pipeline.lockfile_check_count(new_or_upgraded)
        validator_names = ", ".join(self._guard_pipeline.lockfile_validator_names())
        self._guard_verbose_report(
            "poetry-guard: validating "
            f"{len(new_or_upgraded)} new/upgraded package(s) across {check_count} check(s)"
            f" using {validator_names}"
        )

        lock_findings = asyncio.run(self._guard_pipeline.run_lockfile(new_or_upgraded, prior))
        result = self._guard_pipeline.aggregate(lock_findings)
        for f in result.accepted:
            self._guard_report(f"poetry-guard: accepted [{f.severity}] {f.key} :: {f.validator}/{f.rule_id}")
        self._guard_report(
            f"poetry-guard: completed {check_count} check(s) on {len(new_or_upgraded)} package(s); "
            f"{len(result.findings)} finding(s), {len(result.blocked)} blocking"
        )
        raise_for_lock(result)

    def _prior_lock_map(self) -> dict[str, PackageRef]:
        if not self.is_locked():
            return {}
        repo = self.locked_repository()
        return {p.name: PackageRef(name=p.name, version=str(p.version)) for p in repo.packages}
