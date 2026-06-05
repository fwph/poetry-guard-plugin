"""GuardExecutor: subclass of poetry.installation.executor.Executor.

Validates each cached artifact between download and install. Used when the
GuardLocker hook does not fire (e.g., `poetry install` from a checked-in lock).

Installed by class-swap (executor.__class__ = GuardExecutor) so we don't have
to know how to reconstruct an Executor from its private attributes — the
original __init__ already ran. Guard state is attached via attach().
"""

import asyncio
from pathlib import Path
from typing import Callable

from poetry.installation.executor import Executor
from poetry.installation.operations.install import Install
from poetry.installation.operations.update import Update

from poetry_guard_plugin.config import GuardConfig
from poetry_guard_plugin.pipeline import Pipeline, raise_for_artifact
from poetry_guard_plugin.validators.base import PackageRef


class GuardExecutor(Executor):
    _guard_config: GuardConfig
    _guard_pipeline: Pipeline
    _guard_report: Callable[[str], None]
    _validated_archives: set[str]

    def attach(
        self,
        config: GuardConfig,
        pipeline: Pipeline,
        report: Callable[[str], None],
    ) -> None:
        self._guard_config = config
        self._guard_pipeline = pipeline
        self._guard_report = report
        self._validated_archives = set()

    def _install(self, operation: Install | Update) -> int:
        if getattr(self, "_guard_config", None) is not None and self._guard_config.enabled:
            archive = self._resolve_archive(operation)
            if archive is not None and str(archive) not in self._validated_archives:
                self._validate_archive(operation, archive)
                self._validated_archives.add(str(archive))
        return super()._install(operation)

    def _resolve_archive(self, operation: Install | Update) -> Path | None:
        package = operation.package
        try:
            if package.source_type == "git":
                return self._prepare_git_archive(operation)
            if package.source_type == "file":
                # Scan the raw sdist/tarball, not the wheel built from it.
                # _prepare_archive() builds a wheel; setup.py patterns would be lost.
                if package.source_url is None:
                    return None
                p = Path(package.source_url)
                root_dir: Path | None = getattr(package, "root_dir", None)
                if not p.is_absolute() and root_dir is not None:
                    p = root_dir / p
                return p if p.is_file() else None
            if package.source_type == "directory":
                return None  # directory installs: no single artifact to scan
            if package.source_type == "url":
                from poetry.core.packages.utils.link import Link

                if package.source_url is None:
                    return None
                return self._download_link(operation, Link(package.source_url))
            return self._download(operation)
        except Exception:
            return None

    def _validate_archive(self, operation: Install | Update, archive: Path) -> None:
        pkg = PackageRef(name=operation.package.name, version=str(operation.package.version))
        artifact_findings = asyncio.run(self._guard_pipeline.run_artifact_at_path(pkg, archive))
        result = self._guard_pipeline.aggregate(artifact_findings)
        for f in result.accepted:
            self._guard_report(f"poetry-guard: accepted [{f.severity}] {f.key} :: {f.validator}/{f.rule_id}")
        raise_for_artifact(result)
