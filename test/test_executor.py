from unittest.mock import MagicMock

import pytest

from poetry_guard_plugin.config import GuardConfig
from poetry_guard_plugin.exceptions import ArtifactResolutionError
from poetry_guard_plugin.executor import GuardExecutor


def test_install_raises_when_archive_resolution_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    executor = object.__new__(GuardExecutor)
    executor._guard_config = GuardConfig()

    operation = MagicMock()
    operation.package.name = "pkg"
    operation.package.version = "1.0"

    def fail_resolve(_operation: object) -> None:
        raise RuntimeError("download failed")

    monkeypatch.setattr(executor, "_resolve_archive", fail_resolve)

    with pytest.raises(ArtifactResolutionError, match="failed to resolve artifact for pkg@1.0"):
        executor._install(operation)
