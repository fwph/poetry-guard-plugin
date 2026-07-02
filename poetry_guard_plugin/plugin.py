"""ApplicationPlugin entry point.

Registers a single COMMAND listener that fires before each cleo command.
For InstallerCommand subclasses (add/install/update/lock/sync/remove), it:

  1. Loads config from [tool.poetry-guard] in pyproject.toml.
  2. Snapshots pyproject.toml so a failed `poetry add` can roll back the
     dependency mutation Poetry applies pre-solve.
  3. Swaps cmd.poetry._locker with a GuardLocker that validates new-or-upgraded
     packages before the lockfile is written.
  4. Class-swaps the installer's executor to GuardExecutor so each downloaded
     artifact is validated before install. Class-swap (vs. constructing a new
     Executor) avoids depending on Poetry's private __init__ wiring.

On ERROR, restores the pyproject snapshot.
"""

import os
from pathlib import Path
from typing import Callable

from cleo.events.console_events import COMMAND, ERROR
from cleo.events.event import Event
from cleo.events.event_dispatcher import EventDispatcher
from poetry.console.application import Application
from poetry.console.commands.installer_command import InstallerCommand
from poetry.plugins.application_plugin import ApplicationPlugin

from poetry_guard_plugin.cache import VerdictCache
from poetry_guard_plugin.config import GuardConfig, load_from_pyproject
from poetry_guard_plugin.executor import GuardExecutor
from poetry_guard_plugin.locker import GuardLocker
from poetry_guard_plugin.pipeline import Pipeline


class GuardApplicationPlugin(ApplicationPlugin):
    def __init__(self) -> None:
        self._snapshot: bytes | None = None
        self._snapshot_path: Path | None = None

    def activate(self, application: Application) -> None:
        super().activate(application=application)
        dispatcher = application.event_dispatcher
        if dispatcher is None:
            return
        dispatcher.add_listener(COMMAND, self._on_command)
        dispatcher.add_listener(ERROR, self._on_error)

    def _on_command(
        self,
        event: Event,
        event_name: str,
        dispatcher: EventDispatcher,
    ) -> None:
        def _discard(_msg: str) -> None:
            return None

        cmd = getattr(event, "command", None)
        if not isinstance(cmd, InstallerCommand):
            return

        poetry = cmd.poetry
        pyproject_path = Path(poetry.file.path)
        config = load_from_pyproject(pyproject_path)
        config = self._apply_cli_overrides(event, config)
        io = getattr(event, "io", None)
        report: Callable[[str], None] = io.write_line if io is not None else _discard
        verbose_report: Callable[[str], None]
        if io is not None and io.is_verbose():
            verbose_report = io.write_line
        else:
            verbose_report = _discard
        if not config.enabled:
            report("<comment>poetry-guard: disabled, skipping validation</>")
            return

        self._snapshot_path = pyproject_path
        try:
            self._snapshot = pyproject_path.read_bytes()
        except OSError:
            self._snapshot = None

        cache = VerdictCache(config.cache_dir)
        pipeline = Pipeline.from_entry_points(
            config=config,
            cache=cache,
            fetch_artifact=None,
        )

        guard_locker = GuardLocker.wrap(
            existing=cmd.poetry.locker,
            config=config,
            pipeline=pipeline,
            report=report,
            verbose_report=verbose_report,
        )
        cmd.poetry.set_locker(guard_locker)
        cmd.installer.set_locker(guard_locker)

        executor = cmd.installer.executor
        executor.__class__ = GuardExecutor
        guard_executor: GuardExecutor = executor  # type: ignore[assignment]
        guard_executor.attach(config=config, pipeline=pipeline, report=report, verbose_report=verbose_report)

    def _on_error(
        self,
        event: Event,
        event_name: str,
        dispatcher: EventDispatcher,
    ) -> None:
        if self._snapshot is None or self._snapshot_path is None:
            return
        try:
            current = self._snapshot_path.read_bytes()
        except OSError:
            return
        if current != self._snapshot:
            self._snapshot_path.write_bytes(self._snapshot)
            io = getattr(event, "io", None)
            if io is not None:
                io.write_line("<info>poetry-guard: rolled back pyproject.toml after validation failure</>")

    @staticmethod
    def _apply_cli_overrides(event: Event, config: GuardConfig) -> GuardConfig:
        accept_risk: tuple[str, ...] = ()
        no_guard = False

        env_accept = os.environ.get("POETRY_GUARD_ACCEPT_RISK", "")
        if env_accept:
            accept_risk = tuple(v.strip() for v in env_accept.split(",") if v.strip())
        if os.environ.get("POETRY_GUARD_NO_GUARD", "").lower() in ("1", "true", "yes"):
            no_guard = True

        return config.with_cli_overrides(accept_risk=accept_risk, no_guard=no_guard)
