from __future__ import annotations

import tomllib
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from poetry_guard_plugin.validators.base import Severity


@dataclass(frozen=True)
class GuardConfig:
    enabled: bool = True
    offline: bool = False
    osv_url: str = "https://api.osv.dev/v1/querybatch"
    osv_severity: Severity = Severity.MODERATE
    guarddog_severity: Severity = Severity.HIGH
    guarddog_risk_threshold: int = 7
    min_age_days: int = 3
    accept_risk: frozenset[str] = field(default_factory=frozenset)
    ignore_rules: frozenset[str] = field(default_factory=frozenset)
    cache_dir: Path = field(default_factory=lambda: Path.home() / ".cache" / "poetry-guard")

    def with_cli_overrides(
        self,
        accept_risk: tuple[str, ...] = (),
        no_guard: bool = False,
        offline: bool | None = None,
    ) -> GuardConfig:
        return replace(
            self,
            enabled=False if no_guard else self.enabled,
            offline=self.offline if offline is None else offline,
            accept_risk=self.accept_risk | frozenset(accept_risk),
        )


def load_from_pyproject(pyproject_path: Path) -> GuardConfig:
    if not pyproject_path.is_file():
        return GuardConfig()
    raw = tomllib.loads(pyproject_path.read_text())
    section = raw.get("tool", {}).get("poetry-guard")
    if section is None:
        return GuardConfig()
    return _from_mapping(dict(section))


def _from_mapping(data: dict[str, Any]) -> GuardConfig:
    kwargs: dict[str, Any] = {}
    if "enabled" in data:
        kwargs["enabled"] = bool(data["enabled"])
    if "offline" in data:
        kwargs["offline"] = bool(data["offline"])
    if "osv_url" in data:
        kwargs["osv_url"] = str(data["osv_url"])
    if "osv_severity" in data:
        kwargs["osv_severity"] = Severity(str(data["osv_severity"]))
    if "guarddog_severity" in data:
        kwargs["guarddog_severity"] = Severity(str(data["guarddog_severity"]))
    if "guarddog_risk_threshold" in data:
        kwargs["guarddog_risk_threshold"] = int(data["guarddog_risk_threshold"])
    if "min_age_days" in data:
        kwargs["min_age_days"] = int(data["min_age_days"])
    if "accept_risk" in data:
        kwargs["accept_risk"] = frozenset(str(x) for x in data["accept_risk"])
    if "ignore_rules" in data:
        kwargs["ignore_rules"] = frozenset(str(x) for x in data["ignore_rules"])
    if "cache_dir" in data:
        kwargs["cache_dir"] = Path(str(data["cache_dir"])).expanduser()
    return GuardConfig(**kwargs)
