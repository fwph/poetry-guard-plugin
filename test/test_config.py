from pathlib import Path

from poetry_guard_plugin.config import GuardConfig, load_from_pyproject
from poetry_guard_plugin.validators.base import Severity


def test_defaults_when_section_absent(tmp_path: Path) -> None:
    pp = tmp_path / "pyproject.toml"
    pp.write_text('[tool.poetry]\nname="x"\n')
    config = load_from_pyproject(pp)
    assert config.enabled is True
    assert config.osv_severity is Severity.MODERATE
    assert config.guarddog_severity is Severity.HIGH


def test_loads_full_section(tmp_path: Path) -> None:
    pp = tmp_path / "pyproject.toml"
    pp.write_text(
        "[tool.poetry-guard]\n"
        "enabled = false\n"
        "offline = true\n"
        'osv_severity = "high"\n'
        'guarddog_severity = "critical"\n'
        "min_age_days = 5\n"
        'accept_risk = ["pkg@1.0"]\n'
        'ignore_rules = ["typosquatting"]\n'
    )
    config = load_from_pyproject(pp)
    assert config.enabled is False
    assert config.offline is True
    assert config.osv_severity is Severity.HIGH
    assert config.guarddog_severity is Severity.CRITICAL
    assert config.min_age_days == 5
    assert config.accept_risk == frozenset({"pkg@1.0"})
    assert config.ignore_rules == frozenset({"typosquatting"})


def test_cli_overrides_compose() -> None:
    base = GuardConfig(accept_risk=frozenset({"a@1"}))
    overridden = base.with_cli_overrides(accept_risk=("b@2",), no_guard=True, offline=True)
    assert overridden.enabled is False
    assert overridden.offline is True
    assert overridden.accept_risk == frozenset({"a@1", "b@2"})
