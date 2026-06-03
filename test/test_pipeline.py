from dataclasses import dataclass
from pathlib import Path

import pytest

from poetry_guard_plugin.cache import VerdictCache
from poetry_guard_plugin.config import GuardConfig
from poetry_guard_plugin.exceptions import LockValidationError
from poetry_guard_plugin.pipeline import Pipeline, raise_for_lock
from poetry_guard_plugin.validators.base import (
    Finding,
    PackageRef,
    RuleSpec,
    Severity,
)


@dataclass
class StubLockfileValidator:
    findings_for: dict[str, tuple[Finding, ...]]
    name: str = "stub"
    rules_version: str = "1"
    rules: tuple[RuleSpec, ...] = ()

    async def validate(
        self,
        resolved: tuple[PackageRef, ...],
        prior: dict[str, PackageRef],
    ) -> tuple[Finding, ...]:
        out: list[Finding] = []
        for p in resolved:
            out.extend(self.findings_for.get(p.key, ()))
        return tuple(out)


@dataclass
class StubArtifactValidator:
    findings_for: dict[str, tuple[Finding, ...]]
    name: str = "stub-art"
    rules_version: str = "1"
    rules: tuple[RuleSpec, ...] = ()

    async def validate(
        self,
        package: PackageRef,
        artifact_path: Path,
    ) -> tuple[Finding, ...]:
        return self.findings_for.get(package.key, ())


def _f(pkg: str, ver: str, severity: Severity = Severity.HIGH, validator: str = "stub") -> Finding:
    return Finding(
        validator=validator,
        rule_id="r",
        severity=severity,
        package_name=pkg,
        package_version=ver,
        message="m",
    )


@pytest.mark.asyncio
async def test_lockfile_findings_cached_and_replayed(tmp_path: Path) -> None:
    pkg = PackageRef("a", "1")
    finding = _f("a", "1")
    sv = StubLockfileValidator(findings_for={pkg.key: (finding,)})
    cache = VerdictCache(tmp_path)
    pipeline = Pipeline(
        config=GuardConfig(),
        cache=cache,
        lockfile_validators=(sv,),
    )
    first = await pipeline.run_lockfile([pkg], {})
    sv.findings_for = {}  # next call would return nothing if cache miss
    second = await pipeline.run_lockfile([pkg], {})
    assert len(first) == 1 == len(second)
    assert first[0].rule_id == second[0].rule_id


@pytest.mark.asyncio
async def test_artifact_findings_cached_by_sha(tmp_path: Path) -> None:
    pkg = PackageRef("a", "1")
    artifact = tmp_path / "art.tar.gz"
    artifact.write_bytes(b"hello")
    av = StubArtifactValidator(findings_for={pkg.key: (_f("a", "1", validator="stub-art"),)})
    cache = VerdictCache(tmp_path / "cache")
    calls = {"n": 0}

    def fetch(p: PackageRef) -> Path:
        calls["n"] += 1
        return artifact

    pipeline = Pipeline(
        config=GuardConfig(),
        cache=cache,
        artifact_validators=(av,),
        fetch_artifact=fetch,
    )
    a = await pipeline.run_artifact([pkg])
    av.findings_for = {}
    b = await pipeline.run_artifact([pkg])
    assert len(a) == 1 == len(b)
    assert calls["n"] == 2  # fetch is called each time, but validator output cached on sha


def test_aggregate_blocks_high_severity(tmp_path: Path) -> None:
    cache = VerdictCache(tmp_path)
    pipeline = Pipeline(config=GuardConfig(), cache=cache)
    findings = (_f("p", "1", Severity.HIGH, validator="osv"),)
    result = pipeline.aggregate(findings)
    assert result.blocked == findings
    with pytest.raises(LockValidationError):
        raise_for_lock(result)


def test_aggregate_accepts_via_accept_risk(tmp_path: Path) -> None:
    cache = VerdictCache(tmp_path)
    pipeline = Pipeline(
        config=GuardConfig(accept_risk=frozenset({"p@1"})),
        cache=cache,
    )
    findings = (_f("p", "1", Severity.CRITICAL, validator="osv"),)
    result = pipeline.aggregate(findings)
    assert result.blocked == ()
    assert result.accepted == findings


def test_aggregate_ignore_rules(tmp_path: Path) -> None:
    cache = VerdictCache(tmp_path)
    pipeline = Pipeline(
        config=GuardConfig(ignore_rules=frozenset({"r"})),
        cache=cache,
    )
    findings = (_f("p", "1", Severity.HIGH, validator="osv"),)
    result = pipeline.aggregate(findings)
    assert result.blocked == ()


def test_aggregate_low_severity_does_not_block(tmp_path: Path) -> None:
    cache = VerdictCache(tmp_path)
    pipeline = Pipeline(config=GuardConfig(), cache=cache)
    findings = (_f("p", "1", Severity.LOW, validator="metadata"),)
    result = pipeline.aggregate(findings)
    assert result.blocked == ()
    assert result.accepted == findings
