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
    volatile_rule_ids: frozenset[str] = frozenset()
    cache_context_hash: str | None = None
    calls: int = 0

    async def validate(
        self,
        resolved: tuple[PackageRef, ...],
        prior: dict[str, PackageRef],
    ) -> tuple[Finding, ...]:
        self.calls += 1
        out: list[Finding] = []
        for p in resolved:
            out.extend(self.findings_for.get(p.key, ()))
        return tuple(out)

    def non_cacheable_rule_ids(self) -> frozenset[str]:
        return self.volatile_rule_ids

    def lockfile_cache_context_hash(self) -> str | None:
        return self.cache_context_hash


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


@dataclass
class RaisingLockfileValidator:
    name: str = "raising"
    rules_version: str = "1"
    rules: tuple[RuleSpec, ...] = ()

    async def validate(
        self,
        resolved: tuple[PackageRef, ...],
        prior: dict[str, PackageRef],
    ) -> tuple[Finding, ...]:
        raise RuntimeError("boom")


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
async def test_non_cacheable_lockfile_rules_are_refreshed_without_duplicate_stable_findings(
    tmp_path: Path,
) -> None:
    pkg = PackageRef("a", "1")
    stable = Finding(
        validator="metadata",
        rule_id="repo_url_missing",
        severity=Severity.LOW,
        package_name="a",
        package_version="1",
        message="repo missing",
    )
    old_dynamic = Finding(
        validator="metadata",
        rule_id="too_new",
        severity=Severity.MODERATE,
        package_name="a",
        package_version="1",
        message="uploaded 0.1 days ago",
    )
    fresh_dynamic = Finding(
        validator="metadata",
        rule_id="too_new",
        severity=Severity.MODERATE,
        package_name="a",
        package_version="1",
        message="uploaded 1.1 days ago",
    )
    cache = VerdictCache(tmp_path)
    cache.put_lockfile("metadata", "2", pkg, (stable, old_dynamic))
    validator = StubLockfileValidator(
        findings_for={pkg.key: (stable, fresh_dynamic)},
        name="metadata",
        rules_version="3",
        volatile_rule_ids=frozenset({"too_new"}),
        cache_context_hash="ctx-3",
    )
    pipeline = Pipeline(
        config=GuardConfig(),
        cache=cache,
        lockfile_validators=(validator,),
    )

    findings = await pipeline.run_lockfile([pkg], {})

    assert [f.rule_id for f in findings] == ["repo_url_missing", "too_new"]
    assert [f.message for f in findings if f.rule_id == "too_new"] == ["uploaded 1.1 days ago"]


@pytest.mark.asyncio
async def test_offline_reuses_cached_stable_findings_without_rerunning_volatile_rules(tmp_path: Path) -> None:
    pkg = PackageRef("a", "1")
    stable = Finding(
        validator="metadata",
        rule_id="repo_url_missing",
        severity=Severity.LOW,
        package_name="a",
        package_version="1",
        message="repo missing",
    )
    validator = StubLockfileValidator(
        findings_for={pkg.key: (_f("a", "1", validator="metadata"),)},
        name="metadata",
        rules_version="3",
        volatile_rule_ids=frozenset({"too_new"}),
        cache_context_hash="ctx-3",
    )
    cache = VerdictCache(tmp_path)
    cache.put_lockfile("metadata", "3", pkg, (stable,), cache_context_hash="ctx-3")
    pipeline = Pipeline(
        config=GuardConfig(offline=True),
        cache=cache,
        lockfile_validators=(validator,),
    )

    findings = await pipeline.run_lockfile([pkg], {})

    assert findings == (stable,)
    assert validator.calls == 0
    cached = cache.get_lockfile("metadata", "3", pkg, cache_context_hash="ctx-3")
    assert cached == (stable,)


@pytest.mark.asyncio
async def test_lockfile_cache_is_scoped_by_validator_cache_context(tmp_path: Path) -> None:
    pkg = PackageRef("a", "1")
    cached_finding = _f("a", "1", validator="metadata")
    first_validator = StubLockfileValidator(
        findings_for={pkg.key: (cached_finding,)},
        name="metadata",
        rules_version="3",
        cache_context_hash="ctx-3",
    )
    cache = VerdictCache(tmp_path)
    pipeline = Pipeline(
        config=GuardConfig(),
        cache=cache,
        lockfile_validators=(first_validator,),
    )
    first = await pipeline.run_lockfile([pkg], {})
    assert first == (cached_finding,)

    second_validator = StubLockfileValidator(
        findings_for={},
        name="metadata",
        rules_version="3",
        cache_context_hash="ctx-7",
    )
    second_pipeline = Pipeline(
        config=GuardConfig(),
        cache=cache,
        lockfile_validators=(second_validator,),
    )

    second = await second_pipeline.run_lockfile([pkg], {})

    assert second == ()
    assert second_validator.calls == 1
    assert cache.get_lockfile("metadata", "3", pkg, cache_context_hash="ctx-3") == (cached_finding,)
    assert cache.get_lockfile("metadata", "3", pkg, cache_context_hash="ctx-7") == ()


@pytest.mark.asyncio
async def test_disabled_volatile_rule_uses_cache_without_rerun(tmp_path: Path) -> None:
    pkg = PackageRef("a", "1")
    finding = Finding(
        validator="metadata",
        rule_id="repo_url_missing",
        severity=Severity.LOW,
        package_name="a",
        package_version="1",
        message="repo missing",
    )
    validator = StubLockfileValidator(
        findings_for={pkg.key: ()},
        name="metadata",
        rules_version="3",
        volatile_rule_ids=frozenset(),
        cache_context_hash="ctx-0",
    )
    cache = VerdictCache(tmp_path)
    cache.put_lockfile("metadata", "3", pkg, (finding,), cache_context_hash="ctx-0")
    pipeline = Pipeline(
        config=GuardConfig(min_age_days=0),
        cache=cache,
        lockfile_validators=(validator,),
    )

    findings = await pipeline.run_lockfile([pkg], {})

    assert findings == (finding,)
    assert validator.calls == 0


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


@pytest.mark.asyncio
async def test_lockfile_validator_errors_propagate(tmp_path: Path) -> None:
    pkg = PackageRef("a", "1")
    cache = VerdictCache(tmp_path)
    pipeline = Pipeline(
        config=GuardConfig(),
        cache=cache,
        lockfile_validators=(RaisingLockfileValidator(),),
    )
    with pytest.raises(RuntimeError, match="boom"):
        await pipeline.run_lockfile([pkg], {})


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


def test_lockfile_check_count_scales_with_packages_and_validators(tmp_path: Path) -> None:
    cache = VerdictCache(tmp_path)
    pipeline = Pipeline(
        config=GuardConfig(),
        cache=cache,
        lockfile_validators=(
            StubLockfileValidator(findings_for={}),
            StubLockfileValidator(findings_for={}, name="stub-2"),
        ),
    )
    packages = (PackageRef("a", "1"), PackageRef("b", "2"), PackageRef("c", "3"))
    assert pipeline.lockfile_check_count(packages) == 6


def test_artifact_check_count_tracks_validator_count(tmp_path: Path) -> None:
    cache = VerdictCache(tmp_path)
    pipeline = Pipeline(
        config=GuardConfig(),
        cache=cache,
        artifact_validators=(
            StubArtifactValidator(findings_for={}),
            StubArtifactValidator(findings_for={}, name="stub-art-2"),
        ),
    )
    assert pipeline.artifact_check_count() == 2
