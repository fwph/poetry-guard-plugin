from pathlib import Path

from poetry_guard_plugin.cache import VerdictCache
from poetry_guard_plugin.validators.base import Finding, PackageRef, Severity


def _finding(rule: str = "r1", severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        validator="osv",
        rule_id=rule,
        severity=severity,
        package_name="pkg",
        package_version="1.0",
        message="m",
        detail={"k": "v"},
    )


def test_artifact_round_trip(tmp_path: Path) -> None:
    cache = VerdictCache(tmp_path)
    sha = "a" * 64
    assert cache.get_artifact("guarddog", "v2.10", sha) is None
    cache.put_artifact("guarddog", "v2.10", sha, (_finding(),))
    hit = cache.get_artifact("guarddog", "v2.10", sha)
    assert hit is not None
    assert len(hit) == 1
    assert hit[0].rule_id == "r1"


def test_lockfile_round_trip(tmp_path: Path) -> None:
    cache = VerdictCache(tmp_path)
    pkg = PackageRef(name="pkg", version="1.0")
    assert cache.get_lockfile("osv", "1", pkg) is None
    cache.put_lockfile("osv", "1", pkg, (_finding(),))
    hit = cache.get_lockfile("osv", "1", pkg)
    assert hit is not None and hit[0].severity is Severity.HIGH


def test_empty_findings_cached(tmp_path: Path) -> None:
    cache = VerdictCache(tmp_path)
    pkg = PackageRef(name="x", version="9")
    cache.put_lockfile("osv", "1", pkg, ())
    hit = cache.get_lockfile("osv", "1", pkg)
    assert hit == ()


def test_lockfile_read_can_skip_selected_rule_ids(tmp_path: Path) -> None:
    cache = VerdictCache(tmp_path)
    pkg = PackageRef(name="pkg", version="1.0")
    findings = (
        _finding(rule="too_new", severity=Severity.MODERATE),
        _finding(rule="repo_url_missing", severity=Severity.LOW),
    )
    cache.put_lockfile("metadata", "2", pkg, findings)
    hit = cache.get_lockfile("metadata", "2", pkg, skip_rule_ids=frozenset({"too_new"}))
    assert hit is not None
    assert [f.rule_id for f in hit] == ["repo_url_missing"]


def test_sha256_of_file(tmp_path: Path) -> None:
    p = tmp_path / "f.bin"
    p.write_bytes(b"hello")
    sha = VerdictCache.sha256_of(p)
    assert sha == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
