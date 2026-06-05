import hashlib
import json
from dataclasses import asdict
from pathlib import Path

from poetry_guard_plugin.validators.base import Finding, PackageRef, Severity


class VerdictCache:
    def __init__(self, root: Path) -> None:
        self._root = root

    @staticmethod
    def sha256_of(path: Path) -> str:
        with path.open("rb") as fh:
            return hashlib.file_digest(fh, "sha256").hexdigest()

    def _artifact_path(self, validator: str, rules_version: str, sha256: str) -> Path:
        return self._root / "artifact" / validator / rules_version / f"{sha256}.json"

    def _lockfile_path(self, validator: str, rules_version: str, package: PackageRef) -> Path:
        safe_name = package.name.replace("/", "_")
        return self._root / "lockfile" / validator / rules_version / f"{safe_name}@{package.version}.json"

    def get_artifact(self, validator: str, rules_version: str, sha256: str) -> tuple[Finding, ...] | None:
        return self._read(self._artifact_path(validator, rules_version, sha256))

    def put_artifact(
        self,
        validator: str,
        rules_version: str,
        sha256: str,
        findings: tuple[Finding, ...],
    ) -> None:
        self._write(self._artifact_path(validator, rules_version, sha256), findings)

    def get_lockfile(
        self,
        validator: str,
        rules_version: str,
        package: PackageRef,
    ) -> tuple[Finding, ...] | None:
        return self._read(self._lockfile_path(validator, rules_version, package))

    def put_lockfile(
        self,
        validator: str,
        rules_version: str,
        package: PackageRef,
        findings: tuple[Finding, ...],
    ) -> None:
        self._write(self._lockfile_path(validator, rules_version, package), findings)

    @staticmethod
    def _read(path: Path) -> tuple[Finding, ...] | None:
        if not path.is_file():
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        return tuple(_finding_from_dict(d) for d in data["findings"])

    @staticmethod
    def _write(path: Path, findings: tuple[Finding, ...]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"findings": [_finding_to_dict(f) for f in findings]}
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        tmp.replace(path)


def _finding_to_dict(f: Finding) -> dict[str, object]:
    d = asdict(f)
    d["severity"] = f.severity.value
    return d


def _finding_from_dict(d: dict[str, object]) -> Finding:
    raw_detail = d.get("detail")
    detail: dict[str, object] = dict(raw_detail) if isinstance(raw_detail, dict) else {}
    return Finding(
        validator=str(d["validator"]),
        rule_id=str(d["rule_id"]),
        severity=Severity(str(d["severity"])),
        package_name=str(d["package_name"]),
        package_version=str(d["package_version"]),
        message=str(d["message"]),
        detail=detail,
    )
