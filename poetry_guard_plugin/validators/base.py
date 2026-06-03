from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Protocol, runtime_checkable


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        order = [Severity.INFO, Severity.LOW, Severity.MODERATE, Severity.HIGH, Severity.CRITICAL]
        return order.index(self)

    def at_least(self, threshold: "Severity") -> bool:
        return self.rank >= threshold.rank


@dataclass(frozen=True)
class RuleSpec:
    rule_id: str
    default_severity: Severity
    description: str = ""


@dataclass(frozen=True)
class Finding:
    validator: str
    rule_id: str
    severity: Severity
    package_name: str
    package_version: str
    message: str
    detail: dict[str, object] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.package_name}@{self.package_version}"


@dataclass(frozen=True)
class Verdict:
    package_name: str
    package_version: str
    findings: tuple[Finding, ...] = ()
    artifact_sha256: str | None = None

    @property
    def key(self) -> str:
        return f"{self.package_name}@{self.package_version}"

    def max_severity(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        return max((f.severity for f in self.findings), key=lambda s: s.rank)


@dataclass(frozen=True)
class PackageRef:
    name: str
    version: str

    @property
    def key(self) -> str:
        return f"{self.name}@{self.version}"


@runtime_checkable
class LockfileValidator(Protocol):
    name: str
    rules_version: str
    rules: tuple[RuleSpec, ...]

    async def validate(
        self,
        resolved: tuple[PackageRef, ...],
        prior: dict[str, PackageRef],
    ) -> tuple[Finding, ...]: ...


@runtime_checkable
class ArtifactValidator(Protocol):
    name: str
    rules_version: str
    rules: tuple[RuleSpec, ...]

    async def validate(
        self,
        package: PackageRef,
        artifact_path: Path,
    ) -> tuple[Finding, ...]: ...
