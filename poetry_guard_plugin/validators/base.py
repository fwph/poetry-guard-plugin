from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        members = tuple(self.__class__)
        return members.index(self) < members.index(other)

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        members = tuple(self.__class__)
        return members.index(self) <= members.index(other)

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        members = tuple(self.__class__)
        return members.index(self) > members.index(other)

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        members = tuple(self.__class__)
        return members.index(self) >= members.index(other)


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
        return max(f.severity for f in self.findings)


@dataclass(frozen=True)
class PackageRef:
    name: str
    version: str

    @property
    def key(self) -> str:
        return f"{self.name}@{self.version}"


class LockfileValidator(ABC):
    name: str
    rules_version: str
    rules: tuple[RuleSpec, ...]

    def non_cacheable_rule_ids(self) -> frozenset[str]:
        return frozenset()

    def lockfile_cache_context_hash(self) -> str | None:
        return None

    @abstractmethod
    async def validate(
        self,
        resolved: tuple[PackageRef, ...],
        prior: dict[str, PackageRef],
    ) -> tuple[Finding, ...]:
        raise NotImplementedError


class ArtifactValidator(ABC):
    name: str
    rules_version: str
    rules: tuple[RuleSpec, ...]

    @abstractmethod
    async def validate(
        self,
        package: PackageRef,
        artifact_path: Path,
    ) -> tuple[Finding, ...]:
        raise NotImplementedError
