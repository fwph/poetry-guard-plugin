"""GuardDog artifact validator.

GuardDog v3 emits both low-level rule matches under ``results`` and correlated
package risks under ``risks`` plus an aggregate ``risk_score`` payload. The
correlated risks are the useful signal for Poetry Guard because they already
combine capability and threat evidence and provide a severity label.
"""

import asyncio
import hashlib
import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from poetry_guard_plugin.config import GuardConfig
from poetry_guard_plugin.validators.base import ArtifactValidator, Finding, PackageRef, RuleSpec, Severity


def _rules() -> tuple[RuleSpec, ...]:
    return (
        RuleSpec(rule_id="guarddog-low-risk", default_severity=Severity.LOW, description="GuardDog low-risk package"),
        RuleSpec(
            rule_id="guarddog-medium-risk",
            default_severity=Severity.MODERATE,
            description="GuardDog medium-risk package",
        ),
        RuleSpec(
            rule_id="guarddog-high-risk",
            default_severity=Severity.HIGH,
            description="GuardDog high-risk package",
        ),
    )


_RULES = _rules()


@dataclass
class GuardDogValidator(ArtifactValidator):
    config: GuardConfig
    name: str = "guarddog"
    rules_version: str = "v3.0"
    rules: tuple[RuleSpec, ...] = _RULES

    def artifact_cache_context_hash(self) -> str:
        payload = json.dumps(
            {"guarddog_risk_threshold": self.config.guarddog_risk_threshold},
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    async def validate(
        self,
        package: PackageRef,
        artifact_path: Path,
    ) -> tuple[Finding, ...]:
        binary = shutil.which("guarddog")
        if binary is None:
            return ()
        proc = await asyncio.create_subprocess_exec(
            binary,
            "pypi",
            "scan",
            str(artifact_path),
            "--output-format",
            "json",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if not stdout:
            raise RuntimeError(
                f"guarddog produced no output (exit {proc.returncode}): " f"{stderr.decode(errors='replace')[:300]}"
            )
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError as e:
            raise RuntimeError(f"guarddog output is not valid JSON: {e}") from e
        errors: dict[str, object] = dict(data.get("errors") or {})
        if errors:
            summary = "; ".join(f"{k}: {v}" for k, v in errors.items())
            raise RuntimeError(f"guarddog scan incomplete — {summary}")
        if "risk_score" in data or "risks" in data:
            return self._parse_v3(package, data)
        return self._parse_v2_compat(package, data)

    def _parse_v3(self, package: PackageRef, data: dict[str, Any]) -> tuple[Finding, ...]:
        risk_score = data.get("risk_score")
        if not isinstance(risk_score, dict):
            return ()
        raw_score = risk_score.get("score")
        if not isinstance(raw_score, int | float):
            return ()
        if raw_score < self.config.guarddog_risk_threshold:
            return ()

        risks = data.get("risks")
        if not isinstance(risks, list):
            return ()

        findings: list[Finding] = []
        aggregate_severity = self._severity_from_label(risk_score.get("label"))
        for risk in risks:
            if not isinstance(risk, dict):
                continue
            rule_id = str(risk.get("threat_rule") or risk.get("name") or "guarddog-risk")
            severity = self._severity_from_label(risk.get("severity")) or aggregate_severity
            message = self._message_for_risk(rule_id, risk)
            detail: dict[str, object] = {
                "risk": risk,
                "risk_score": risk_score,
            }
            findings.append(
                Finding(
                    validator=self.name,
                    rule_id=rule_id,
                    severity=severity,
                    package_name=package.name,
                    package_version=package.version,
                    message=message,
                    detail=detail,
                )
            )
        return tuple(findings)

    def _parse_v2_compat(self, package: PackageRef, data: dict[str, Any]) -> tuple[Finding, ...]:
        results = data.get("results")
        if not isinstance(results, dict):
            return ()
        findings: list[Finding] = []
        for rule_id, value in results.items():
            if not value:
                continue
            severity = Severity.HIGH if "threat" in rule_id or "download-exec" in rule_id else Severity.MODERATE
            if "metadata" in rule_id:
                severity = Severity.LOW
            message, detail = self._describe_compat(rule_id, value)
            findings.append(
                Finding(
                    validator=self.name,
                    rule_id=str(rule_id),
                    severity=severity,
                    package_name=package.name,
                    package_version=package.version,
                    message=message,
                    detail=detail,
                )
            )
        return tuple(findings)

    @staticmethod
    def _severity_from_label(label: object) -> Severity:
        if label in ("high", "high_risk"):
            return Severity.HIGH
        if label in ("medium", "medium_risk"):
            return Severity.MODERATE
        if label in ("low", "low_risk"):
            return Severity.LOW
        return Severity.LOW

    @staticmethod
    def _message_for_risk(rule_id: str, risk: dict[str, Any]) -> str:
        description = risk.get("threat_description")
        location = risk.get("threat_location") or risk.get("file_path")
        if isinstance(description, str) and description:
            if isinstance(location, str) and location:
                return f"GuardDog {rule_id}: {description} ({location})"
            return f"GuardDog {rule_id}: {description}"
        name = str(risk.get("name") or rule_id)
        if isinstance(location, str) and location:
            return f"GuardDog {name} ({location})"
        return f"GuardDog {name}"

    @staticmethod
    def _describe_compat(rule_id: object, value: object) -> tuple[str, dict[str, object]]:
        if isinstance(value, list):
            count = len(value)
            first_loc = ""
            if value and isinstance(value[0], dict):
                first_loc = str(value[0].get("location", ""))
            msg = f"GuardDog {rule_id}: {count} match(es)"
            if first_loc:
                msg += f" (first at {first_loc})"
            return msg, {"matches": value}
        if isinstance(value, dict):
            return f"GuardDog {rule_id}: {value}", {"detail": value}
        return f"GuardDog {rule_id}", {"value": value}
