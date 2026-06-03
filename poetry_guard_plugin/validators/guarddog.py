"""GuardDog artifact validator.

Shells out to the `guarddog` CLI (DataDog/guarddog). The JSON output shape on
v2.10 is roughly:

    {
        "issues": int,                           # total non-empty results
        "errors": {rule: errmsg, ...},
        "results": {rule_id: None | list | dict, ...},
        "package": str,
        "path": str,
    }

For source rules, a populated result is a list of {location, code, message}.
For metadata rules, it's rule-specific: a non-empty list/dict means the rule
fired, an empty/None value means it did not.

GuardDog v3 (alpha as of 2026-05-26, see DataDog/guarddog #706 / #742) replaces
this with a risk-correlation engine emitting a single 0-10 score per package
along MITRE ATT&CK chains. When v3 ships, swap the parser in `_parse_v2` for a
`_parse_v3` that thresholds on `risk_threshold`. Everything else in this module
should stay put.
"""

import asyncio
import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from poetry_guard_plugin.config import GuardConfig
from poetry_guard_plugin.validators.base import Finding, PackageRef, RuleSpec, Severity

_SOURCE_RULES = {
    "api-obfuscation",
    "shady-links",
    "pyarmor",
    "obfuscation",
    "clipboard-access",
    "exfiltrate-sensitive-data",
    "download-executable",
    "exec-base64",
    "silent-process-execution",
    "dll-hijacking",
    "screenshot",
    "steganography",
    "code-execution",
    "unicode",
    "cmd-overwrite",
    "suspicious_passwd_access_linux",
}

_METADATA_RULES = {
    "empty_information",
    "release_zero",
    "typosquatting",
    "potentially_compromised_email_domain",
    "unclaimed_maintainer_email_domain",
    "repository_integrity_mismatch",
    "single_python_file",
    "bundled_binary",
    "deceptive_author",
}

_HIGH_SEVERITY_SOURCE = {
    "exec-base64",
    "exfiltrate-sensitive-data",
    "download-executable",
    "silent-process-execution",
    "code-execution",
    "cmd-overwrite",
    "steganography",
    "dll-hijacking",
    "suspicious_passwd_access_linux",
}

_HIGH_SEVERITY_METADATA = {
    "potentially_compromised_email_domain",
    "unclaimed_maintainer_email_domain",
    "typosquatting",
}


def _rules() -> tuple[RuleSpec, ...]:
    out: list[RuleSpec] = []
    for r in _SOURCE_RULES:
        sev = Severity.HIGH if r in _HIGH_SEVERITY_SOURCE else Severity.MODERATE
        out.append(RuleSpec(rule_id=r, default_severity=sev, description=f"GuardDog source rule {r}"))
    for r in _METADATA_RULES:
        sev = Severity.HIGH if r in _HIGH_SEVERITY_METADATA else Severity.LOW
        out.append(RuleSpec(rule_id=r, default_severity=sev, description=f"GuardDog metadata rule {r}"))
    return tuple(out)


_RULES = _rules()
_RULE_SEVERITY: dict[str, Severity] = {r.rule_id: r.default_severity for r in _RULES}


@dataclass
class GuardDogValidator:
    config: GuardConfig
    name: str = "guarddog"
    rules_version: str = "v2.10"
    rules: tuple[RuleSpec, ...] = _RULES

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
        stdout, _ = await proc.communicate()
        if not stdout:
            return ()
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            return ()
        return self._parse_v2(package, data)

    def _parse_v2(self, package: PackageRef, data: dict[str, Any]) -> tuple[Finding, ...]:
        results = data.get("results") or {}
        findings: list[Finding] = []
        for rule_id, value in results.items():
            if not value:
                continue
            severity = self._severity_for(rule_id)
            message, detail = self._describe(rule_id, value)
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

    def _severity_for(self, rule_id: str) -> Severity:
        return _RULE_SEVERITY.get(rule_id, Severity.LOW)

    @staticmethod
    def _describe(rule_id: str, value: object) -> tuple[str, dict[str, object]]:
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
