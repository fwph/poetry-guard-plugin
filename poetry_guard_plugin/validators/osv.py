from dataclasses import dataclass

import aiohttp

from poetry_guard_plugin.config import GuardConfig
from poetry_guard_plugin.validators.base import Finding, LockfileValidator, PackageRef, RuleSpec, Severity

_RULES = (
    RuleSpec(
        rule_id="malicious",
        default_severity=Severity.CRITICAL,
        description="OSV record from the malicious-packages feed (MAL-*)",
    ),
    RuleSpec(
        rule_id="vulnerable",
        default_severity=Severity.MODERATE,
        description="OSV record (CVE/GHSA/PYSEC) affects this version",
    ),
)


@dataclass
class OsvValidator(LockfileValidator):
    config: GuardConfig
    name: str = "osv"
    rules_version: str = "1"
    rules: tuple[RuleSpec, ...] = _RULES

    async def validate(
        self,
        resolved: tuple[PackageRef, ...],
        prior: dict[str, PackageRef],
    ) -> tuple[Finding, ...]:
        if self.config.offline or not resolved:
            return ()
        payload = {
            "queries": [{"package": {"ecosystem": "PyPI", "name": p.name}, "version": p.version} for p in resolved]
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(self.config.osv_url, json=payload, timeout=aiohttp.ClientTimeout(total=15)) as r:
                r.raise_for_status()
                data = await r.json()
        return self._parse(resolved, data)

    def _parse(
        self,
        resolved: tuple[PackageRef, ...],
        data: dict[str, object],
    ) -> tuple[Finding, ...]:
        raw_results = data.get("results")
        results: list[dict[str, object]] = list(raw_results) if isinstance(raw_results, list) else []
        findings: list[Finding] = []
        for pkg, result in zip(resolved, results, strict=True):
            vulns_raw = (result or {}).get("vulns") if isinstance(result, dict) else None
            vulns: list[dict[str, object]] = list(vulns_raw) if isinstance(vulns_raw, list) else []
            for v in vulns:
                vuln_id = str(v.get("id", ""))
                is_malicious = vuln_id.startswith("MAL-")
                rule_id = "malicious" if is_malicious else "vulnerable"
                severity = Severity.CRITICAL if is_malicious else self.config.osv_severity
                findings.append(
                    Finding(
                        validator=self.name,
                        rule_id=rule_id,
                        severity=severity,
                        package_name=pkg.name,
                        package_version=pkg.version,
                        message=f"OSV {vuln_id} affects {pkg.key}",
                        detail={"osv_id": vuln_id, "modified": str(v.get("modified", ""))},
                    )
                )
        return tuple(findings)
