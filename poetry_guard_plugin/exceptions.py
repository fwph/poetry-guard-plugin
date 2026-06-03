from poetry_guard_plugin.validators.base import Finding


class PoetryGuardError(Exception):
    pass


class ValidationError(PoetryGuardError):
    def __init__(self, findings: tuple[Finding, ...]) -> None:
        self.findings = findings
        super().__init__(self._render(findings))

    @staticmethod
    def _render(findings: tuple[Finding, ...]) -> str:
        lines = ["poetry-guard: validation failed"]
        for f in findings:
            lines.append(f"  [{f.severity.value}] {f.key} :: {f.validator}/{f.rule_id} -- {f.message}")
        lines.append("set POETRY_GUARD_ACCEPT_RISK=<pkg@version>[,...] to bypass per package")
        return "\n".join(lines)


class LockValidationError(ValidationError):
    pass


class ArtifactValidationError(ValidationError):
    pass
