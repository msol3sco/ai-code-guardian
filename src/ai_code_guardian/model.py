from dataclasses import dataclass, field


class GuardianError(Exception):
    """An operational error with a message safe to show."""


@dataclass(frozen=True)
class Rule:
    title: str
    severity: str
    message: str


RULES = {
    "ACG001": Rule("Private key marker", "error", "Private key marker found. Remove the key and rotate it if exposed."),
    "ACG002": Rule("Credential format", "error", "A provider credential format was found. Verify, remove and rotate if exposed."),
    "ACG003": Rule("Credential assignment", "warning", "Possible hard-coded credential. Load secrets from a protected source."),
    "ACG101": Rule("Dynamic Python execution", "warning", "Review dynamic code execution. Prefer explicit parsing or dispatch."),
    "ACG102": Rule("Shell invocation", "warning", "Review shell invocation. Prefer a subprocess argument list without a shell."),
    "ACG103": Rule("Pickle deserialization", "warning", "Avoid deserializing pickle data from untrusted sources."),
    "ACG104": Rule("TLS verification disabled", "warning", "Keep TLS certificate verification enabled."),
    "ACG201": Rule("Known dependency advisory", "error", "A known advisory affects this pinned dependency."),
}


@dataclass(frozen=True, order=True)
class Finding:
    path: str
    line: int
    rule_id: str
    detail: str = ""
    override_level: str | None = field(default=None, compare=False)

    @property
    def rule(self) -> Rule:
        return RULES[self.rule_id]

    @property
    def severity(self) -> str:
        return self.override_level or self.rule.severity


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0
    suppressed_findings: int = 0

    def skip(self, reason: str) -> None:
        self.files_skipped += 1
        self.notes.append(reason)

    @property
    def exit_code(self) -> int:
        if self.errors:
            return 2
        return int(bool(self.findings))
