import json
from dataclasses import dataclass, field, replace
from datetime import date, datetime, timezone
from fnmatch import fnmatchcase
from pathlib import PurePosixPath

from .model import RULES, GuardianError, Report

POLICY_NAME = ".ai-code-guardian.json"
MAX_POLICY_BYTES = 64 * 1024
SOURCE_RULES = RULES.keys() - {"ACG201"}
LEVELS = {"off", "warning", "error"}


def path_matches(pattern: tuple[str, ...], path: tuple[str, ...]) -> bool:
    positions = {0}
    for part in pattern:
        if part == "**":
            positions = set(range(min(positions), len(path) + 1))
        else:
            positions = {
                index + 1 for index in positions
                if index < len(path) and fnmatchcase(path[index], part)
            }
        if not positions:
            return False
    return len(path) in positions


@dataclass(frozen=True)
class Suppression:
    rule: str
    pattern: tuple[str, ...]
    expires: date
    line: int | None


@dataclass
class Policy:
    levels: dict[str, str] = field(default_factory=dict)
    suppressions: tuple[Suppression, ...] = ()

    def apply(self, report: Report, *, path_prefix: PurePosixPath | None = PurePosixPath()) -> None:
        today = datetime.now(timezone.utc).date()
        active: dict[str, list[Suppression]] = {}
        expired = 0
        for item in self.suppressions:
            if item.expires >= today:
                active.setdefault(item.rule, []).append(item)
            else:
                expired += 1
        if expired:
            report.notes.append(f"{expired} policy suppression(s) expired and were ignored.")

        findings = []
        for finding in report.findings:
            level = self.levels.get(finding.rule_id)
            if level == "off":
                report.suppressed_findings += 1
                continue
            candidates = active.get(finding.rule_id, ())
            if path_prefix is not None and candidates:
                path = (path_prefix / finding.path).parts
                if any(
                    (item.line is None or item.line == finding.line)
                    and path_matches(item.pattern, path)
                    for item in candidates
                ):
                    report.suppressed_findings += 1
                    continue
            findings.append(replace(finding, override_level=level) if level else finding)
        report.findings = findings


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise GuardianError("Policy JSON contains a duplicate key.")
        obj[key] = value
    return obj


def read_policy(data: bytes) -> Policy:
    if len(data) > MAX_POLICY_BYTES:
        raise GuardianError("Policy file exceeds 64 KiB.")
    try:
        value = json.loads(data.decode("utf-8-sig"), object_pairs_hook=unique_object)
    except (ValueError, RecursionError):
        raise GuardianError("Policy file must contain a valid UTF-8 JSON object.") from None
    if not isinstance(value, dict) or value.keys() - {"rules", "suppressions"}:
        raise GuardianError("Policy must be an object with optional 'rules' and 'suppressions' keys.")
    levels = value.get("rules", {})
    if not isinstance(levels, dict) or any(
        rule not in SOURCE_RULES or not isinstance(level, str) or level not in LEVELS
        for rule, level in levels.items()
    ):
        raise GuardianError("Policy 'rules' must map source rule IDs to 'off', 'warning', or 'error'.")
    entries = value.get("suppressions", [])
    if not isinstance(entries, list):
        raise GuardianError("Policy 'suppressions' must be an array.")
    return Policy(levels, tuple(read_suppression(entry, index) for index, entry in enumerate(entries, 1)))


def read_suppression(entry: object, index: int) -> Suppression:
    required = {"rule", "path", "reason", "expires"}
    label = f"Policy suppression #{index}"
    if not isinstance(entry, dict) or required - entry.keys() or entry.keys() - (required | {"line"}):
        raise GuardianError(f"{label} requires 'rule', 'path', 'reason', 'expires' and optionally 'line'.")
    rule = entry["rule"]
    if not isinstance(rule, str) or rule not in SOURCE_RULES:
        raise GuardianError(f"{label} must name a known source rule.")
    path = entry["path"]
    if not isinstance(path, str):
        raise GuardianError(f"{label} must have a repository-relative path pattern.")
    parts = tuple(path.split("/"))
    if (
        not path.isprintable() or path != path.strip() or "\\" in path or ":" in path
        or any(part in {"", ".", ".."} or ("**" in part and part != "**") for part in parts)
    ):
        raise GuardianError(f"{label} must have a repository-relative POSIX path pattern.")
    reason = entry["reason"]
    if not isinstance(reason, str) or not reason.strip():
        raise GuardianError(f"{label} requires a non-empty reason.")
    line = entry.get("line")
    if "line" in entry and (type(line) is not int or line < 1):
        raise GuardianError(f"{label} must use a positive integer for 'line'.")
    try:
        expires = date.fromisoformat(entry["expires"])
        if expires.isoformat() != entry["expires"]:
            raise ValueError
    except (ValueError, TypeError):
        raise GuardianError(f"{label} expiry must be a valid date in YYYY-MM-DD form.") from None
    return Suppression(rule, parts, expires, line)
