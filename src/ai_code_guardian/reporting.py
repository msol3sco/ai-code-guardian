import json
from urllib.parse import quote

from . import __version__
from .model import RULES, Report

SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/"
    "sarif-2.1/schema/sarif-schema-2.1.0.json"
)


def visible(value: str) -> str:
    # Quote control characters in human output, including terminal escapes.
    return "".join(char if char.isprintable() else ascii(char)[1:-1] for char in value)


def text_report(report: Report) -> str:
    lines = [
        f"{visible(item.path)}:{item.line}: {item.severity} {item.rule_id} "
        f"{item.rule.message}{' ' + item.detail if item.detail else ''}"
        for item in report.findings
    ]
    lines.extend(f"Note: {visible(note)}" for note in report.notes)
    lines.extend(f"Error: {visible(error)}" for error in report.errors)
    if report.suppressed_findings:
        lines.append(f"{report.suppressed_findings} finding(s) suppressed by policy.")
    lines.append(
        f"{len(report.findings)} finding(s), {report.files_scanned} source file(s) scanned, "
        f"{report.files_skipped} file(s) skipped."
    )
    return "\n".join(lines) + "\n"


def json_report(report: Report) -> dict:
    return {
        "tool": "AI Code Guardian",
        "version": __version__,
        "findings": [
            {
                "rule_id": item.rule_id,
                "severity": item.severity,
                "message": item.rule.message,
                "path": item.path,
                "line": item.line,
                **({"detail": item.detail} if item.detail else {}),
            }
            for item in report.findings
        ],
        "files_scanned": report.files_scanned,
        "files_skipped": report.files_skipped,
        "suppressed_findings": report.suppressed_findings,
        "notes": report.notes,
        "errors": report.errors,
    }


def sarif_report(report: Report) -> dict:
    notifications = [
        {"level": level, "message": {"text": message}}
        for level, messages in (("warning", report.notes), ("error", report.errors))
        for message in messages
    ]
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            **({"properties": {"suppressed_findings": report.suppressed_findings}} if report.suppressed_findings else {}),
            "tool": {
                "driver": {
                    "name": "AI Code Guardian",
                    "semanticVersion": __version__,
                    "rules": [
                        {
                            "id": rule_id,
                            "shortDescription": {"text": rule.title},
                            "fullDescription": {"text": rule.message},
                            "defaultConfiguration": {"level": rule.severity},
                        }
                        for rule_id, rule in RULES.items()
                    ],
                },
            },
            "invocations": [{
                "executionSuccessful": not report.errors,
                "exitCode": report.exit_code,
                "toolExecutionNotifications": notifications,
            }],
            "results": [
                {
                    "ruleId": item.rule_id,
                    "level": item.severity,
                    "message": {"text": " ".join(filter(None, (item.rule.message, item.detail)))},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": quote(item.path, safe="/", errors="surrogatepass")},
                            "region": {"startLine": item.line},
                        },
                    }],
                }
                for item in report.findings
            ],
        }],
    }


def github_escape(value: str, *, property_value: bool = False) -> str:
    value = value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    if property_value:
        value = value.replace(":", "%3A").replace(",", "%2C")
    return value


def github_annotations(report: Report) -> str:
    limits = {"error": 10, "warning": 10}
    lines = []
    if report.errors:
        lines.append("::error title=Guardian scan incomplete::See the scan report for details.")
        limits["error"] -= 1

    omitted = 0
    for item in report.findings:
        level = item.severity
        if limits[level] == 0:
            omitted += 1
            continue
        path = github_escape(item.path, property_value=True)
        title = github_escape(f"{item.rule_id} {item.rule.title}", property_value=True)
        message = github_escape(item.rule.message)
        lines.append(f"::{level} file={path},line={item.line},title={title}::{message}")
        limits[level] -= 1

    lines.append(
        f"AI Code Guardian found {len(report.findings)} issue(s) and suppressed "
        f"{report.suppressed_findings} finding(s) by policy."
    )
    if omitted:
        lines.append(f"{omitted} finding(s) omitted from annotations. See the full scan report.")
    return "\n".join(lines) + "\n"


def render(report: Report, format_: str) -> str:
    report.findings.sort()
    if format_ == "text":
        return text_report(report)
    payload = sarif_report(report) if format_ == "sarif" else json_report(report)
    return json.dumps(payload, indent=2) + "\n"
