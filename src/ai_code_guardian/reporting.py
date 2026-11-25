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
        f"{visible(item.path)}:{item.line}: {item.rule.severity} {item.rule_id} "
        f"{item.rule.message}{' ' + item.detail if item.detail else ''}"
        for item in report.findings
    ]
    lines.extend(f"Note: {visible(note)}" for note in report.notes)
    lines.extend(f"Error: {visible(error)}" for error in report.errors)
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
                "severity": item.rule.severity,
                "message": item.rule.message,
                "path": item.path,
                "line": item.line,
                **({"detail": item.detail} if item.detail else {}),
            }
            for item in report.findings
        ],
        "files_scanned": report.files_scanned,
        "files_skipped": report.files_skipped,
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
                    "level": item.rule.severity,
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


def render(report: Report, format_: str) -> str:
    report.findings.sort()
    if format_ == "text":
        return text_report(report)
    payload = sarif_report(report) if format_ == "sarif" else json_report(report)
    return json.dumps(payload, indent=2) + "\n"
