import ast
import re
from bisect import bisect_right
from pathlib import PurePosixPath

from .model import Finding, Report
from .session_tls import REQUEST_METHODS, disabled_verify_line, session_tls_findings

PRIVATE_KEY = re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----")
PROVIDER_TOKEN = re.compile(
    r"(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9]{36,255}"
    r"|github_pat_[A-Za-z0-9_]{30,255}|(?:AKIA|ASIA)[A-Z0-9]{16}"
    r"|sk-(?:proj|svcacct)-[A-Za-z0-9_-]{35,255}|(?:sk|rk)_live_[A-Za-z0-9]{16,255}"
    r"|xox[baprs]-(?:[A-Za-z0-9]+-)*[A-Za-z0-9]{10,})"
    r"(?![A-Za-z0-9_])"
)
ASSIGNMENT = re.compile(
    r"""\b(?:[a-z0-9]{1,32}[_-]){0,5}?(?:api[_-]?key|access[_-]?token|auth[_-]?token|"""
    r"""client[_-]?secret|password|secret[_-]?key|token|secret)['"]?\s*[:=]\s*"""
    r"""(?:(?P<quote>["'])(?P<quoted>[^"' \t]+)(?P=quote)|"""
    r"""(?P<bare>[A-Za-z0-9_+./=-]+)(?=\s*(?:#.*)?$))""",
    re.IGNORECASE,
)
PLACEHOLDERS = re.compile(
    r"^(?:example|dummy|placeholder|replace[_-]?me|change[_-]?me|your[_-]|"
    r"insert[_-]|redacted|test[_-]|fake[_-])",
    re.IGNORECASE,
)
SUBPROCESS_CALLS = {
    "subprocess.run", "subprocess.Popen", "subprocess.call",
    "subprocess.check_call", "subprocess.check_output",
}


def looks_like_secret(value: str) -> bool:
    return (
        len(value) >= 8
        and not PLACEHOLDERS.match(value)
        and not value.startswith(("$", "<"))
        and not (value.startswith("{") and value.endswith("}"))
        and len(set(value)) >= 4
    )


def dotted_name(node: ast.AST, aliases: dict[str, str]) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(aliases.get(node.id, node.id))
        return ".".join(reversed(parts))
    return ""


def import_aliases(tree: ast.AST) -> dict[str, str]:
    aliases = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                root = item.name.split(".")[0]
                aliases[item.asname or root] = item.name if item.asname else root
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for item in node.names:
                if item.name != "*":
                    aliases[item.asname or item.name] = f"{node.module}.{item.name}"
    return aliases


def matching_call(node: ast.Call, name: str) -> tuple[str, int] | None:
    line = node.func.lineno
    if name in {"eval", "exec", "builtins.eval", "builtins.exec"}:
        return "ACG101", line
    if name in {"os.system", "os.popen"}:
        return "ACG102", line
    if name in {"pickle.load", "pickle.loads", "_pickle.load", "_pickle.loads"}:
        return "ACG103", line
    for keyword in node.keywords:
        if not isinstance(keyword.value, ast.Constant):
            continue
        if name in SUBPROCESS_CALLS and keyword.arg == "shell" and keyword.value.value is True:
            return "ACG102", keyword.value.lineno
    if name.startswith("requests.") and name.removeprefix("requests.") in REQUEST_METHODS:
        verify_line = disabled_verify_line(node)
        if verify_line is not None:
            return "ACG104", verify_line
    return None


def inspect_source(
    report: Report, path: str, source: str, changed: list[tuple[int, int]] | None = None,
) -> None:
    starts = [start for start, _ in changed] if changed is not None else []

    def is_changed(line: int) -> bool:
        if changed is None:
            return True
        index = bisect_right(starts, line) - 1
        return index >= 0 and line <= changed[index][1]

    found = set()

    def add(rule_id: str, line: int) -> None:
        found.add(Finding(path, line, rule_id))

    report.files_scanned += 1
    is_env = PurePosixPath(path).name.lower().startswith(".env")
    for line_no, line in enumerate(source.split("\n"), 1):
        if not is_changed(line_no):
            continue
        if PRIVATE_KEY.search(line):
            add("ACG001", line_no)
        if PROVIDER_TOKEN.search(line):
            add("ACG002", line_no)
        elif any(
            looks_like_secret(match["quoted"] or match["bare"])
            for match in ASSIGNMENT.finditer(line)
            if match["quoted"] or is_env
        ):
            add("ACG003", line_no)

    if PurePosixPath(path).suffix.lower() in {".py", ".pyw"}:
        try:
            tree = ast.parse(source, filename="<source>")
        except (SyntaxError, ValueError, RecursionError):
            report.notes.append(f"Python rules skipped for {path} (source could not be parsed).")
        else:
            aliases = import_aliases(tree)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    match = matching_call(node, dotted_name(node.func, aliases))
                    if match and (is_changed(match[1]) or is_changed(node.func.lineno)):
                        rule_id, evidence_line = match
                        line = evidence_line if is_changed(evidence_line) else node.func.lineno
                        add(rule_id, line)
            try:
                session_findings = session_tls_findings(tree)
            except RecursionError:
                report.notes.append(f"Requests Session checks skipped for {path} (Python source nesting is too deep).")
            else:
                for evidence_line, target_line in session_findings:
                    if is_changed(evidence_line) or is_changed(target_line):
                        add("ACG104", evidence_line if is_changed(evidence_line) else target_line)
    report.findings.extend(sorted(found))
