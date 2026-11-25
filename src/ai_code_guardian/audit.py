import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from .model import Finding, GuardianError, Report
from .sources import MAX_BYTES

PIN = re.compile(r"([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)==([0-9][A-Za-z0-9.!+_-]*)")
ADVISORY = re.compile(r"[A-Z][A-Z0-9]*-[A-Za-z0-9-]{1,80}")


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def read_pins(path: Path) -> dict[str, tuple[str, int]]:
    try:
        if not path.is_file():
            raise GuardianError("The requirements input must be a regular file.")
        with path.open("rb") as stream:
            data = stream.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise GuardianError("The requirements input exceeds 1 MiB.")
        source = data.decode("utf-8-sig")
    except (OSError, UnicodeError):
        raise GuardianError("Could not read the requirements input as UTF-8.") from None

    pins = {}
    for number, line in enumerate(source.splitlines(), 1):
        requirement = line.split("#", 1)[0].strip()
        if not requirement:
            continue
        match = PIN.fullmatch(requirement)
        if not match:
            raise GuardianError(f"Requirements line {number} must be a plain 'name==version' pin.")
        name = normalize(match[1])
        if name in pins:
            raise GuardianError(f"Requirements line {number} repeats a package.")
        pins[name] = (match[2], number)
    if not pins:
        raise GuardianError("The requirements file does not contain any pinned packages.")
    return pins


def run_pip_audit(pins: dict[str, tuple[str, int]]) -> list:
    if importlib.util.find_spec("pip_audit") is None:
        raise GuardianError("pip-audit is missing. In a virtual environment, run: python -m pip install '.[audit]'")
    # Forward only validated package names and versions, never the original file.
    with TemporaryDirectory(prefix="guardian-audit-") as directory:
        pinned = Path(directory) / "requirements.txt"
        pinned.write_text("".join(f"{name}=={version}\n" for name, (version, _) in pins.items()), encoding="utf-8")
        try:
            result = subprocess.run(
                [
                    sys.executable, "-I", "-m", "pip_audit", "-r", str(pinned),
                    "--format", "json", "--desc", "off", "--aliases", "off",
                    "--progress-spinner", "off", "--strict", "--no-deps", "--disable-pip",
                    "--vulnerability-service", "pypi", "--cache-dir", directory, "--timeout", "15",
                ],
                env={key: value for key, value in os.environ.items() if not key.upper().startswith("PIP_AUDIT_")},
                capture_output=True, check=False, timeout=180,
            )
        except subprocess.TimeoutExpired:
            raise GuardianError("pip-audit timed out. Check network access to PyPI and retry.") from None
        except OSError:
            raise GuardianError("Could not start pip-audit.") from None

    try:
        payload = json.loads(result.stdout)
        dependencies = payload["dependencies"]
        if result.returncode not in (0, 1) or not isinstance(dependencies, list):
            raise ValueError
    except (ValueError, KeyError, TypeError):
        raise GuardianError("pip-audit did not return a usable report. Check the pins and network access to PyPI.") from None
    return dependencies


def audit_requirements(report: Report, path: Path) -> None:
    pins = read_pins(path)
    dependencies = run_pip_audit(pins)
    absolute = Path(os.path.abspath(path))
    name = absolute.relative_to(Path.cwd()).as_posix() if absolute.is_relative_to(Path.cwd()) else path.name
    audited = set()
    findings = set()
    for entry in dependencies:
        if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
            raise GuardianError("pip-audit returned an unexpected dependency entry.")
        package = normalize(entry["name"])
        if package not in pins or package in audited or "skip_reason" in entry:
            continue
        version, line = pins[package]
        advisories = entry.get("vulns")
        if not isinstance(advisories, list):
            raise GuardianError("pip-audit returned an unexpected advisory list.")
        audited.add(package)
        for advisory in advisories:
            advisory_id = advisory.get("id") if isinstance(advisory, dict) else None
            if not isinstance(advisory_id, str) or not ADVISORY.fullmatch(advisory_id):
                raise GuardianError("pip-audit returned an unexpected advisory identifier.")
            findings.add(Finding(name, line, "ACG201", f"{package}=={version} ({advisory_id})"))
    report.findings.extend(sorted(findings))
    if audited != pins.keys():
        report.errors.append(f"pip-audit did not check {len(pins.keys() - audited)} pinned package(s).")
