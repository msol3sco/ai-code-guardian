import argparse
import sys
from pathlib import Path

from . import __version__
from .audit import audit_requirements
from .model import GuardianError, Report
from .reporting import github_annotations, render
from .sources import scan_git, scan_path


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="ai-code-guardian",
        description="Run local code checks or opt in to a pinned Python dependency audit.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    output = argparse.ArgumentParser(add_help=False)
    output.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    output.add_argument("--output", metavar="FILE", type=Path, help="create a UTF-8 report file (must not exist)")

    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", parents=[output], help="scan files, the index, or a committed diff")
    mode = scan.add_mutually_exclusive_group()
    mode.add_argument("--path", type=Path, help="file or directory to scan in full (default: current directory)")
    mode.add_argument("--staged", action="store_true", help="scan added or modified lines in the Git index")
    mode.add_argument("--diff", metavar="BASE", help="scan lines changed since the merge base of BASE and HEAD")
    scan.add_argument("--head", default=None, help="committed tip for --diff (default: HEAD)")
    scan.add_argument("--config", type=Path, metavar="FILE", help="use an explicit policy file")
    scan.add_argument(
        "--fail-on", choices=("warning", "error"), default="warning",
        help="lowest finding severity that returns exit code 1 (default: warning)",
    )
    scan.add_argument(
        "--github-annotations", action="store_true", help="emit GitHub Actions annotations (requires --diff and --output)",
    )

    audit = commands.add_parser("audit", parents=[output], help="check exact Python dependency pins via PyPI")
    audit.add_argument("--requirements", "-r", type=Path, required=True, metavar="FILE")
    args = parser.parse_args(argv)
    if args.command == "scan":
        if args.head is not None and args.diff is None:
            scan.error("--head requires --diff BASE")
        if args.github_annotations and (args.diff is None or args.output is None):
            scan.error("--github-annotations requires --diff BASE and --output FILE")
    return args


def write_stdout(payload: str) -> None:
    # Preserve useful output on terminals that cannot represent a Unicode path.
    encoding = sys.stdout.encoding or "utf-8"
    sys.stdout.write(payload.encode(encoding, errors="backslashreplace").decode(encoding))


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    report = Report(fail_on=args.fail_on) if args.command == "scan" else Report()
    try:
        if args.command == "audit":
            audit_requirements(report, args.requirements)
        elif args.staged or args.diff is not None:
            scan_git(report, staged=args.staged, base=args.diff or "", head=args.head or "HEAD", config=args.config)
        else:
            scan_path(report, args.path or Path("."), config=args.config)
    except GuardianError as error:
        report.errors.append(str(error))
    except OSError:
        report.errors.append("Could not access the requested input or a temporary file.")

    try:
        payload = render(report, args.format)
        if args.output:
            with args.output.open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(payload)
            if args.command == "scan" and args.github_annotations:
                write_stdout(github_annotations(report))
        else:
            write_stdout(payload)
    except OSError:
        print("Could not write the report. Check the destination and use a new output filename.", file=sys.stderr)
        return 2
    return report.exit_code
