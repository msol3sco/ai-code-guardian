import os
import re
import stat
import subprocess
from pathlib import Path
from typing import Iterator

from .model import GuardianError, Report
from .rules import inspect_source

MAX_BYTES = 1024 * 1024
IGNORED_DIRS = {
    ".git", ".venv", "venv", ".tox", ".nox", "__pycache__",
    ".pytest_cache", ".mypy_cache", ".ruff_cache", "node_modules", "build", "dist",
}
HUNK = re.compile(rb"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
REGULAR_MODES = {b"100644", b"100755"}
OID = re.compile(rb"(?:[0-9a-f]{40}|[0-9a-f]{64})")


def scan_bytes(
    report: Report, name: str, data: bytes, changed: list[tuple[int, int]] | None = None,
) -> None:
    if len(data) > MAX_BYTES:
        report.skip(f"{name} skipped (larger than 1 MiB).")
        return
    if b"\0" in data:
        report.skip(f"{name} skipped (binary content).")
        return
    try:
        source = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        report.skip(f"{name} skipped (content is not UTF-8).")
        return
    inspect_source(report, name, source, changed)


def is_link(info: os.stat_result) -> bool:
    reparse = getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return stat.S_ISLNK(info.st_mode) or bool(reparse)


def scan_file(report: Report, path: Path, name: str) -> None:
    try:
        info = path.lstat()
        if is_link(info) or not stat.S_ISREG(info.st_mode):
            report.skip(f"{name} skipped (link or non-regular file).")
            return
        with path.open("rb") as stream:
            scan_bytes(report, name, stream.read(MAX_BYTES + 1))
    except OSError:
        report.errors.append(f"Could not read {name}.")


def scan_path(report: Report, target: Path) -> None:
    # absolute() preserves symlinks so they can be rejected before traversal.
    target = target.absolute()
    try:
        for component in reversed((target, *target.parents)):
            if is_link(component.lstat()):
                raise GuardianError("The scan target crosses a symbolic link or reparse point.")
    except OSError:
        raise GuardianError("The scan target does not exist or cannot be accessed.") from None
    if not stat.S_ISDIR(target.lstat().st_mode):
        scan_file(report, target, target.name)
        return

    def walk_error(_error: OSError) -> None:
        report.errors.append("Could not traverse part of the scan directory.")

    for folder, dirs, files in os.walk(target, onerror=walk_error):
        directory = Path(folder)
        kept_dirs = []
        for subdir in sorted(dirs):
            if subdir in IGNORED_DIRS or subdir.endswith(".egg-info"):
                continue
            try:
                if not is_link((directory / subdir).lstat()):
                    kept_dirs.append(subdir)
            except OSError:
                walk_error(OSError())
        dirs[:] = kept_dirs
        for filename in sorted(files):
            if filename == ".git":
                continue
            path = directory / filename
            scan_file(report, path, path.relative_to(target).as_posix())


def git(cwd: Path, failure: str, *args: str) -> bytes:
    try:
        result = subprocess.run(
            [
                "git", "--no-pager", "-c", "core.quotePath=true",
                "-c", "core.fsmonitor=false", *args,
            ],
            cwd=cwd, capture_output=True, check=False, timeout=60,
        )
    except FileNotFoundError:
        raise GuardianError("Git is required for staged and diff scans.") from None
    except (OSError, subprocess.TimeoutExpired):
        raise GuardianError(failure) from None
    if result.returncode:
        raise GuardianError(failure)
    return result.stdout


def revision(root: Path, ref: str, label: str) -> str:
    output = git(
        root, f"Cannot resolve the {label} Git revision. Check refs and fetch missing history.",
        "rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}",
    ).strip()
    if not OID.fullmatch(output):
        raise GuardianError("Git returned an unexpected commit ID.")
    return output.decode("ascii")


def raw_changes(raw: bytes) -> Iterator[tuple[bytes, bytes, bytes, bytes, str]]:
    # A rename contributes two paths. Only the destination has new line numbers.
    fields = iter(raw.rstrip(b"\0").split(b"\0")) if raw else iter(())
    for field in fields:
        old_mode, new_mode, old_oid, new_oid, status = field.split()
        path = next(fields)
        if status.startswith(b"R"):
            path = next(fields)
        yield old_mode[1:], new_mode, old_oid, new_oid, path.decode("utf-8", errors="replace")


def changed_lines(patch: bytes) -> list[tuple[int, int]]:
    intervals = []
    for line in patch.split(b"\n"):
        match = HUNK.match(line)
        if match:
            start = int(match[1])
            count = int(match[2]) if match[2] is not None else 1
            if count:
                intervals.append((start, start + count - 1))
    return intervals


def scan_git(report: Report, *, staged: bool, base: str = "", head: str = "") -> None:
    cwd = Path.cwd()
    root_bytes = git(cwd, "Run the Git scan inside a working repository.", "rev-parse", "--show-toplevel")
    root = Path(os.fsdecode(root_bytes.removesuffix(b"\n")))
    if staged:
        # Git also handles an unborn branch: it compares against the empty tree.
        revision_args = ("--cached",)
    else:
        base_oid = revision(root, base, "base")
        head_oid = revision(root, head, "head")
        merge_base = git(
            root, "No common Git ancestor found. Fetch full history and verify both refs.",
            "merge-base", base_oid, head_oid,
        ).strip()
        if not OID.fullmatch(merge_base):
            raise GuardianError("Git returned an unexpected merge base.")
        revision_args = (merge_base.decode("ascii"), head_oid)
    raw = git(
        root, "Could not compare Git snapshots. Resolve index conflicts and check repository state.",
        "diff", "--raw", "-z", "--no-abbrev", "--no-ext-diff", "--no-textconv",
        "--find-renames=50%", "--diff-filter=AMRTU", *revision_args, "--",
    )
    for old_mode, new_mode, old_oid, new_oid, path in raw_changes(raw):
        if new_mode == b"000000":
            report.errors.append(f"Could not scan unresolved index entry {path}.")
            continue
        if new_mode not in REGULAR_MODES:
            report.skip(f"{path} skipped (Git entry is not a regular file).")
            continue
        if old_oid == new_oid and old_mode in REGULAR_MODES:
            continue
        new = new_oid.decode("ascii")
        size = git(root, f"Could not read Git blob size for {path}.", "cat-file", "-s", new)
        if int(size) > MAX_BYTES:
            report.skip(f"{path} skipped (larger than 1 MiB).")
            continue
        data = git(root, f"Could not read Git blob for {path}.", "cat-file", "blob", new)
        intervals = None
        if old_mode in REGULAR_MODES:
            old = old_oid.decode("ascii")
            old_size = git(root, f"Could not read previous Git blob size for {path}.", "cat-file", "-s", old)
            if int(old_size) > MAX_BYTES:
                report.skip(f"{path} skipped (previous Git blob larger than 1 MiB).")
                continue
            patch = git(
                root, f"Could not compare Git blobs for {path}.",
                "diff", "--no-ext-diff", "--no-textconv", "--text", "--unified=0",
                "--inter-hunk-context=0", "--diff-algorithm=myers", "--no-indent-heuristic",
                old, new, "--",
            )
            intervals = changed_lines(patch)
            if not intervals:
                continue
        scan_bytes(report, path, data, intervals)
