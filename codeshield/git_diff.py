"""Read-only, bounded Git access and added-line parsing; never read worktree sources."""

import os
import re
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from codeshield.config import Config
from codeshield.errors import ScanError


class Git:
    def __init__(self, directory: Path, config: Config):
        self.directory = directory
        self.config = config
        self.deadline = time.monotonic() + config.scan_timeout_seconds
        self.executable = shutil.which("git")
        if not self.executable:
            raise ScanError("Git is unavailable.")
        self.root = Path(os.fsdecode(self.run("rev-parse", "--show-toplevel").rstrip(b"\r\n"))).resolve()
        if self.run("rev-parse", "--is-inside-work-tree").strip() != b"true":
            raise ScanError("Scan requires a Git working-tree repository.")
        self.directory = self.root

    def check_deadline(self):
        if time.monotonic() >= self.deadline:
            raise ScanError("Scan timed out; scan incomplete.")

    def run(self, *args: str, limit: int | None = None) -> bytes:
        self.check_deadline()
        limit = limit if limit is not None else self.config.max_scan_bytes
        env = os.environ.copy()
        env.update(GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0")
        timed_out = threading.Event()
        try:
            with subprocess.Popen(
                [self.executable, "--literal-pathspecs", "-c", "core.fsmonitor=false",
                 "-C", str(self.directory), *args],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env,
            ) as process:
                def expire():
                    timed_out.set()
                    try:
                        process.kill()
                    except OSError:
                        pass

                timer = threading.Timer(
                    min(self.config.git_timeout_seconds, max(0.001, self.deadline - time.monotonic())), expire
                )
                timer.start()
                try:
                    data = process.stdout.read(limit + 1)
                    if len(data) > limit:
                        process.kill()
                    process.wait()
                finally:
                    timer.cancel()
                    timer.join()
                if timed_out.is_set():
                    raise ScanError("Git operation timed out; scan incomplete.")
                if len(data) > limit:
                    raise ScanError("Git output exceeds scan limits; scan incomplete.")
                if process.returncode:
                    raise ScanError("Git operation failed; verify the repository and index.")
                return data
        except OSError:
            raise ScanError("Git operation failed; verify the repository and index.") from None

    def staged_metadata(self) -> bytes:
        if self.run("ls-files", "--unmerged", "-z"):
            raise ScanError("Unmerged index; resolve conflicts before scanning.")
        return self.run("diff", "--cached", "--raw", "-z", "--no-abbrev", "--no-ext-diff",
                        "--no-textconv", "--find-renames=50%", "--diff-filter=ACMRT", "--no-relative", "--")

    def blob_size(self, oid: str) -> int:
        if set(oid) == {"0"}:
            return 0
        try:
            return int(self.run("cat-file", "-s", oid, limit=64))
        except ValueError:
            raise ScanError("Invalid Git object metadata.") from None


@dataclass(frozen=True)
class Change:
    old_mode: str
    mode: str
    old_oid: str
    oid: str
    old_path: str
    path: str


def valid_path(path: str) -> str:
    parts = PurePosixPath(path).parts
    if (not parts or PurePosixPath(path).is_absolute() or ".." in parts
            or "\\" in path or ":" in path or "\0" in path):
        raise ScanError("Unsafe repository path encountered.")
    return path


def parse_changes(raw: bytes) -> list[Change]:
    fields = raw.split(b"\0")
    changes = []
    i = 0
    try:
        while i < len(fields) - 1:
            header = fields[i].decode("ascii")
            match = re.fullmatch(r":([0-7]{6}) ([0-7]{6}) ([0-9a-f]{40,64}) ([0-9a-f]{40,64}) ([ACMRT])\d*", header)
            if not match:
                raise ValueError
            old_mode, mode, old_oid, oid, status = match.groups()
            i += 1
            old_path = valid_path(fields[i].decode("utf-8"))
            i += 1
            if status in ("R", "C"):
                path = valid_path(fields[i].decode("utf-8"))
                i += 1
            else:
                path = old_path
            changes.append(Change(old_mode, mode, old_oid, oid, old_path, path))
        if fields[-1] != b"":
            raise ValueError
    except (ValueError, IndexError, UnicodeError):
        raise ScanError("Invalid Git change metadata.") from None
    return changes


HUNK = re.compile(rb"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?:.*)")


def parse_added_lines(patch: bytes) -> dict[int, bytes]:
    """Validate unified hunk lengths; paths in headers never determine source paths."""
    added = {}
    old_left = new_left = line_number = sections = 0
    for line in patch.split(b"\n"):
        if line.startswith(b"\\ No newline at end of file"):
            continue
        if old_left or new_left:
            prefix = line[:1]
            if prefix == b"+" and new_left:
                if line_number in added:
                    raise ScanError("Overlapping Git diff hunks.")
                added[line_number] = line[1:]
                new_left -= 1
                line_number += 1
            elif prefix == b"-" and old_left:
                old_left -= 1
            elif prefix == b" " and old_left and new_left:
                old_left -= 1
                new_left -= 1
                line_number += 1
            else:
                raise ScanError("Malformed Git diff hunk.")
            continue
        if line.startswith(b"diff --git "):
            sections += 1
            if sections > 1:
                raise ScanError("Ambiguous rename diff; scan incomplete.")
        elif line.startswith(b"@@"):
            match = HUNK.fullmatch(line)
            if not match:
                raise ScanError("Malformed Git diff header.")
            _, old_count, new_start, new_count = match.groups()
            old_left = int(old_count) if old_count is not None else 1
            new_left = int(new_count) if new_count is not None else 1
            line_number = int(new_start)
    if old_left or new_left:
        raise ScanError("Incomplete Git diff hunk.")
    return added


def staged_additions(git: Git, change: Change, data: bytes) -> frozenset[int]:
    paths = list(dict.fromkeys((change.old_path, change.path)))
    patch = git.run(
        "diff", "--cached", "--unified=0", "--inter-hunk-context=0", "--diff-algorithm=myers",
        "--no-ext-diff", "--no-textconv", "--no-color", "--no-relative", "--text",
        "--find-renames=50%", "--", *paths,
        limit=git.config.max_scan_bytes * 3 + 65536,
    )
    added = parse_added_lines(patch)
    lines = data.split(b"\n")
    if any(number < 1 or number > len(lines) or lines[number - 1] != value
           for number, value in added.items()):
        raise ScanError("Index changed during scanning; rerun the scan.")
    if change.old_oid != change.oid and not added and b"@@" not in patch:
        raise ScanError("Git did not produce a verifiable text diff.")
    return frozenset(added)
