"""Bounded, link-safe file snapshots held in memory, never logged or persisted."""

import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

from codeshield.errors import ScanError
from codeshield.git_diff import valid_path
from codeshield.remediation.security import read_acl
from codeshield.scanner import contained_file


@dataclass(frozen=True, repr=False)
class Snapshot:
    relative: str
    data: bytes | None = field(repr=False)
    signature: tuple | None = field(repr=False)
    mode: int = 0o600
    acl: bytes | None = field(default=None, repr=False)

    @classmethod
    def read(cls, root: Path, relative: str, limit: int):
        valid_path(relative)
        if any(part.casefold() == ".git" for part in Path(relative).parts):
            raise ScanError("Git metadata is not a remediation target.")
        path = contained_file(root, relative)
        if path is None:
            raise ScanError("Linked or escaping paths cannot be remediated.")
        try:
            before = path.stat(follow_symlinks=False)
        except FileNotFoundError:
            return cls(relative, None, None)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ScanError("Remediation requires regular files with one hard link.")
        if getattr(before, "st_file_attributes", 0) & 0x4000:
            raise ScanError("Encrypted files require manual remediation; encryption attributes are never dropped.")
        if before.st_dev != root.stat().st_dev:
            raise ScanError("Cross-filesystem remediation is not supported.")
        if before.st_size > limit:
            raise ScanError("Remediation file exceeds the configured size limit.")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        with os.fdopen(os.open(path, flags), "rb") as stream:
            opened = os.fstat(stream.fileno())
            if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                    or (opened.st_dev, opened.st_ino, opened.st_size) != (before.st_dev, before.st_ino, before.st_size)):
                raise ScanError("File changed while preparing remediation.")
            data = stream.read(limit + 1)
        after = path.stat(follow_symlinks=False)
        signature = lambda s: (s.st_dev, s.st_ino, s.st_mtime_ns, s.st_ctime_ns, s.st_size, s.st_mode, s.st_nlink)
        if signature(before) != signature(after) or len(data) != before.st_size or contained_file(root, relative) is None:
            raise ScanError("File changed while preparing remediation.")
        return cls(relative, data, signature(after), stat.S_IMODE(after.st_mode), read_acl(path))

    def verify(self, root: Path, limit: int):
        current = Snapshot.read(root, self.relative, limit)
        if (self.data, self.signature, self.acl) != (current.data, current.signature, current.acl):
            raise ScanError("Plan is stale; files changed. Review a new dry run.")

    def writable(self):
        if self.data is not None and not self.mode & stat.S_IWUSR:
            raise ScanError("Read-only files cannot be remediated.")
