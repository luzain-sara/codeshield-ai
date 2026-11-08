"""Approved, guarded multi-file writes with private temporaries and in-memory rollback."""

import os
import tempfile
import time
from pathlib import Path

from codeshield.agent.providers import in_ci
from codeshield.errors import ScanError
from codeshield.models import Provider
from codeshield.remediation.planner import Plan, is_ignored, plan_remediation
from codeshield.remediation.security import set_permissions
from codeshield.remediation.snapshot import Snapshot
from codeshield.remediation.validator import syntax
from codeshield.scanner import contained_file, scan


def atomic_write(root: Path, before: Snapshot, data: bytes, *, private=False):
    path = contained_file(root, before.relative)
    if path is None:
        raise ScanError("Linked or escaping paths cannot be modified.")
    temporary_directory = contained_file(root, ".codeshield")
    if temporary_directory is None:
        raise ScanError("Unsafe transaction directory.")
    descriptor, temporary_name = tempfile.mkstemp(prefix="remediation-", suffix=".tmp", dir=temporary_directory)
    temporary = Path(temporary_name)
    try:
        # Set ACL/mode before writing any source or environment bytes to the temporary.
        with os.fdopen(descriptor, "wb") as stream:
            set_permissions(temporary, 0o600, private=True)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        set_permissions(temporary, before.mode, before.acl, private=private)
        before.verify(root, max(len(data), len(before.data or b"")) + 1)
        if contained_file(root, before.relative) is None:
            raise ScanError("Path changed before atomic replacement.")
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def index_unchanged(plan: Plan):
    if (plan.index != plan.git.run("ls-files", "--stage", "-z")
            or plan.head != plan.git.run("rev-parse", "--revs-only", "HEAD")):
        raise ScanError("Index or HEAD changed; remediation cannot proceed.")


def validate_result(plan: Plan):
    source = plan.edits[-1]
    current = Snapshot.read(plan.git.root, source.before.relative, plan.config.max_file_bytes + 4096)
    if current.data != source.after:
        raise ScanError("Source changed after remediation; validation failed.")
    syntax(current.data, plan.runtime, plan.git.root, plan.config.git_timeout_seconds)
    config = plan.config.model_copy(update={"provider": Provider.RULES})
    working = scan(config, cwd=plan.git.root, path=Path(source.before.relative))
    staged = scan(config, cwd=plan.git.root)
    if not any(f.finding_id == plan.finding.finding_id for f in staged.findings):
        raise ScanError("The staged finding changed unexpectedly during remediation.")
    if plan.git.run("ls-files", "-z", "--", ".env"):
        raise ScanError("Environment file became tracked; validation failed.")
    plan.git.run("check-ignore", "-q", "--", ".env")
    index_unchanged(plan)
    return working.summary.total


def apply_plan(plan: Plan, *, approved: bool = False) -> str:
    if approved is not True:
        raise ScanError("Explicit developer approval is required; no files changed.")
    if in_ci():
        raise ScanError("Remediation is disabled in CI.")
    plan.git.deadline = time.monotonic() + plan.config.scan_timeout_seconds
    root = plan.git.root
    index_unchanged(plan)
    for snapshot in plan.guards.values():
        snapshot.verify(root, plan.config.max_file_bytes)
    rebuilt = plan_remediation(plan.finding.finding_id, plan.config, cwd=root, env_name=plan.env_name,
                               store_secret=any(edit.private for edit in plan.edits))
    if rebuilt.edits != plan.edits or rebuilt.runtime != plan.runtime or rebuilt.index != plan.index or rebuilt.head != plan.head:
        raise ScanError("The reviewed plan no longer matches deterministic safety validation.")
    lock_directory = contained_file(root, ".codeshield")
    if lock_directory is None:
        raise ScanError("Unsafe remediation lock directory.")
    created_directory = not lock_directory.exists()
    lock_directory.mkdir(mode=0o700, exist_ok=True)
    set_permissions(lock_directory, 0o700, private=True)
    lock_path = lock_directory / "remediation.lock"
    descriptor = None
    changed = []
    expected = dict(plan.guards)
    try:
        try:
            descriptor = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            raise ScanError("Another remediation is active or a stale lock needs manual review.") from None
        for edit in plan.edits:
            index_unchanged(plan)
            for snapshot in expected.values():
                snapshot.verify(root, plan.config.max_file_bytes + 4096)
            if edit.before.relative != ".gitignore" and not is_ignored(plan.git, ".codeshield/"):
                raise ScanError("Transaction temporaries must be Git-ignored before source or credential writes.")
            if edit.private:
                # The ignore rule must be effective before any new credential bytes are written.
                plan.git.run("check-ignore", "-q", "--", ".env")
                if plan.git.run("ls-files", "-z", "--", ".env"):
                    raise ScanError("Tracked environment files cannot receive credentials.")
            # Record attempts before replacement, including interrupted/post-replace failures.
            changed.append(edit)
            atomic_write(root, edit.before, edit.after, private=edit.private)
            expected[edit.before.relative] = Snapshot.read(root, edit.before.relative, plan.config.max_file_bytes + 4096)
        remaining = validate_result(plan)
        for snapshot in expected.values():
            snapshot.verify(root, plan.config.max_file_bytes + 4096)
        return ("fix_applied_to_worktree_requires_restage\n"
                f"Remaining findings in the modified working-tree file: {remaining}\n"
                "The Git index is unchanged and still contains the original finding.\n"
                "Review all edits, restage intentionally, and rerun codeshield scan --staged.\n"
                "Rotate/revoke credentials previously exposed; this refactor does not revoke them.\n")
    except BaseException as failure:
        if not changed and isinstance(failure, ScanError):
            raise
        rollback_failed = False
        environment_failed = False
        for edit in reversed(changed):
            if edit.before.relative == ".gitignore" and environment_failed:
                rollback_failed = True  # Retain protection if .env could not be restored.
                continue
            try:
                observed = Snapshot.read(root, edit.before.relative, plan.config.max_file_bytes + 4096)
                if (observed.data, observed.signature, observed.acl) == (edit.before.data, edit.before.signature, edit.before.acl):
                    continue  # The attempted write never took effect.
                if observed.data != edit.after:
                    raise ScanError("Concurrent edits prevent safe rollback.")
                current = expected.get(edit.before.relative)
                if current is not None and current.data == edit.after:
                    current.verify(root, plan.config.max_file_bytes + 4096)
                else:
                    current = observed
                if edit.before.data is None:
                    path = contained_file(root, edit.before.relative)
                    if path is None:
                        raise ScanError("Rollback path changed.")
                    path.unlink()
                else:
                    # Restore original bytes, permissions and Windows ACLs without a disk backup.
                    restore = Snapshot(current.relative, current.data, current.signature, edit.before.mode, current.acl)
                    # atomic_write uses current ACL to check the guard, then restore original ACL.
                    atomic_write(root, restore, edit.before.data)
                    set_permissions(root / edit.before.relative, edit.before.mode, edit.before.acl)
            except Exception:
                rollback_failed = True
                environment_failed = environment_failed or edit.before.relative == ".env"
        if rollback_failed:
            raise ScanError("Remediation failed and rollback is incomplete; review files manually. No commit-safe claim is made.") from None
        raise ScanError("Remediation failed; all completed writes were rolled back. No source or credential values were displayed.") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
            lock_path.unlink(missing_ok=True)
        if created_directory:
            try:
                lock_directory.rmdir()
            except OSError:
                pass
