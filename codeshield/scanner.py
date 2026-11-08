"""Offline scanner over Git index snapshots or an explicitly selected worktree."""

import hashlib
import json
import os
import re
import stat
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from uuid import uuid4

from codeshield import __version__
from codeshield.agent.providers import require_live_opt_in
from codeshield.agent.sanitizer import sanitize
from codeshield.agent.workflow import verify_findings
from codeshield.config import Config
from codeshield.detectors.context import code_lines
from codeshield.detectors.patterns import ASSIGNMENT, Candidate, Detector, safe_path
from typing import Callable
from codeshield.errors import ScanError
from codeshield.git_diff import Git, parse_changes, staged_additions, valid_path
from codeshield.models import (Finding, Provider, ScanResult, ScanScope, Severity,
                               SkippedFile, Summary, ValidationStatus)

PROTECTED = {".git", ".hg", ".svn", ".venv", ".codeshield", "venv", "__pycache__", "node_modules",
             "vendor", "dist", "build", ".pytest_cache", ".mypy_cache", ".ruff_cache"}
EXTENSIONS = {".py", ".js", ".cjs", ".mjs", ".jsx", ".ts", ".tsx", ".json", ".yaml", ".yml"}
KEY_ONLY = re.compile(r'''(?:(?:const|let|var)\s+)?["']?[A-Za-z_$][\w$.-]{0,100}["']?\s*(?::\s*(?:str|bytes|string)\s*)?[:=]\s*\(?\s*''')
SEVERITY_ORDER = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}


def excluded_reason(path: str, config: Config) -> str | None:
    parts = PurePosixPath(path).parts
    if any(part.casefold() in PROTECTED | {name.casefold() for name in config.exclude_dirs}
           for part in parts[:-1]):
        return "protected_directory"
    name = parts[-1]
    if name in {"package-lock.json", "pnpm-lock.yaml"} or name.endswith(".min.js"):
        return "generated_file"
    if PurePosixPath(path).suffix.lower() not in EXTENSIONS and not (name.lower() == ".env" or name.lower().startswith(".env.")):
        return "unsupported_file_type"
    return None


def decode_source(data: bytes) -> str | None:
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        raise ScanError("Unsupported text encoding; UTF-8 is required.")
    if b"\0" in data:
        return None
    try:
        return data.decode("utf-8-sig")
    except UnicodeError:
        raise ScanError("Unsupported text encoding; UTF-8 is required.") from None


def is_link(path: Path) -> bool:
    return path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction())


def contained_file(root: Path, relative: str) -> Path | None:
    path = root
    for part in PurePosixPath(relative).parts:
        path /= part
        if is_link(path):
            return None
    if not path.resolve().is_relative_to(root):
        return None
    return path


def scan(config: Config, *, path: Path | None = None, cwd: Path | None = None,
         live_enabled: bool = False,
         _on_finding: Callable[[Finding, str, bytes, Candidate], None] | None = None) -> ScanResult:
    if config.provider == Provider.GEMINI:
        require_live_opt_in(live_enabled)
    started = datetime.now(timezone.utc)
    cwd = cwd or Path.cwd()
    requested = None
    requested_is_file = False
    if path is not None:
        requested = Path(os.path.abspath(cwd / path))
        if any(is_link(parent) for parent in (requested, *requested.parents)):
            raise ScanError("Working-tree scan path must not traverse links.")
        try:
            requested_mode = requested.stat().st_mode
        except OSError:
            raise ScanError("Working-tree scan path is missing or unreadable.") from None
        requested_is_file = stat.S_ISREG(requested_mode)
        if not requested_is_file and not stat.S_ISDIR(requested_mode):
            raise ScanError("Working-tree scan path must be a regular file or directory.")
    git = Git(requested if requested and not requested_is_file else (requested.parent if requested else cwd), config)
    if requested and not requested.is_relative_to(git.root):
        raise ScanError("Scan path is outside the repository.")
    if git.run("ls-files", "--unmerged", "-z"):
        raise ScanError("Unmerged index; resolve conflicts before scanning.")
    detector = Detector(config)
    findings = []
    contexts = {}
    skipped = []
    files_scanned = volume = 0

    def skip(relative: str, reason: str):
        skipped.append(SkippedFile(path=safe_path(relative), reason=reason))

    def budget(size: int):
        nonlocal volume
        volume += size
        if size > config.max_file_bytes or volume > config.max_scan_bytes:
            raise ScanError("File or scan byte limit exceeded; scan incomplete.")

    def inspect(relative: str, data: bytes, additions: frozenset[int] | None):
        nonlocal files_scanned
        text = decode_source(data)
        if text is None:
            skip(relative, "binary")
            return
        files_scanned += 1
        pending = []
        prefix = ""
        allow_bare = relative.lower().endswith((".yaml", ".yml")) or PurePosixPath(relative).name.lower().startswith(".env")
        cleaned_lines = code_lines(text, relative)
        for number, line in enumerate(cleaned_lines, 1):
            git.check_deadline()
            own_assignment = bool(prefix and ASSIGNMENT.match(line.lstrip(), timeout=0.05))
            context = line if own_assignment else prefix + line
            offset = 0 if own_assignment else len(prefix)
            if line.strip():
                prefix = line.rstrip().removesuffix("(") + " " if KEY_ONLY.fullmatch(line.strip()) else ""
            if additions is not None and number not in additions:
                continue
            for candidate in detector.find(context, allow_bare=allow_bare):
                if candidate.start < offset:
                    continue
                candidate = replace(candidate, start=candidate.start - offset, end=candidate.end - offset)
                pending.append((number, candidate))
                if len(findings) + len(pending) > config.max_findings:
                    raise ScanError("Finding limit exceeded; scan incomplete.")
        display_path = safe_path(relative, tuple(item.value for _, item in pending))
        for number, candidate in pending:
            # Fingerprints use location/rule only, never raw candidate bytes or their hash.
            identity = json.dumps([display_path, candidate.rule_id, number, candidate.start + 1], ensure_ascii=True)
            finding = Finding(
                finding_id=hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24],
                rule_id=candidate.rule_id, path=display_path, line=number, column=candidate.start + 1,
                severity=candidate.severity, confidence=candidate.confidence, assessment_source=Provider.RULES,
                redacted_sample="<REDACTED_SECRET>", evidence=(candidate.evidence,),
                recommendation="Remove the hardcoded value. Rotate it if previously exposed; review and rescan staged changes.",
            )
            findings.append(finding)
            if _on_finding is not None:
                _on_finding(finding, relative, data, candidate)
            window = "\n".join(cleaned_lines[max(0, number - 2):number + 1])[:2048]
            contexts[finding.finding_id] = sanitize(relative, window, candidate.rule_id)

    if requested is None:
        metadata = git.staged_metadata()
        changes = parse_changes(metadata)
        if len(changes) > config.max_files:
            raise ScanError("File count limit exceeded; scan incomplete.")
        for change in changes:
            git.check_deadline()
            reason = excluded_reason(change.path, config)
            if reason:
                skip(change.path, reason)
                continue
            if change.mode not in ("100644", "100755"):
                skip(change.path, "link_or_submodule")
                continue
            size = git.blob_size(change.oid)
            budget(size)
            old_size = git.blob_size(change.old_oid)
            if change.old_oid != change.oid:
                budget(old_size)
            data = git.run("cat-file", "blob", change.oid, limit=config.max_file_bytes)
            if len(data) != size:
                raise ScanError("Git object size mismatch.")
            if decode_source(data) is None:
                skip(change.path, "binary")
                continue
            # Cap both sides before allowing Git to generate a patch.
            additions = staged_additions(git, change, data)
            inspect(change.path, data, additions)
        if metadata != git.staged_metadata():
            raise ScanError("Index changed during scanning; rerun the scan.")
    else:
        raw = git.run("ls-files", "--cached", "--others", "--exclude-standard", "-z")
        try:
            paths = sorted({valid_path(item.decode("utf-8")) for item in raw.split(b"\0") if item})
        except UnicodeError:
            raise ScanError("Unsupported repository path encoding.") from None
        if requested_is_file:
            paths = [requested.relative_to(git.root).as_posix()]
        if len(paths) > config.max_files:
            raise ScanError("File count limit exceeded; scan incomplete.")
        for relative in paths:
            git.check_deadline()
            absolute = git.root.joinpath(*PurePosixPath(relative).parts)
            if absolute != requested and not absolute.is_relative_to(requested):
                continue
            reason = excluded_reason(relative, config)
            if reason:
                skip(relative, reason)
                continue
            target = contained_file(git.root, relative)
            if target is None:
                skip(relative, "link_or_submodule")
                continue
            try:
                target_mode = target.stat(follow_symlinks=False).st_mode
            except FileNotFoundError:
                continue  # Deleted worktree path has no current content to scan.
            if not stat.S_ISREG(target_mode):
                skip(relative, "link_or_submodule")
                continue
            flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
            with os.fdopen(os.open(target, flags), "rb") as stream:
                before = os.fstat(stream.fileno())
                if not stat.S_ISREG(before.st_mode):
                    raise ScanError("Working-tree source is not a regular file.")
                budget(before.st_size)
                data = stream.read(config.max_file_bytes + 1)
                after = os.fstat(stream.fileno())
            if (len(data) != before.st_size or before.st_mtime_ns != after.st_mtime_ns
                    or contained_file(git.root, relative) is None):
                raise ScanError("Working-tree file changed during scanning; rerun the scan.")
            inspect(relative, data, None)
    findings.sort(key=lambda item: (item.path, item.line, item.column, item.rule_id))
    blocking = sum(SEVERITY_ORDER[item.severity] >= SEVERITY_ORDER[config.blocking_severity] for item in findings)
    git.check_deadline()
    verified = verify_findings(tuple(findings), contexts, config, git.root, live_enabled=live_enabled)
    failed = any(item.verification.status != "ok" for item in verified)
    return ScanResult(
        run_id=uuid4(), scan_scope=ScanScope.STAGED if requested is None else ScanScope.WORKTREE,
        started_at=started, finished_at=datetime.now(timezone.utc), tool_version=__version__,
        provider=config.provider, verification_model=config.gemini_model if config.provider == Provider.GEMINI else None,
        findings=verified, summary=Summary(total=len(findings), blocking=blocking),
        validation_status=ValidationStatus.FAILED if failed else ValidationStatus.PASSED, files_scanned=files_scanned,
        skipped_files=tuple(sorted(skipped, key=lambda item: (item.path, item.reason))),
    )
