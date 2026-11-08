"""Offline developer gates. No integration path can opt into Gemini or apply fixes."""

import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import shlex
import stat
import sys

from codeshield.config import Config
from codeshield.errors import ScanError
from codeshield.git_diff import Git


@contextmanager
def automated():
    previous = os.environ.get("CODESHIELD_AUTOMATED")
    os.environ["CODESHIELD_AUTOMATED"] = "1"
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop("CODESHIELD_AUTOMATED", None)
        else:
            os.environ["CODESHIELD_AUTOMATED"] = previous


def hook_main(argv: list[str] | None = None) -> int:
    from codeshield.cli import main
    argparse.ArgumentParser(prog="codeshield-hook").parse_args(argv)
    with automated():
        return main(["scan", "--staged", "--provider", "mock"])


def hook_bytes() -> bytes:
    executable = shlex.quote(Path(sys.executable).as_posix())
    return ("#!/bin/sh\n# codeshield-managed-pre-commit-v1\n"
            f"exec {executable} -I -m codeshield.integrations hook\n").encode("utf-8")


def no_links(path: Path):
    if any(parent.is_symlink() or (hasattr(parent, "is_junction") and parent.is_junction())
           for parent in (path, *path.parents)):
        raise ScanError("Hook paths must not traverse links.")


def manage_hook(action: str, cwd: Path) -> str:
    git = Git(cwd, Config())
    common = Path(os.fsdecode(git.run("rev-parse", "--path-format=absolute", "--git-common-dir").rstrip(b"\r\n")))
    configured = os.fsdecode(git.run("config", "--path", "--get", "core.hooksPath", accepted_codes=(0, 1))).rstrip("\r\n")
    directory = Path(configured) if configured else common / "hooks"
    if not directory.is_absolute():
        directory = git.root / directory
    target = directory / "pre-commit"
    no_links(target)
    if not (target.resolve().is_relative_to(git.root) or target.resolve().is_relative_to(common.resolve())):
        raise ScanError("Shared external hook directories require manual integration.")
    expected = hook_bytes()
    try:
        info = target.stat(follow_symlinks=False)
    except FileNotFoundError:
        info = None
    if info:
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 16384:
            raise ScanError("Existing hook is not a safe managed file.")
        actual = target.read_bytes()
        if actual != expected:
            raise ScanError("Existing hook preserved; compose it manually or use the pre-commit framework.")
    if action == "install":
        if info:
            target.chmod(0o755)
            return "Managed offline pre-commit hook is already installed."
        directory.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(expected)
        target.chmod(0o755)
        return "Installed offline pre-commit hook. Existing hooks and Git configuration were not overwritten."
    if action != "uninstall":
        raise ScanError("Unknown hook action.")
    if info:
        if target.read_bytes() != expected or target.stat().st_ino != info.st_ino:
            raise ScanError("Hook changed; removal refused.")
        target.unlink()
    return "Managed pre-commit hook removed; other hooks and configuration were preserved."


def event_refs(event: str, data: dict) -> tuple[str, str, bool] | None:
    """Use event SHAs, never PR branch names or the checkout's staged index."""
    try:
        if event == "pull_request":
            base = data["pull_request"]["base"]["sha"]
            head = data["pull_request"]["head"]["sha"]
            merge = True
        elif event == "push":
            base, head = data["before"], data["after"]
            merge = False
        else:
            raise ValueError
        if not all(isinstance(value, str) and re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", value) for value in (base, head)):
            raise ValueError
        if set(head) == {"0"}:
            if event == "push" and data.get("deleted") is True:
                return None
            raise ValueError
        if set(base) == {"0"}:
            if event != "push":
                raise ValueError
            base = "EMPTY"
        return base, head, merge
    except (KeyError, TypeError, ValueError):
        raise ScanError("CI event has invalid or unsupported comparison metadata.") from None


def ci_main(argv: list[str] | None = None) -> int:
    from codeshield.cli import main
    from codeshield.reporting import write_report
    parser = argparse.ArgumentParser(prog="codeshield-ci", description="Offline GitHub event comparison gate")
    parser.add_argument("--event", choices=("pull_request", "push"), default=os.environ.get("GITHUB_EVENT_NAME"))
    parser.add_argument("--event-file", type=Path, default=Path(os.environ["GITHUB_EVENT_PATH"]) if os.environ.get("GITHUB_EVENT_PATH") else None)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    code = 3
    try:
        if args.event_file is None or args.event not in ("pull_request", "push"):
            raise ScanError("CI event and event file are required.")
        no_links(args.event_file)
        info = args.event_file.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > 8 * 1024 * 1024:
            raise ScanError("CI event file is unsupported or too large.")
        with args.event_file.open("rb") as stream:
            payload = stream.read(8 * 1024 * 1024 + 1)
        if len(payload) > 8 * 1024 * 1024:
            raise ScanError("CI event file exceeds the size limit.")
        refs = event_refs(args.event, json.loads(payload))
        if refs is None:
            report = {"schema_version": "1", "validation_status": "not_run", "reason": "deleted_push", "exit_code": 0}
            write_report(args.output, json.dumps(report, indent=2) + "\n")
            return 0
        base, head, merge = refs
        command = ["scan", "--base-ref", base, "--head-ref", head, "--provider", "mock",
                   "--format", "json", "--output", str(args.output)]
        if merge:
            command.append("--merge-base")
        with automated():
            code = int(main(command))
        if code in (0, 1):
            return code
    except (OSError, ValueError, TypeError, RecursionError, ScanError):
        code = 3
    # No raw event, ref expression, exception payload, or fabricated clean summary.
    failure = {"schema_version": "1", "validation_status": "failed", "error": "ci_scan_failed", "exit_code": code}
    try:
        write_report(args.output, json.dumps(failure, indent=2) + "\n")
    except (ScanError, OSError):
        print("CI report could not be created; use a new writable output path.", file=sys.stderr)
        return 3
    print("CI security scan failed closed; inspect repository history and configuration.", file=sys.stderr)
    return code


def docker_main(argv: list[str] | None = None) -> int:
    """Scan-only container interface. The optional provider SDK is absent from the image."""
    from codeshield.cli import main
    parser = argparse.ArgumentParser(prog="codeshield-docker", description="Offline scan-only container")
    scope = parser.add_mutually_exclusive_group()
    scope.add_argument("--staged", action="store_true")
    scope.add_argument("--path")
    scope.add_argument("--base-ref")
    parser.add_argument("--head-ref")
    parser.add_argument("--merge-base", action="store_true")
    parser.add_argument("--provider", choices=("mock", "rules"), default="mock")
    parser.add_argument("--format", choices=("human", "json"), default="human")
    parser.add_argument("--output")
    parser.add_argument("--config")
    args = parser.parse_args(argv)
    command = ["scan", "--provider", args.provider, "--format", args.format]
    for name in ("path", "base_ref", "head_ref", "output", "config"):
        value = getattr(args, name)
        if value is not None:
            command.extend(["--" + name.replace("_", "-"), value])
    if args.staged:
        command.append("--staged")
    if args.merge_base:
        command.append("--merge-base")
    with automated():
        return main(command)


def entrypoint():
    parser = argparse.ArgumentParser(prog="python -m codeshield.integrations")
    parser.add_argument("integration", choices=("hook", "ci", "docker"))
    args, remaining = parser.parse_known_args()
    if args.integration == "hook":
        if remaining:
            parser.error("the staged hook does not accept arguments")
        return hook_main([])
    return ci_main(remaining) if args.integration == "ci" else docker_main(remaining)


if __name__ == "__main__":
    raise SystemExit(entrypoint())
