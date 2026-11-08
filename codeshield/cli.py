"""Phase 0 CLI: diagnostics and explicit, fail-closed placeholders."""

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

from codeshield import __version__
from codeshield.config import ConfigError, load_config
from codeshield.models import ExitCode, Provider


def doctor(config_path: Path | None, provider: str | None) -> int:
    try:
        config = load_config(config_path)
    except ConfigError as exc:
        print(str(exc), file=sys.stderr)
        return ExitCode.CONFIG_ERROR
    selected = Provider(provider) if provider else config.provider
    print(f"CodeShield {__version__} - Phase 0 diagnostics")
    print("Configuration: valid")
    if selected != Provider.RULES:
        print("Selected provider is not implemented in Phase 0.", file=sys.stderr)
        return ExitCode.CONFIG_ERROR
    print("Provider: rules (offline; no provider calls)")
    git = shutil.which("git")
    if git is None:
        print("Git: unavailable", file=sys.stderr)
        return ExitCode.VALIDATION_FAILURE

    def run_git(*args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [git, *args], capture_output=True, timeout=config.git_timeout_seconds,
            check=False,
        )

    try:
        if run_git("--version").returncode:
            print("Git: unavailable", file=sys.stderr)
            return ExitCode.VALIDATION_FAILURE
        if run_git("rev-parse", "--is-inside-work-tree").stdout.strip() != b"true":
            print("Git: run doctor inside a working-tree repository", file=sys.stderr)
            return ExitCode.VALIDATION_FAILURE
        tracked = run_git("ls-files", "--error-unmatch", "--", ".env")
        ignored = run_git("check-ignore", "-q", "--", ".env")
        if tracked.returncode == 0 or ignored.returncode != 0:
            print("Environment safety: .env must be untracked and Git-ignored", file=sys.stderr)
            return ExitCode.VALIDATION_FAILURE
        if tracked.returncode != 1:
            print("Git: could not verify environment tracking", file=sys.stderr)
            return ExitCode.VALIDATION_FAILURE
    except (OSError, subprocess.TimeoutExpired):
        print("Git diagnostic failed or timed out.", file=sys.stderr)
        return ExitCode.VALIDATION_FAILURE
    print("Git: available; working-tree repository found")
    print("Environment safety: .env is ignored and untracked")
    print("Foundation checks passed. No scan performed; commit safety is not assessed.")
    return ExitCode.SUCCESS


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="codeshield", description="CodeShield-AI: Phase 0 foundation (scanner not implemented)."
    )
    parser.add_argument("--version", action="version", version=f"codeshield {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("doctor", "scan", "explain", "fix", "init"):
        command = commands.add_parser(name, help=(
            "Check foundation setup" if name == "doctor" else "Reserved; unavailable in Phase 0"
        ))
        command.add_argument("--config", type=Path, help="Explicit TOML configuration file")
        command.add_argument("--provider", choices=[p.value for p in Provider])
        if name in ("explain", "fix"):
            command.add_argument("finding_id")
        if name == "scan":
            scope = command.add_mutually_exclusive_group()
            scope.add_argument("--staged", action="store_true")
            scope.add_argument("--path", type=Path)
            scope.add_argument("--base-ref")
            command.add_argument("--head-ref")
            command.add_argument("--format", choices=("human", "json"), default="human")
            command.add_argument("--output", type=Path)
        if name == "fix":
            mode = command.add_mutually_exclusive_group()
            mode.add_argument("--dry-run", action="store_true")
            mode.add_argument("--apply", action="store_true")
            command.add_argument("--yes", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "doctor":
        return doctor(args.config, args.provider)
    if args.command == "scan" and bool(args.base_ref) != bool(args.head_ref):
        parser.error("--base-ref and --head-ref must be supplied together")
    print(
        f"{args.command} is not implemented in Phase 0. No scan or file changes performed.",
        file=sys.stderr,
    )
    return ExitCode.VALIDATION_FAILURE
