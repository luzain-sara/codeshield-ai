"""Offline detection CLI with fail-closed, non-mutating scan commands."""

import argparse
from codeshield.arguments import SafeArgumentParser
import shutil
import subprocess
import sys
from pathlib import Path

from codeshield import __version__
from codeshield.config import ConfigError, load_config
from codeshield.models import ExitCode, Provider
from codeshield.errors import ScanError
from codeshield.reporting import render, write_report
from codeshield.scanner import scan
from codeshield.agent.providers import check_sdk_available, load_api_key
from codeshield.agent.workflow import plan_fix
from codeshield.remediation.patcher import apply_plan
import re


def doctor(config_path: Path | None, provider: str | None) -> int:
    try:
        config = load_config(config_path)
    except ConfigError as exc:
        print(str(exc), file=sys.stderr)
        return ExitCode.CONFIG_ERROR
    selected = Provider(provider) if provider else config.provider
    print(f"CodeShield {__version__} - setup diagnostics")
    print("Configuration: valid")
    if selected == Provider.GEMINI:
        try:
            check_sdk_available()
            load_api_key(Path.cwd())
        except ConfigError as exc:
            print(str(exc), file=sys.stderr)
            return ExitCode.CONFIG_ERROR
        print("Provider: gemini (credential configured; no provider call made)")
    else:
        print(f"Provider: {selected.value} (offline; no provider calls)")
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
    parser = SafeArgumentParser(
        prog="codeshield", description="CodeShield-AI: local credential scanning, verification and approved remediation."
    )
    parser.add_argument("--version", action="version", version=f"codeshield {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init", help="Create missing offline defaults without overwriting existing files")
    hook = commands.add_parser("hook", help="Install or remove the managed offline pre-commit gate")
    hook.add_argument("action", choices=("install", "uninstall"))
    for name in ("doctor", "scan", "explain", "fix"):
        command = commands.add_parser(name, help=(
            "Check foundation setup" if name == "doctor" else
            "Scan staged additions (default) or an explicit worktree path" if name == "scan" else
            "Explain a current staged finding without storing secrets" if name == "explain" else
            "Preview or approve a conservative working-tree fix"
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
            command.add_argument("--merge-base", action="store_true", help="Compare the unique merge base against the head commit")
            command.add_argument("--format", choices=("human", "json"), default="human")
            command.add_argument("--output", type=Path)
            command.add_argument("--allow-live", action="store_true", help="Explicitly allow sanitized Gemini verification outside CI")
        if name == "fix":
            mode = command.add_mutually_exclusive_group()
            mode.add_argument("--dry-run", action="store_true")
            mode.add_argument("--apply", action="store_true")
            command.add_argument("--yes", action="store_true")
            command.add_argument("--env-name", help="Approve a destination environment variable name")
            command.add_argument("--store-secret", action="store_true", help="Explicitly approve storing the value in an ignored private .env during apply")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "init":
        from codeshield.initialization import initialize
        try:
            sys.stdout.write(initialize(Path.cwd()))
            return ExitCode.SUCCESS
        except (ScanError, OSError, ValueError):
            print("Initialization incomplete; existing files were preserved. Review defaults and rerun init.", file=sys.stderr)
            return ExitCode.VALIDATION_FAILURE
    if args.command == "hook":
        from codeshield.integrations import manage_hook
        try:
            print(manage_hook(args.action, Path.cwd()))
            return ExitCode.SUCCESS
        except (ScanError, OSError, ValueError):
            print("Hook setup failed safely; existing or shared hooks were preserved. See the integration guide.", file=sys.stderr)
            return ExitCode.VALIDATION_FAILURE
    if args.command == "doctor":
        return doctor(args.config, args.provider)
    if args.command == "fix" and args.yes and not args.apply:
        parser.error("--yes requires --apply")
    if args.command in ("fix", "explain"):
        try:
            config = load_config(args.config)
            config = config.model_copy(update={"provider": Provider(args.provider) if args.provider else config.provider})
            if args.command == "explain":
                if not re.fullmatch("[0-9a-f]{24}", args.finding_id):
                    raise ConfigError("Finding ID must be the 24-character ID from a fresh staged scan.")
                if config.provider == Provider.GEMINI:
                    raise ConfigError("Explain uses offline reconstruction; select --provider mock or rules.")
                result = scan(config)
                found = [f for f in result.findings if f.finding_id == args.finding_id]
                if len(found) != 1:
                    raise ScanError("Finding is absent or stale; rerun the staged scan.")
                print(found[0].model_dump_json(indent=2))
                return ExitCode.SUCCESS
            plan = plan_fix(args.finding_id, config, cwd=Path.cwd(), env_name=args.env_name, store_secret=args.store_secret)
            sys.stdout.write(plan.preview())
            if not args.apply:
                print("Dry run: no files changed.")
                return ExitCode.SUCCESS
            approved = args.yes
            if not approved:
                if not sys.stdin.isatty():
                    raise ConfigError("Interactive approval is required; use --apply --yes only for trusted local automation.")
                try:
                    approved = input("Apply exactly this plan? [y/N] ").strip().lower() in ("y", "yes")
                except (EOFError, KeyboardInterrupt):
                    approved = False
            if not approved:
                print("Approval declined; no files changed.")
                return ExitCode.SUCCESS
            sys.stdout.write(apply_plan(plan, approved=True))
            return ExitCode.BLOCKING_FINDINGS  # The unchanged index must be restaged and checked.
        except ConfigError as exc:
            print(str(exc), file=sys.stderr)
            return ExitCode.CONFIG_ERROR
        except ScanError as exc:
            print(str(exc), file=sys.stderr)
            return ExitCode.VALIDATION_FAILURE
        except (OSError, UnicodeError, ValueError, RecursionError, TimeoutError):
            print("Remediation or explanation failed safely; review the repository and rerun a dry run.", file=sys.stderr)
            return ExitCode.VALIDATION_FAILURE
    if args.command == "scan" and bool(args.base_ref) != bool(args.head_ref):
        parser.error("--base-ref and --head-ref must be supplied together")
    if args.command == "scan" and args.merge_base and not args.base_ref:
        parser.error("--merge-base requires --base-ref and --head-ref")
    if args.command == "scan":
        try:
            config = load_config(args.config)
            selected = Provider(args.provider) if args.provider else config.provider
            if args.allow_live and selected != Provider.GEMINI:
                raise ConfigError("--allow-live requires the gemini provider.")
            config = config.model_copy(update={"provider": selected})
            if selected == Provider.GEMINI and args.allow_live:
                print("Gemini opt-in: only sanitized structural context may be sent to Google; no raw source or credential values.", file=sys.stderr)
            result = scan(config, path=args.path, live_enabled=args.allow_live,
                          base_ref=args.base_ref, head_ref=args.head_ref, merge_base=args.merge_base)
            report = render(result, args.format)
            if args.output:
                write_report(args.output, report)
            sys.stdout.write(report)
            if result.validation_status == "failed":
                print("Verification incomplete; findings remain unresolved and no fixes are authorized.", file=sys.stderr)
                return ExitCode.VALIDATION_FAILURE
            return ExitCode.BLOCKING_FINDINGS if result.summary.blocking else ExitCode.SUCCESS
        except ConfigError as exc:
            print(str(exc), file=sys.stderr)
            return ExitCode.CONFIG_ERROR
        except ScanError as exc:
            print(str(exc), file=sys.stderr)
            return ExitCode.VALIDATION_FAILURE
        except (OSError, UnicodeError, ValueError, TimeoutError):
            print("Scan or report validation failed; no complete result is available.", file=sys.stderr)
            return ExitCode.VALIDATION_FAILURE
    return ExitCode.VALIDATION_FAILURE
