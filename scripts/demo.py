"""Reproducible offline journey; all modifications stay in a temporary repository."""
import ast
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from codeshield.arguments import SafeArgumentParser


def demo(approve=False):
    fixture = Path(__file__).resolve().parents[1] / "examples/demo-repo/app.py"
    source = fixture.read_text(encoding="utf-8").replace("  # codeshield: test-fixture", "")
    value = ast.literal_eval(ast.parse(source).body[0].value)
    if not isinstance(value, str) or not value.startswith("SyntheticPortfolioFixture_"):
        raise ValueError("Demo fixture must remain synthetic.")
    env = os.environ.copy()
    for name in ("GEMINI_API_KEY", "GOOGLE_API_KEY"):
        env.pop(name, None)
    with tempfile.TemporaryDirectory(prefix="codeshield-demo-") as directory:
        root = Path(directory)

        def run(command, expected=0):
            result = subprocess.run(command, cwd=root, env=env, stdin=subprocess.DEVNULL, capture_output=True,
                                    text=True, encoding="utf-8", timeout=60)
            if value in result.stdout + result.stderr or result.returncode != expected:
                raise ValueError("Demo check failed; captured output withheld for privacy.")
            return result.stdout

        def cli(*args, expected=0):
            return run([sys.executable, "-I", "-m", "codeshield", *args], expected)

        def git(*args):
            return run(["git", "-c", "core.autocrlf=false", *args])

        git("init", "-b", "main")
        print("Disposable synthetic repository created; automatic cleanup is enabled.")
        cli("init")
        (root / "app.py").write_text(source, encoding="utf-8", newline="\n")
        git("add", "app.py", ".gitignore", ".env.example", "codeshield.toml")
        report = json.loads(cli("scan", "--staged", "--provider", "mock", "--format", "json", expected=1))
        finding, = report["findings"]
        if finding["assessment_source"] != "mock" or finding["verification"]["status"] != "ok":
            raise ValueError("Demo verification did not complete offline.")
        identity = finding["finding_id"]
        print("Detection: blocked (exit 1). Verification: mock, no live API call.")
        print(cli("explain", identity, "--provider", "mock"), end="")
        print(cli("fix", identity, "--provider", "mock", "--dry-run"), end="")
        if not approve:
            print("Preview complete. Rerun with --approve-demo-fix to approve a fix in a new disposable repository.")
            return
        print(cli("fix", identity, "--provider", "mock", "--apply", "--yes", expected=1), end="")
        cli("scan", "--path", "app.py", "--provider", "mock")
        cli("scan", "--staged", "--provider", "mock", expected=1)
        print("Validated worktree; staged index still blocks (exit 1).")
        git("add", "app.py", ".gitignore", ".env.example")
        cli("scan", "--staged", "--provider", "mock")
        print("Demo passed: intentional restaging clears the staged finding (exit 0). No commit or push was made.")


def main():
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument("--approve-demo-fix", action="store_true", help="Explicitly approve remediation only in this disposable synthetic demo")
    args = parser.parse_args()
    try:
        demo(args.approve_demo_fix)
        return 0
    except (OSError, ValueError, SyntaxError, subprocess.TimeoutExpired):
        print("Demo failed safely. Check installation, Git and local remediation eligibility; no captured payload was displayed.", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
