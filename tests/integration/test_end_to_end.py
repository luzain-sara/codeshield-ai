"""Release journeys across CLI processes using disposable, synthetic repositories."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from codeshield.agent.workflow import plan_fix
from codeshield.config import Config
from codeshield.errors import ScanError
from codeshield.integrations import automated
from codeshield.remediation.patcher import apply_plan
from codeshield.scanner import scan

SECRET = "SyntheticReleaseSentinel_74_qZ!"  # codeshield: test-fixture
KEY = "SYNTHETIC_UNUSED_PROVIDER_KEY_54"


def cli(root, *args, module="codeshield", expected):
    env = os.environ.copy()
    env["GEMINI_API_KEY"] = KEY
    result = subprocess.run([sys.executable, "-I", "-m", module, *args], cwd=root,
                            env=env, input="", capture_output=True, text=True, encoding="utf-8", timeout=45)
    assert SECRET not in result.stdout + result.stderr
    assert KEY not in result.stdout + result.stderr
    assert result.returncode == expected, "Unexpected exit code; captured output withheld for privacy"
    return result.stdout


@pytest.mark.parametrize("runtime", ["python", "node"])
def test_process_journey_detection_verification_approval_restage_and_gates(git_repo, runtime):
    root, git, write = git_repo
    cli(root, "init", expected=0)
    git("add", ".")
    git("commit", "-m", "synthetic clean foundation")
    base = git("rev-parse", "HEAD").decode().strip()
    name = "service.py" if runtime == "python" else "server.js"
    if runtime == "node":
        write("package.json", json.dumps({"engines": {"node": ">=20"}, "scripts": {"start": "node server.js"}}))
    source = write(name, f'API_KEY = "{SECRET}"\n' if runtime == "python" else f'const apiKey = "{SECRET}";\n')  # codeshield: test-fixture
    git("add", ".")
    original_source, original_index = source.read_bytes(), (root / ".git/index").read_bytes()
    report = json.loads(cli(root, "scan", "--staged", "--format", "json", expected=1))
    finding, = report["findings"]
    assert report["provider"] == finding["assessment_source"] == "mock"
    assert finding["verification"]["status"] == "ok"
    assert finding["verification"]["states"][-1] == "complete"
    assert not finding["verification"]["fix_allowed"]
    identity = finding["finding_id"]
    cli(root, "explain", identity, expected=0)
    preview = cli(root, "fix", identity, "--dry-run", expected=0)
    assert "REDACTED_SECRET" in preview and "No Git staging/commit/push" in preview
    cli(root, "fix", identity, "--apply", expected=2)  # Pipes cannot grant approval.
    assert source.read_bytes() == original_source and (root / ".git/index").read_bytes() == original_index
    applied = cli(root, "fix", identity, "--apply", "--yes", expected=1)
    assert "requires_restage" in applied
    assert SECRET.encode() not in source.read_bytes()
    assert (root / ".git/index").read_bytes() == original_index
    assert git("rev-parse", "HEAD").decode().strip() == base
    assert not (root / ".env").exists()
    cli(root, "scan", "--path", name, expected=0)
    cli(root, "scan", "--staged", expected=1)
    cli(root, "hook", "install", expected=0)
    cli(root, "hook", module="codeshield.integrations", expected=1)
    git("add", name, ".gitignore", ".env.example")
    cli(root, "scan", "--staged", expected=0)
    git("commit", "-m", "synthetic reviewed environment refactor")  # Actual installed hook runs.
    head = git("rev-parse", "HEAD").decode().strip()
    cli(root, "scan", "--base-ref", base, "--head-ref", head, "--merge-base", expected=0)
    write("event.json", json.dumps({"pull_request": {"base": {"sha": base}, "head": {"sha": head}}}))
    cli(root, "ci", "--event", "pull_request", "--event-file", "event.json", "--output", "ci-report.json",
        module="codeshield.integrations", expected=0)
    artifact = (root / "ci-report.json").read_text()
    assert SECRET not in artifact and KEY not in artifact
    assert json.loads(artifact)["validation_status"] == "passed"


@pytest.mark.parametrize("failure", [RuntimeError, KeyboardInterrupt])
def test_interrupted_validation_rolls_back_and_retry_succeeds(git_repo, monkeypatch, failure):
    from codeshield.remediation import patcher
    root, git, write = git_repo
    write("app.py", f'API_KEY="{SECRET}"\n')  # codeshield: test-fixture
    git("add", ".")
    identity = scan(Config(), cwd=root).findings[0].finding_id
    before = (root / "app.py").read_bytes(), (root / ".git/index").read_bytes()
    original = patcher.validate_result

    def interrupt(*args):
        raise failure(SECRET + KEY)

    monkeypatch.setattr(patcher, "validate_result", interrupt)
    with pytest.raises(ScanError, match="rolled back") as exc:
        apply_plan(plan_fix(identity, Config(), cwd=root), approved=True)
    assert SECRET not in str(exc.value) and KEY not in str(exc.value)
    assert before == ((root / "app.py").read_bytes(), (root / ".git/index").read_bytes())
    assert not (root / ".env.example").exists()
    assert not (root / ".codeshield/remediation.lock").exists()
    assert not list(root.glob(".codeshield/remediation-*.tmp"))
    monkeypatch.setattr(patcher, "validate_result", original)
    assert "requires_restage" in apply_plan(plan_fix(identity, Config(), cwd=root), approved=True)


def test_stale_lock_and_automated_context_cannot_apply(git_repo):
    root, git, write = git_repo
    write("app.py", f'API_KEY="{SECRET}"\n')  # codeshield: test-fixture
    git("add", ".")
    identity = scan(Config(), cwd=root).findings[0].finding_id
    plan = plan_fix(identity, Config(), cwd=root)
    lock = write(".codeshield/remediation.lock", "synthetic existing lock\n")
    with pytest.raises(ScanError, match="stale lock"):
        apply_plan(plan, approved=True)
    assert lock.read_text() == "synthetic existing lock\n"
    lock.unlink()  # Explicit test recovery; production never removes an unknown lock.
    with automated(), pytest.raises(ScanError, match="CI"):
        plan_fix(identity, Config(), cwd=root)
    with automated(), pytest.raises(ScanError, match="CI"):
        apply_plan(plan, approved=True)
    assert SECRET in (root / "app.py").read_text()


@pytest.mark.parametrize("args", [["scan", "--provider", SECRET], [SECRET], ["scan", "--" + SECRET], ["scan", "--allow-l"]])
def test_parser_errors_redact_values_and_reject_abbreviated_opt_in(git_repo, args):
    cli(git_repo[0], *args, expected=2)


@pytest.mark.parametrize("integration,args", [("docker", ["--provider", SECRET]), ("ci", ["--event", SECRET]), ("hook", [SECRET])])
def test_integration_parser_errors_never_echo_secrets(git_repo, integration, args):
    cli(git_repo[0], integration, *args, module="codeshield.integrations", expected=2)


@pytest.mark.parametrize("approve", [False, True])
def test_documented_synthetic_demo(approve):
    root = Path(__file__).resolve().parents[2]
    result = subprocess.run([sys.executable, str(root / "scripts/demo.py"), *(["--approve-demo-fix"] if approve else [])],
                            cwd=root, capture_output=True, text=True, encoding="utf-8", timeout=120)
    assert "SyntheticPortfolioFixture_74_qZ!" not in result.stdout + result.stderr
    assert result.returncode == 0, "Demo failed; output withheld for privacy"
    assert ("Demo passed" if approve else "Preview complete") in result.stdout


@pytest.mark.parametrize("name,content", [(".env.example", "API_KEY=\nGEMINI_API_KEY=\n"), ("blank.yaml", "api_key:\npassword:\n")])
def test_adjacent_empty_credentials_do_not_become_each_others_values(git_repo, name, content):
    root, git, write = git_repo
    write(name, content)
    git("add", ".")
    assert not scan(Config(), cwd=root).findings
    write(name, content + ('PASSWORD=' if name.startswith('.env') else 'password: ') + SECRET + '\n')  # codeshield: test-fixture
    git("add", ".")
    assert scan(Config(), cwd=root).summary.blocking == 1
