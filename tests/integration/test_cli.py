import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from codeshield import __version__


def cli(cwd, *args):
    return subprocess.run(
        [sys.executable, "-m", "codeshield", *args], cwd=cwd,
        capture_output=True, text=True, timeout=15,
    )


@pytest.fixture
def repo(tmp_path):
    subprocess.run(["git", "init", str(tmp_path)], check=True, capture_output=True)
    (tmp_path / ".gitignore").write_text(".env\n", encoding="utf-8")
    return tmp_path


def test_help_and_version(tmp_path):
    help_result = cli(tmp_path, "--help")
    assert help_result.returncode == 0
    assert all(name in help_result.stdout for name in ("doctor", "scan", "fix", "init"))
    assert cli(tmp_path, "--version").stdout.strip() == f"codeshield {__version__}"


def test_installed_console_entrypoint(tmp_path):
    executable = Path(sys.executable).parent / ("codeshield.exe" if sys.platform == "win32" else "codeshield")
    result = subprocess.run([str(executable), "--version"], cwd=tmp_path,
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0
    assert __version__ in result.stdout


def test_doctor_succeeds_without_mutation(repo):
    before = set(repo.rglob("*"))
    result = cli(repo, "doctor")
    assert result.returncode == 0, result.stderr
    assert "No scan performed" in result.stdout
    assert set(repo.rglob("*")) == before


def test_doctor_outside_git(tmp_path):
    result = cli(tmp_path, "doctor")
    assert result.returncode == 3
    assert "working-tree repository" in result.stderr


def test_doctor_rejects_unignored_env(repo):
    (repo / ".gitignore").unlink()
    assert cli(repo, "doctor").returncode == 3


def test_doctor_rejects_tracked_env_without_printing_contents(repo):
    (repo / ".env").write_text("FAKE_TRACKING_SENTINEL", encoding="utf-8")
    subprocess.run(["git", "add", "-f", ".env"], cwd=repo, check=True, capture_output=True)
    result = cli(repo, "doctor")
    assert result.returncode == 3
    assert "FAKE_TRACKING_SENTINEL" not in result.stdout + result.stderr


def test_invalid_config_does_not_leak(repo):
    (repo / "codeshield.toml").write_text('api_key="FAKE_CLI_SENTINEL"', encoding="utf-8")
    result = cli(repo, "doctor")
    assert result.returncode == 2
    assert "FAKE_CLI_SENTINEL" not in result.stdout + result.stderr


@pytest.mark.parametrize("args", [
    ["explain", "example"], ["fix", "example", "--dry-run"],
    ["fix", "example", "--apply", "--yes"], ["init"],
])
def test_unimplemented_commands_fail_closed_and_do_not_write(repo, args):
    before = set(repo.rglob("*"))
    result = cli(repo, *args)
    assert result.returncode == 3
    assert "not implemented in Phase 2" in result.stderr
    assert set(repo.rglob("*")) == before


def test_scan_does_not_create_or_overwrite_report(repo):
    output = repo / "report.json"
    output.write_text("preserve", encoding="utf-8")
    assert cli(repo, "scan", "--staged", "--format", "json", "--output", str(output)).returncode == 3
    assert output.read_text(encoding="utf-8") == "preserve"


@pytest.mark.parametrize("args", [
    [], ["unknown"], ["scan", "--staged", "--path", "."],
    ["scan", "--base-ref", "main"], ["scan", "--head-ref", "HEAD"],
    ["doctor", "--provider", "invalid"],
    ["fix", "example", "--apply", "--dry-run"],
])
def test_invalid_invocations(repo, args):
    assert cli(repo, *args).returncode == 2


@pytest.mark.parametrize("provider", ["gemini"])
def test_unavailable_providers_are_explicit(repo, provider):
    result = cli(repo, "doctor", "--provider", provider)
    assert result.returncode == 2
    assert "credentials" in result.stderr or "gemini extra" in result.stderr


def test_missing_git_is_failure(monkeypatch, capsys, tmp_path):
    from codeshield.cli import doctor
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(shutil, "which", lambda _: None)
    assert doctor(None, None) == 3
    assert "unavailable" in capsys.readouterr().err


def test_git_timeout_is_safe_failure(monkeypatch, capsys, tmp_path):
    from codeshield.cli import doctor
    monkeypatch.chdir(tmp_path)

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired("FAKE_TIMEOUT_SENTINEL", 1)

    monkeypatch.setattr(subprocess, "run", timeout)
    assert doctor(None, None) == 3
    output = capsys.readouterr()
    assert "FAKE_TIMEOUT_SENTINEL" not in output.out + output.err
