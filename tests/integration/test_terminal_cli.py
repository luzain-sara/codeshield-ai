import json
from io import StringIO
import subprocess
import sys

import pytest

from codeshield.cli import main

SECRET = "SyntheticTerminalCredential_84_qZ!"  # codeshield: test-fixture


@pytest.mark.parametrize("prefix,suffix", [(["--no-color"], []), ([], ["--no-color"])])
def test_human_cli_is_redacted_and_json_file_stays_identical(git_repo, prefix, suffix):
    root, git, write = git_repo
    write("app.py", f'API_KEY="{SECRET}"\n')  # codeshield: test-fixture
    git("add", ".")
    def run(*args):
        return subprocess.run([sys.executable, "-I", "-m", "codeshield", *prefix, "scan", *args, *suffix], cwd=root,
                              capture_output=True, text=True, encoding="utf-8", timeout=30)
    result = run("--output", "human.txt")
    assert result.returncode == 1
    human = (root / "human.txt").read_text()
    assert "Finding 1 | HIGH" in result.stdout and "Security gate: BLOCKED" in result.stdout
    assert SECRET not in result.stdout + result.stderr + human and "\x1b" not in result.stdout + human
    result = run("--format", "json", "--output", "report.json")
    assert result.returncode == 1 and json.loads(result.stdout)["summary"]["blocking"] == 1
    assert result.stdout == (root / "report.json").read_text()
    assert "CodeShield-AI" not in result.stdout and SECRET not in result.stdout + result.stderr


def test_cli_errors_do_not_print_a_clean_gate_or_write_success_report(git_repo, monkeypatch, capsys):
    root, git, write = git_repo
    monkeypatch.chdir(root)
    assert main(["scan", "--path", "missing.py", "--output", "report.json"]) == 3
    captured = capsys.readouterr()
    assert not captured.out and "Security gate: ERROR" in captured.err
    assert not (root / "report.json").exists()
    assert main(["scan", "--provider", "gemini"]) == 2
    captured = capsys.readouterr()
    assert not captured.out and "Security gate: ERROR" in captured.err and "exit 2" in captured.err
    assert main(["scan", "--provider", "gemini", "--format", "json"]) == 2
    captured = capsys.readouterr()
    assert not captured.out and "\x1b" not in captured.err and "Security gate:" not in captured.err


def test_report_write_failure_never_prints_pass(git_repo, monkeypatch, capsys):
    root, git, write = git_repo
    write("existing.txt", "preserve")
    monkeypatch.chdir(root)
    assert main(["scan", "--output", "existing.txt"]) == 3
    captured = capsys.readouterr()
    assert not captured.out and "Security gate: ERROR" in captured.err
    assert (root / "existing.txt").read_text() == "preserve"


def test_json_cli_does_not_import_rich(git_repo):
    root, git, write = git_repo
    code = "import sys; from codeshield.cli import main; assert main(['scan','--format','json']) == 0; assert 'rich' not in sys.modules"
    result = subprocess.run([sys.executable, "-I", "-c", code], cwd=root, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0 and json.loads(result.stdout)["provider"] == "mock"


def test_color_terminal_output_does_not_add_ansi_to_saved_report(git_repo, monkeypatch):
    class Terminal(StringIO):
        def isatty(self):
            return True
    root, git, write = git_repo
    monkeypatch.chdir(root)
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("CLICOLOR", raising=False)
    monkeypatch.setenv("TERM", "xterm")
    output = Terminal()
    monkeypatch.setattr(sys, "stdout", output)
    assert main(["scan", "--output", "human.txt"]) == 0
    assert "\x1b" in output.getvalue()
    saved = (root / "human.txt").read_text()
    assert "\x1b" not in saved and "Security gate: PASS" in saved


def test_failed_verification_human_gate_matches_exit_three(git_repo, monkeypatch, capsys):
    from codeshield.config import Config
    from codeshield.scanner import scan
    root, git, write = git_repo
    write("app.py", f'API_KEY="{SECRET}"\n')  # codeshield: test-fixture
    git("add", ".")
    failed = scan(Config(), cwd=root).model_copy(update={"validation_status": "failed"})
    monkeypatch.setattr("codeshield.cli.scan", lambda *args, **kwargs: failed)
    monkeypatch.chdir(root)
    assert main(["scan"]) == 3
    captured = capsys.readouterr()
    assert "Security gate: ERROR" in captured.out and "Security gate: PASS" not in captured.out
    assert SECRET not in captured.out + captured.err
