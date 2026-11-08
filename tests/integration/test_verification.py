import json
from pathlib import Path

import pytest

from codeshield.cli import main
from codeshield.config import Config, ConfigError
from codeshield.models import Provider
from codeshield.scanner import scan

SECRET = "SyntheticPhaseTwoSentinel8_xQ!"  # codeshield: test-fixture


def test_default_mock_preserves_staged_findings_without_reading_credentials(git_repo, monkeypatch):
    root, git, write = git_repo
    write("app.py", f'password="{SECRET}"\n')
    git("add", ".")
    before = (root / ".git/index").read_bytes(), (root / "app.py").read_bytes()
    monkeypatch.setattr("codeshield.agent.providers.load_api_key", lambda *args: pytest.fail("Mock cannot load keys"))
    result = scan(Config(), cwd=root)
    assert result.provider == Provider.MOCK and result.findings[0].assessment_source == Provider.MOCK
    assert result.findings[0].verification.status == "ok" and result.summary.blocking == 1
    assert SECRET not in result.model_dump_json()
    assert not (root / ".codeshield").exists()
    assert before == ((root / ".git/index").read_bytes(), (root / "app.py").read_bytes())


def test_explicit_rules_mode_remains_fully_offline(git_repo, monkeypatch):
    root, git, write = git_repo
    write("app.py", f'password="{SECRET}"\n')
    git("add", ".")
    monkeypatch.setattr("codeshield.agent.providers.load_api_key", lambda *args: pytest.fail("Rules cannot load keys"))
    result = scan(Config(provider="rules"), cwd=root)
    assert result.provider == Provider.RULES and result.findings[0].assessment_source == Provider.RULES
    assert result.summary.blocking == 1 and not (root / ".codeshield").exists()


def test_mock_false_positive_is_advisory_and_still_blocks_at_threshold(git_repo):
    root, git, write = git_repo
    write("tests/example.py", 'session="xW7vB2mQ8zA4kT9rY6pL1sD5"\n')
    git("add", ".")
    result = scan(Config(blocking_severity="medium"), cwd=root)
    assert result.findings[0].verification.decision.classification == "false_positive"
    assert result.summary.blocking == 1 and not result.findings[0].verification.fix_allowed


@pytest.mark.parametrize("args", [
    ["scan", "--provider", "gemini"], ["scan", "--allow-live"],
    ["scan", "--provider", "rules", "--allow-live"],
])
def test_cli_live_opt_in_is_required_and_unambiguous(git_repo, monkeypatch, capsys, args):
    root, git, write = git_repo
    monkeypatch.chdir(root)
    assert main(args) == 2
    output = capsys.readouterr()
    assert not output.out


def test_config_cannot_enable_live_requests_without_cli_consent(git_repo, monkeypatch, capsys):
    root, git, write = git_repo
    write("codeshield.toml", 'provider="gemini"\n')
    monkeypatch.chdir(root)
    assert main(["scan"]) == 2
    assert "allow-live" in capsys.readouterr().err


@pytest.mark.parametrize("variable", ["CI", "GITHUB_ACTIONS", "GITLAB_CI", "TF_BUILD"])
def test_ci_disables_live_even_with_consent(git_repo, monkeypatch, variable):
    root, git, write = git_repo
    monkeypatch.setenv(variable, "true")
    with pytest.raises(ConfigError, match="CI"):
        scan(Config(provider="gemini"), cwd=root, live_enabled=True)


def test_json_and_human_reports_disclose_mock_provenance(git_repo, monkeypatch, capsys):
    root, git, write = git_repo
    write("app.py", f'password="{SECRET}"\n')
    git("add", ".")
    monkeypatch.chdir(root)
    assert main(["scan", "--format", "json"]) == 1
    output = capsys.readouterr()
    report = json.loads(output.out)
    assert report["provider"] == "mock"
    assert report["findings"][0]["verification"]["source"] == "mock"
    assert SECRET not in output.out + output.err
    assert main(["scan"]) == 1
    output = capsys.readouterr()
    assert "provider: mock" in output.out and "source=mock" in output.out
    assert SECRET not in output.out + output.err


def test_doctor_mock_never_reads_key(git_repo, monkeypatch, capsys):
    root, git, write = git_repo
    write(".gitignore", ".env\n")
    monkeypatch.chdir(root)
    monkeypatch.setattr("codeshield.cli.load_api_key", lambda *args: pytest.fail("No key should be loaded"))
    assert main(["doctor"]) == 0
    assert "mock (offline" in capsys.readouterr().out
