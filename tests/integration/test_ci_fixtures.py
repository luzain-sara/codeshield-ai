"""Self-scan regressions: explicit synthetic annotations never exempt test directories."""
import json
from pathlib import Path

import pytest

from codeshield.config import Config
from codeshield.integrations import ci_main
from codeshield.scanner import scan

PROJECT = Path(__file__).resolve().parents[2]
FILES = ("tests/integration/test_integrations.py", "scripts/check_docker.py")


def fixture_snapshots(git_repo):
    root, git, write = git_repo
    write("README.md", "Synthetic CI baseline\n")
    git("add", ".")
    git("commit", "-m", "synthetic baseline")
    base = git("rev-parse", "HEAD").decode().strip()
    for name in FILES:
        write(name, (PROJECT / name).read_bytes())
    git("add", ".")
    return root, git, write, base


@pytest.mark.parametrize("event", ["push", "pull_request"])
def test_real_fixture_sources_pass_staged_ref_and_ci_gates(git_repo, monkeypatch, capsys, event):
    root, git, write, base = fixture_snapshots(git_repo)
    index = (root / ".git/index").read_bytes()
    assert scan(Config(), cwd=root).summary.blocking == 0
    assert (root / ".git/index").read_bytes() == index
    git("commit", "-m", "synthetic annotated fixtures")
    head = git("rev-parse", "HEAD").decode().strip()
    report = scan(Config(), cwd=root, base_ref=base, head_ref=head, merge_base=(event == "pull_request"))
    assert report.summary.total == report.summary.blocking == 0
    payload = {"before": base, "after": head} if event == "push" else {"pull_request": {"base": {"sha": base}, "head": {"sha": head}}}
    write("event.json", json.dumps(payload))
    monkeypatch.chdir(root)
    assert ci_main(["--event", event, "--event-file", "event.json", "--output", "report.json"]) == 0
    assert json.loads((root / "report.json").read_text())["summary"]["blocking"] == 0


@pytest.mark.parametrize("kind", ["same_sentinel", "known_prefix", "marker_in_string"])
@pytest.mark.parametrize("name", ["tests/integration/test_integrations.py", "tests/test_unmarked.py"])
def test_unmarked_credentials_in_test_files_still_block_and_are_redacted(git_repo, monkeypatch, capsys, name, kind):
    root, git, write, base = fixture_snapshots(git_repo)
    # The identical value is exempt only on its explicitly annotated source line.
    sentinel = "SyntheticPhaseFourSentinel8_qZ!"
    if kind == "known_prefix":
        sentinel = "AIza" + "X7q" * 11 + "Z9"  # Invented recognizable shape, never a real API key.
    suffix = '; message="codeshield: test-fixture"' if kind == "marker_in_string" else ""
    original = (root / name).read_bytes() if (root / name).exists() else b""
    write(name, original + ('\npassword="' + sentinel + '"' + suffix + '\n').encode())  # codeshield: test-fixture
    git("add", ".")
    staged = scan(Config(), cwd=root)
    assert staged.summary.blocking == 1 and staged.findings[0].path == name
    assert sentinel not in staged.model_dump_json()
    git("commit", "-m", "synthetic unmarked credential probe")
    head = git("rev-parse", "HEAD").decode().strip()
    compared = scan(Config(), cwd=root, base_ref=base, head_ref=head)
    assert compared.summary.blocking == 1 and sentinel not in compared.model_dump_json()
    write("event.json", json.dumps({"before": base, "after": head}))
    monkeypatch.chdir(root)
    assert ci_main(["--event", "push", "--event-file", "event.json", "--output", "report.json"]) == 1
    captured = capsys.readouterr()
    assert sentinel not in captured.out + captured.err + (root / "report.json").read_text()


def test_fixture_marker_scope_is_one_comment_line(git_repo):
    root, git, write = git_repo
    sentinel = "SyntheticUnmarkedCredentialProbe_97"
    write("tests/test_scope.py", 'password="' + sentinel + '" # codeshield: test-fixture\npassword="' + sentinel + '"\n')  # codeshield: test-fixture
    git("add", ".")
    result = scan(Config(), cwd=root)
    assert [finding.line for finding in result.findings] == [2]
