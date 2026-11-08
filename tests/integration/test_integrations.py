"""Real Git operations use synthetic disposable repositories, never the project index."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

from codeshield.config import Config
from codeshield.errors import ScanError
from codeshield.integrations import automated, ci_main, docker_main, event_refs, hook_main, manage_hook
from codeshield.scanner import scan

SECRET = "SyntheticPhaseFourSentinel8_qZ!"


def commit(git):
    git("add", ".")
    git("commit", "-m", "synthetic snapshot")
    return git("rev-parse", "HEAD").decode().strip()


def test_ref_scan_uses_immutable_trees_and_only_added_lines(git_repo):
    root, git, write = git_repo
    write("app.py", f'password="{SECRET}"\nanswer=1\n')
    base = commit(git)
    write("app.py", f'password="{SECRET}"\nanswer=2\napi_key="{SECRET}"\n')
    head = commit(git)
    source = write("app.py", "answer=3\n")
    git("add", ".")
    before = source.read_bytes(), (root / ".git/index").read_bytes()
    report = scan(Config(), cwd=root, base_ref=base, head_ref=head)
    assert [f.line for f in report.findings] == [3]
    assert report.base_commit == base and report.head_commit == head
    assert report.scan_scope == "refs" and report.comparison == "endpoints"
    assert SECRET not in report.model_dump_json()
    assert before == (source.read_bytes(), (root / ".git/index").read_bytes())


@pytest.mark.parametrize("ending", ["", "\n", "\r\n"])
def test_new_branch_empty_tree_and_tags(git_repo, ending):
    root, git, write = git_repo
    write("file with spaces.py", f'api_key="{SECRET}"' + ending)
    head = commit(git)
    git("tag", "-a", "snapshot", "-m", "synthetic tag")
    report = scan(Config(), cwd=root, base_ref="EMPTY", head_ref="snapshot")
    assert report.summary.blocking == 1 and report.head_commit == head
    assert not scan(Config(), cwd=root, base_ref=head, head_ref=head).findings


@pytest.mark.parametrize("edited", [False, True])
def test_refs_rename_and_deletion(git_repo, edited):
    root, git, write = git_repo
    text = f'password="{SECRET}"\n' + 'answer=1\n' * 30
    write("old.py", text)
    write("removed.py", f'password="{SECRET}"\n')
    base = commit(git)
    git("mv", "old.py", "new name.py")
    git("rm", "removed.py")
    if edited:
        write("new name.py", text + f'api_key="{SECRET}"\n')
    head = commit(git)
    result = scan(Config(), cwd=root, base_ref=base, head_ref=head)
    assert len(result.findings) == int(edited)


def test_pr_merge_base_differs_from_endpoint_diff(git_repo):
    root, git, write = git_repo
    write("app.py", "answer=1\n")
    common = commit(git)
    git("branch", "feature")
    write("app.py", f'api_key="{SECRET}"\n')
    base = commit(git)
    git("checkout", "feature")
    write("app.py", f'api_key="{SECRET}"\n')
    write("feature.py", "answer=2\n")
    head = commit(git)
    assert not scan(Config(), cwd=root, base_ref=base, head_ref=head).findings
    report = scan(Config(), cwd=root, base_ref=base, head_ref=head, merge_base=True)
    assert report.summary.blocking == 1 and report.base_commit == common


@pytest.mark.parametrize("ref", ["missing", "--output=credential", "bad\nref", SECRET])
def test_bad_refs_fail_closed_without_echo(git_repo, ref):
    root, git, write = git_repo
    write("a.py", "answer=1\n")
    head = commit(git)
    with pytest.raises(ScanError) as exc:
        scan(Config(), cwd=root, base_ref=ref, head_ref=head)
    assert ref not in str(exc.value)


def test_ref_comparison_ignores_unmerged_index(git_repo):
    root, git, write = git_repo
    write("a.py", f'password="{SECRET}"\n')
    head = commit(git)
    oid = git("hash-object", "-w", "--stdin", input=b"answer=1\n").strip()
    git("update-index", "--index-info", input=b"100644 " + oid + b" 1\tconflict.py\n")
    assert scan(Config(), cwd=root, base_ref="EMPTY", head_ref=head).summary.blocking == 1


def test_native_hook_blocks_staged_secret_and_allows_clean_commit(git_repo):
    root, git, write = git_repo
    manage_hook("install", root)
    assert "already installed" in manage_hook("install", root)
    write("app.py", "answer=1\n")
    commit(git)
    write("app.py", f'password="{SECRET}"\n')
    git("add", "app.py")
    write("app.py", "answer=2\n")
    before = git("ls-files", "--stage", "-z")
    result = subprocess.run(["git", "-C", str(root), "commit", "-m", "must block"], capture_output=True)
    assert result.returncode != 0
    assert SECRET.encode() not in result.stdout + result.stderr
    # Git commit itself refreshes index stat metadata, even when its hook blocks.
    assert before == git("ls-files", "--stage", "-z")
    manage_hook("uninstall", root)
    assert not (root / ".git/hooks/pre-commit").exists()


def test_hook_preserves_existing_and_supports_local_hooks_path(git_repo):
    root, git, write = git_repo
    git("config", "core.hooksPath", "local hooks")
    existing = write("local hooks/pre-commit", "#!/bin/sh\nexit 0\n")
    for action in ("install", "uninstall"):
        with pytest.raises(ScanError):
            manage_hook(action, root)
        assert existing.read_bytes() == b"#!/bin/sh\nexit 0\n"
    existing.unlink()
    manage_hook("install", root)
    assert b" -I -m " in existing.read_bytes()
    manage_hook("uninstall", root)
    git("config", "core.hooksPath", str(root.parent / "shared-hooks"))
    with pytest.raises(ScanError):
        manage_hook("install", root)


def test_hook_forces_mock_over_repository_provider(git_repo, monkeypatch, capsys):
    root, git, write = git_repo
    write("codeshield.toml", 'provider="gemini"\n')
    write("app.py", f'password="{SECRET}"\n')
    git("add", ".")
    monkeypatch.chdir(root)
    assert hook_main([]) == 1
    assert SECRET not in capsys.readouterr().out


def test_automation_guard_restores_environment(monkeypatch):
    from codeshield.agent.providers import require_live_opt_in
    from codeshield.config import ConfigError
    import os
    monkeypatch.setenv("CODESHIELD_AUTOMATED", "prior")
    with automated(), pytest.raises(ConfigError, match="automated"):
        require_live_opt_in(True)
    assert os.environ["CODESHIELD_AUTOMATED"] == "prior"


def test_github_event_refs():
    a, b, zero = "a" * 40, "b" * 40, "0" * 40
    assert event_refs("pull_request", {"pull_request": {"base": {"sha": a}, "head": {"sha": b}}}) == (a, b, True)
    assert event_refs("push", {"before": zero, "after": b}) == ("EMPTY", b, False)
    assert event_refs("push", {"before": a, "after": zero, "deleted": True}) is None
    for payload in ({}, {"before": SECRET, "after": b}, {"before": a, "after": zero}):
        with pytest.raises(ScanError) as exc:
            event_refs("push", payload)
        assert SECRET not in str(exc.value)


@pytest.mark.parametrize("event", ["push", "pull_request"])
def test_ci_redacted_report_and_no_mutation(git_repo, monkeypatch, capsys, event):
    root, git, write = git_repo
    write("app.py", "answer=1\n")
    base = commit(git)
    source = write("app.py", f'password="{SECRET}"\n')
    head = commit(git)
    payload = {"before": base, "after": head} if event == "push" else {"pull_request": {"base": {"sha": base}, "head": {"sha": head}}}
    write("event.json", json.dumps(payload))
    write("codeshield.toml", 'provider="gemini"\n')
    monkeypatch.chdir(root)
    before = source.read_bytes(), (root / ".git/index").read_bytes()
    assert ci_main(["--event", event, "--event-file", "event.json", "--output", "report.json"]) == 1
    report = (root / "report.json").read_text()
    assert json.loads(report)["provider"] == "mock"
    captured = capsys.readouterr()
    assert SECRET not in report + captured.out + captured.err
    assert before == (source.read_bytes(), (root / ".git/index").read_bytes())


@pytest.mark.parametrize("payload", ["invalid json", "[]", '{"before":"' + SECRET + '","after":"bad"}', '{"before":"' + 'a'*40 + '","after":"' + 'b'*40 + '"}'])
def test_ci_failure_report_is_not_a_clean_scan(git_repo, monkeypatch, capsys, payload):
    root, git, write = git_repo
    write("event.json", payload)
    monkeypatch.chdir(root)
    assert ci_main(["--event", "push", "--event-file", "event.json", "--output", "report.json"]) == 3
    text = (root / "report.json").read_text()
    report = json.loads(text)
    assert report["validation_status"] == "failed" and "summary" not in report
    captured = capsys.readouterr()
    assert SECRET not in text + captured.out + captured.err


def test_ci_deleted_push_and_existing_output(git_repo, monkeypatch):
    root, git, write = git_repo
    write("event.json", json.dumps({"before": "a"*40, "after": "0"*40, "deleted": True}))
    monkeypatch.chdir(root)
    args = ["--event", "push", "--event-file", "event.json", "--output", "report.json"]
    assert ci_main(args) == 0
    before = (root / "report.json").read_bytes()
    assert ci_main(args) == 3
    assert (root / "report.json").read_bytes() == before


@pytest.mark.parametrize("args", [["--provider", "gemini"], ["--allow-live"], ["fix"]])
def test_docker_interface_rejects_live_and_mutation(args):
    with pytest.raises(SystemExit) as exc:
        docker_main(args)
    assert exc.value.code == 2


def test_docker_interface_scans_offline(git_repo, monkeypatch):
    root, git, write = git_repo
    write("app.py", f'password="{SECRET}"\n')
    git("add", ".")
    monkeypatch.chdir(root)
    assert docker_main([]) == 1


def test_ref_resolution_is_not_repeated_after_branch_moves(git_repo, monkeypatch):
    import codeshield.scanner as scanner_module
    root, git, write = git_repo
    write("app.py", "answer=1\n")
    base = commit(git)
    write("app.py", f'password="{SECRET}"\n')
    head = commit(git)
    original = scanner_module.ref_changes

    def move_branch(reader, base_oid, head_oid):
        git("update-ref", "refs/heads/main", base)
        return original(reader, base_oid, head_oid)

    monkeypatch.setattr(scanner_module, "ref_changes", move_branch)
    report = scan(Config(), cwd=root, base_ref=base, head_ref="main")
    assert report.head_commit == head and report.summary.blocking == 1


def test_shallow_history_does_not_fall_back_to_index(git_repo):
    root, git, write = git_repo
    write("app.py", "answer=1\n")
    base = commit(git)
    write("app.py", f'password="{SECRET}"\n')
    head = commit(git)
    clone = root.parent / (root.name + "-shallow")
    subprocess.run(["git", "clone", "--depth=1", root.as_uri(), str(clone)], check=True, capture_output=True)
    with pytest.raises(ScanError, match="history"):
        scan(Config(), cwd=clone, base_ref=base, head_ref=head)


def test_unrelated_histories_refuse_merge_base(git_repo):
    root, git, write = git_repo
    write("a.py", "answer=1\n")
    base = commit(git)
    git("checkout", "--orphan", "unrelated")
    write("b.py", "answer=2\n")
    head = commit(git)
    with pytest.raises(ScanError):
        scan(Config(), cwd=root, base_ref=base, head_ref=head, merge_base=True)


def test_ambiguous_merge_base_fails_closed(git_repo, monkeypatch):
    from codeshield.git_diff import Git
    root, git, write = git_repo
    write("a.py", "answer=1\n")
    head = commit(git)
    original = Git.run

    def multiple_bases(self, *args, **kwargs):
        if args[0] == "merge-base":
            return (head + "\n" + "a"*40 + "\n").encode()
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Git, "run", multiple_bases)
    with pytest.raises(ScanError, match="one merge base"):
        scan(Config(), cwd=root, base_ref=head, head_ref=head, merge_base=True)


def test_linked_worktree_installer_targets_common_hooks(git_repo):
    root, git, write = git_repo
    write("a.py", "answer=1\n")
    commit(git)
    worktree = root.parent / (root.name + "-linked")
    git("worktree", "add", "-b", "linked", str(worktree))
    manage_hook("install", worktree)
    assert (root / ".git/hooks/pre-commit").is_file()
    manage_hook("uninstall", worktree)


def test_hook_rejects_linked_paths(git_repo, monkeypatch):
    root, git, write = git_repo
    original = Path.is_symlink
    monkeypatch.setattr(Path, "is_symlink", lambda self: self.name == "hooks" or original(self))
    with pytest.raises(ScanError, match="links"):
        manage_hook("install", root)


@pytest.mark.parametrize("arguments", [["scan", "--head-ref", "HEAD"], ["scan", "--merge-base"], ["scan", "--staged", "--base-ref", "HEAD", "--head-ref", "HEAD"]])
def test_invalid_ref_cli_combinations(arguments):
    from codeshield.cli import main
    with pytest.raises(SystemExit) as exc:
        main(arguments)
    assert exc.value.code == 2
