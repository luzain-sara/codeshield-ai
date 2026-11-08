import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from codeshield.config import Config
from codeshield.errors import ScanError
from codeshield.models import ScanResult
from codeshield.scanner import scan

SECRET = "SyntheticDetectionSentinel7_qZ!"
OTHER = "SyntheticUnstagedSentinel9_wX!"


def run_cli(root, *args):
    return subprocess.run([sys.executable, "-m", "codeshield", *args], cwd=root,
                          capture_output=True, text=True, encoding="utf-8", timeout=30)


def assert_private(output):
    assert SECRET not in output
    assert OTHER not in output


def test_staged_snapshot_added_lines_and_unchanged_secrets(git_repo):
    root, git, write = git_repo
    write("app.py", f'password="{OTHER}"\nanswer=1\n')
    git("add", ".")
    git("commit", "-m", "synthetic baseline")
    write("app.py", f'password="{OTHER}"\nanswer=2\nAPI_KEY="{SECRET}"\n')
    git("add", "app.py")
    write("app.py", 'password="YOUR_API_KEY"\nanswer=3\n')
    result = scan(Config(), cwd=root)
    assert [(f.line, f.rule_id) for f in result.findings] == [(3, "secret-assignment")]
    assert result.scan_scope == "staged"
    assert result.summary.blocking == 1
    assert_private(result.model_dump_json())


@pytest.mark.parametrize("state", ["unstaged", "removed", "untracked", "deleted", "intent-to-add"])
def test_out_of_scope_content_is_not_reported(git_repo, state):
    root, git, write = git_repo
    write("app.py", f'password="{SECRET}"\n')
    if state == "untracked":
        pass
    elif state == "intent-to-add":
        git("add", "-N", "app.py")
    else:
        git("add", ".")
        git("commit", "-m", "synthetic baseline")
        if state == "unstaged":
            write("app.py", f'password="{OTHER}"\n')
        elif state == "removed":
            write("app.py", "answer=1\n")
            git("add", ".")
        else:
            git("rm", "app.py")
    assert not scan(Config(), cwd=root).findings


@pytest.mark.parametrize("name", ["file with spaces.py", "café 文件.py", "-literal.py", "[bracket].py"])
def test_unusual_paths_unborn_repo_crlf_and_missing_final_newline(git_repo, name):
    root, git, write = git_repo
    write(name, f'answer=1\r\nAPI_KEY="{SECRET}"'.encode("utf-8"))
    git("add", "--", name)
    result = scan(Config(), cwd=root)
    assert len(result.findings) == 1
    assert result.findings[0].line == 2
    assert result.findings[0].path == name


@pytest.mark.parametrize("with_addition", [False, True])
def test_renamed_files_only_report_new_lines(git_repo, with_addition):
    root, git, write = git_repo
    text = f'password="{OTHER}"\n' + "answer=1\n" * 20
    write("old name.py", text)
    git("add", ".")
    git("commit", "-m", "synthetic baseline")
    git("mv", "old name.py", "new name.py")
    if with_addition:
        write("new name.py", text + f'apiKey="{SECRET}"\n')
        git("add", ".")
    result = scan(Config(), cwd=root)
    assert len(result.findings) == int(with_addition)
    if with_addition:
        assert result.findings[0].path == "new name.py"
        assert result.findings[0].line == 22


def test_comments_use_unchanged_snapshot_context(git_repo):
    root, git, write = git_repo
    write("a.ts", "/*\nold comment\n*/\n")
    git("add", ".")
    git("commit", "-m", "synthetic baseline")
    write("a.ts", f'/*\npassword="{SECRET}"\n*/\n')
    git("add", ".")
    assert not scan(Config(), cwd=root).findings


@pytest.mark.parametrize("name", ["node_modules/app.py", "vendor/a.ts", ".venv/a.py", "a.bin", "generated/output.py"])
def test_protected_and_configured_exclusions(git_repo, name):
    root, git, write = git_repo
    write(name, f'password="{SECRET}"')
    git("add", "-f", "--", name)
    result = scan(Config(exclude_dirs=("generated",)), cwd=root)
    assert not result.findings
    assert result.skipped_files


def test_binary_is_skipped(git_repo):
    root, git, write = git_repo
    write("binary.py", b"\0" + f'password="{SECRET}"'.encode())
    git("add", ".")
    result = scan(Config(), cwd=root)
    assert not result.findings
    assert result.skipped_files[0].reason == "binary"


@pytest.mark.parametrize("content", [b"\xff\xfeh\x00i\x00", b"password='\xff'\n"])
def test_unsupported_encoding_fails_closed(git_repo, content):
    root, git, write = git_repo
    write("a.py", content)
    git("add", ".")
    with pytest.raises(ScanError, match="encoding"):
        scan(Config(), cwd=root)


def test_utf8_bom_is_supported(git_repo):
    root, git, write = git_repo
    write("a.py", b"\xef\xbb\xbf" + f'password="{SECRET}"\n'.encode())
    git("add", ".")
    assert scan(Config(), cwd=root).summary.blocking == 1


def test_tracked_ignored_env_is_scanned(git_repo):
    root, git, write = git_repo
    write(".gitignore", ".env\n")
    write(".env", f"API_KEY={SECRET}\n")
    git("add", "-f", ".env")
    assert scan(Config(), cwd=root).summary.blocking == 1


def test_worktree_opt_in_uses_current_contents_and_git_ignores(git_repo):
    root, git, write = git_repo
    write(".gitignore", "ignored.py\n.env\n")
    write("a.py", 'password="YOUR_API_KEY"\n')
    git("add", ".")
    write("a.py", f'password="{SECRET}"\n')
    write("ignored.py", f'password="{OTHER}"\n')
    write(".env", f"API_KEY={OTHER}")
    assert not scan(Config(), cwd=root).findings
    result = scan(Config(), cwd=root, path=Path("."))
    assert result.scan_scope == "worktree"
    assert [f.path for f in result.findings] == ["a.py"]
    assert_private(result.model_dump_json())


def test_path_selection_and_subdirectory_staged_scan(git_repo):
    root, git, write = git_repo
    write("sub/a.py", f'password="{SECRET}"')
    write("b.py", f'password="{OTHER}"')
    git("add", ".")
    result = scan(Config(), cwd=root, path=Path("sub"))
    assert [f.path for f in result.findings] == ["sub/a.py"]
    assert len(scan(Config(), cwd=root / "sub").findings) == 2


def test_symlink_blob_never_followed(git_repo):
    root, git, write = git_repo
    # Construct Git's symlink entry portably, even where Windows denies symlink creation.
    oid = git("hash-object", "-w", "--stdin", input=b"../outside.py").strip().decode()
    git("update-index", "--add", "--cacheinfo", f"120000,{oid},link.py")
    result = scan(Config(), cwd=root)
    assert not result.findings
    assert result.skipped_files[0].reason == "link_or_submodule"


def test_worktree_symlink_escape(git_repo):
    root, git, write = git_repo
    outside = root.parent / "outside.py"
    outside.write_text(f'password="{SECRET}"', encoding="utf-8")
    try:
        (root / "link.py").symlink_to(outside)
    except OSError:
        pytest.skip("Windows symlink creation is unavailable")
    result = scan(Config(), cwd=root, path=Path("."))
    assert not result.findings
    assert any(s.reason == "link_or_submodule" for s in result.skipped_files)
    with pytest.raises(ScanError, match="links"):
        scan(Config(), cwd=root, path=Path("link.py"))


@pytest.mark.parametrize("config", [
    Config(max_file_bytes=8), Config(max_file_bytes=100, max_scan_bytes=100),
    Config(max_files=1), Config(max_findings=1),
])
def test_limits_fail_closed_without_secret_output(git_repo, config):
    root, git, write = git_repo
    write("a.py", f'password="{SECRET}"\n')
    write("b.py", f'password="{OTHER}"\n')
    git("add", ".")
    with pytest.raises(ScanError, match="limit") as exc:
        scan(config, cwd=root)
    assert_private(str(exc.value))


def test_fingerprints_do_not_depend_on_secret_value_and_order_is_stable(git_repo):
    root, git, write = git_repo
    write("b.py", f'password="{SECRET}"\n')
    write("a.py", f'password="{OTHER}"\n')
    git("add", ".")
    first = scan(Config(), cwd=root)
    second = scan(Config(), cwd=root)
    assert first.findings == second.findings
    assert [f.path for f in first.findings] == ["a.py", "b.py"]
    write("b.py", f'password="{OTHER}"\n')
    git("add", ".")
    assert [f.finding_id for f in scan(Config(), cwd=root).findings] == [f.finding_id for f in first.findings]


@pytest.mark.parametrize("format", ["human", "json"])
def test_cli_report_exit_code_privacy_and_no_source_index_mutation(git_repo, format):
    root, git, write = git_repo
    source = write("a.py", f'password="{SECRET}"; unrelated="{OTHER}"\n')
    git("add", ".")
    before = source.read_bytes(), (root / ".git/index").read_bytes()
    result = run_cli(root, "scan", "--provider", "rules", "--staged", "--format", format, "--output", "report.json")
    assert result.returncode == 1, result.stderr
    assert_private(result.stdout + result.stderr + (root / "report.json").read_text(encoding="utf-8"))
    assert before == (source.read_bytes(), (root / ".git/index").read_bytes())
    if format == "json":
        report = ScanResult.model_validate_json(result.stdout)
        assert report.validation_status == "passed"
        assert report.findings[0].assessment_source == "rules"


def test_default_scope_and_blocking_threshold(git_repo):
    root, git, write = git_repo
    write("a.py", f'password="{SECRET}"\n')
    git("add", ".")
    assert run_cli(root, "scan").returncode == 1
    write("codeshield.toml", 'blocking_severity="critical"\n')
    result = run_cli(root, "scan", "--format", "json")
    assert result.returncode == 0
    assert json.loads(result.stdout)["summary"] == {"total": 1, "blocking": 0}


def test_empty_scan_and_missing_git_history(git_repo):
    root, git, write = git_repo
    assert run_cli(root, "scan").returncode == 0
    result = run_cli(root, "scan", "--base-ref", "main", "--head-ref", "HEAD")
    assert result.returncode == 3
    assert "fetch the required history" in result.stderr


@pytest.mark.parametrize("provider", ["gemini"])
def test_provider_not_silently_used(git_repo, provider):
    root, git, write = git_repo
    result = run_cli(root, "scan", "--provider", provider)
    assert result.returncode == 2
    assert not result.stdout


def test_unmerged_index_fails_closed(git_repo):
    root, git, write = git_repo
    oid = git("hash-object", "-w", "--stdin", input=b"synthetic\n").strip()
    entries = b"100644 " + oid + b" 1\ta.py\n100644 " + oid + b" 2\ta.py\n"
    git("update-index", "--index-info", input=entries)
    with pytest.raises(ScanError, match="Unmerged"):
        scan(Config(), cwd=root)


def test_scanner_checks_index_stability(git_repo, monkeypatch):
    from codeshield.git_diff import Git
    root, git, write = git_repo
    original = Git.staged_metadata
    calls = 0

    def changed(self):
        nonlocal calls
        calls += 1
        return original(self) if calls == 1 else b"changed"

    monkeypatch.setattr(Git, "staged_metadata", changed)
    with pytest.raises(ScanError, match="Index changed"):
        scan(Config(), cwd=root)


def test_existing_report_and_git_metadata_are_protected(git_repo):
    root, git, write = git_repo
    destination = write("existing.json", "preserve")
    result = run_cli(root, "scan", "--output", "existing.json")
    assert result.returncode == 3
    assert destination.read_text() == "preserve"
    result = run_cli(root, "scan", "--output", ".git/new-report.json")
    assert result.returncode == 3
    assert not (root / ".git/new-report.json").exists()


def test_failure_does_not_write_report_or_leak(tmp_path):
    result = run_cli(tmp_path, "scan", "--output", "report.json")
    assert result.returncode == 3
    assert not (tmp_path / "report.json").exists()
    assert not result.stdout


@pytest.mark.parametrize("name,source", [
    ("a.py", 'API_KEY = (\n    "' + SECRET + '"\n)\n'),
    ("a.json", '{\n  "password":\n    "' + SECRET + '"\n}\n'),
    ("a.yaml", 'password:\n    "' + SECRET + '"\n'),
    ("a.py", 'password = """' + SECRET + '"""\n'),
])
def test_multiline_assignments_and_single_line_triple_literals(git_repo, name, source):
    root, git, write = git_repo
    write(name, source)
    git("add", ".")
    result = scan(Config(), cwd=root)
    assert len(result.findings) == 1
    assert_private(result.model_dump_json())


@pytest.mark.parametrize("source", [
    "password = settings.password\n", "const apiKey = runtimeKey;\n",
    "const password = getPassword();\n", "password = None\n",
])
def test_variable_references_are_not_literal_credentials(git_repo, source):
    root, git, write = git_repo
    write("a.ts" if source.startswith("const") else "a.py", source)
    git("add", ".")
    assert not scan(Config(), cwd=root).findings


def test_explicit_ignored_env_path_is_opted_in(git_repo):
    root, git, write = git_repo
    write(".gitignore", ".env\n")
    write(".env", f"API_KEY={SECRET}\n")
    result = scan(Config(), cwd=root, path=Path(".env"))
    assert result.summary.blocking == 1


def test_external_diff_and_textconv_are_disabled(git_repo):
    root, git, write = git_repo
    write(".gitattributes", "*.py diff=evil\n")
    write("a.py", f'password="{SECRET}"\n')
    git("config", "diff.external", "codeshield-nonexistent-external-program")
    git("config", "diff.evil.command", "codeshield-nonexistent-diff-program")
    git("config", "diff.evil.textconv", "codeshield-nonexistent-converter")
    git("add", ".")
    assert scan(Config(), cwd=root).summary.blocking == 1


def test_gitattributes_binary_flag_cannot_hide_text(git_repo):
    root, git, write = git_repo
    write(".gitattributes", "*.py -diff\n")
    write("a.py", f'password="{SECRET}"\n')
    git("add", ".")
    assert scan(Config(), cwd=root).summary.blocking == 1


def test_filename_and_surrounding_literals_cannot_leak_candidates(git_repo, caplog, capsys):
    root, git, write = git_repo
    write(SECRET.replace("!", "") + ".py", f'password="{SECRET.replace("!", "")}"; other="{OTHER}"\n')
    git("add", ".")
    report = scan(Config(), cwd=root).model_dump_json()
    assert SECRET.replace("!", "") not in report
    assert OTHER not in report
    captured = capsys.readouterr()
    assert not captured.out and not captured.err and not caplog.text


def test_generated_minified_file_is_skipped(git_repo):
    root, git, write = git_repo
    write("bundle.min.js", f'password="{SECRET}"')
    git("add", ".")
    result = scan(Config(), cwd=root)
    assert not result.findings
    assert result.skipped_files[0].reason == "generated_file"


@pytest.mark.parametrize("name,source", [
    ("a.YAML", "password: " + SECRET),
    (".ENV", "API_KEY=" + SECRET),
    ("a.PY", '# password="' + SECRET + '"'),
    ("a.TS", '// password="' + SECRET + '"'),
])
def test_extension_case_does_not_change_language_rules(git_repo, name, source):
    root, git, write = git_repo
    write(name, source)
    git("add", "-f", "--", name)
    result = scan(Config(), cwd=root)
    assert len(result.findings) == int(name in ("a.YAML", ".ENV"))


def test_worktree_unreadable_file_is_failure_not_skip(git_repo, monkeypatch):
    root, git, write = git_repo
    target = write("a.py", f'password="{SECRET}"')
    original = Path.stat

    def deny(self, *args, **kwargs):
        if self == target:
            raise PermissionError("RAW_PERMISSION_PAYLOAD")
        return original(self, *args, **kwargs)

    # Explicit selection is rejected before a false clean result can be generated.
    monkeypatch.setattr(Path, "stat", deny)
    with pytest.raises(ScanError, match="unreadable") as exc:
        scan(Config(), cwd=root, path=Path("a.py"))
    assert "RAW_PERMISSION_PAYLOAD" not in str(exc.value)


def test_missing_path_is_failure(git_repo):
    root, git, write = git_repo
    with pytest.raises(ScanError, match="missing"):
        scan(Config(), cwd=root, path=Path("missing.py"))
