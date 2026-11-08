"""All writes and Git commits below are confined to synthetic disposable fixtures."""

import json
import os
import stat
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from codeshield.agent.workflow import plan_fix
from codeshield.cli import main
from codeshield.config import Config, ConfigError
from codeshield.errors import ScanError
from codeshield.remediation.patcher import apply_plan
from codeshield.remediation.planner import Edit
from codeshield.scanner import scan

SECRET = "SyntheticRemediationCredential_42"  # codeshield: test-fixture
OTHER = "SyntheticUnrelatedCredential_73"  # codeshield: test-fixture


def prepare(git_repo, source=None, name="app.py", package=None):
    root, git, write = git_repo
    write(name, source or f'API_KEY = "{SECRET}"\n')
    if package is not None:
        # Declare actual server startup intent; a Node tooling engine alone is not proof.
        if package.get("engines"):
            package = dict(package) | {"scripts": {"start": "node " + name}}
        write("package.json", json.dumps(package))
    git("add", ".")
    result = scan(Config(), cwd=root)
    found = [f for f in result.findings if f.path == name]
    assert found, "Synthetic finding must exist before exercising remediation"
    return root, git, write, found[0].finding_id


def state(root):
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob("*") if p.is_file() and ".git" not in p.relative_to(root).parts}


def test_python_dry_run_is_redacted_and_never_writes(git_repo):
    root, git, write, finding_id = prepare(git_repo)
    before, index = state(root), (root / ".git/index").read_bytes()
    plan = plan_fix(finding_id, Config(), cwd=root, store_secret=True)
    assert SECRET not in plan.preview() and SECRET not in repr(plan)
    assert '<REDACTED_SECRET>' in plan.preview()
    assert 'os.environ["API_KEY"]' in plan.preview()
    assert plan.states[-2:] == ("validate_fix", "await_approval")
    assert before == state(root) and index == (root / ".git/index").read_bytes()


def test_python_apply_requires_restage_preserves_index_and_uses_blank_example(git_repo):
    root, git, write, finding_id = prepare(git_repo)
    plan = plan_fix(finding_id, Config(), cwd=root)
    before_index = (root / ".git/index").read_bytes()
    output = apply_plan(plan, approved=True)
    assert "fix_applied_to_worktree_requires_restage" in output and SECRET not in output
    assert (root / "app.py").read_text() == 'import os\nAPI_KEY = os.environ["API_KEY"]\n'
    assert (root / ".env.example").read_text() == "API_KEY=\n"
    assert not (root / ".env").exists()
    git("check-ignore", "-q", ".env")
    assert before_index == (root / ".git/index").read_bytes()
    assert any(f.finding_id == finding_id for f in scan(Config(), cwd=root).findings)
    git("add", "app.py")
    assert not scan(Config(), cwd=root).findings


def test_explicit_store_secret_private_env_preserves_existing_values(git_repo):
    root, git, write = git_repo
    write(".gitignore", "/.env\n")
    write(".env", "UNRELATED_KEY='" + OTHER + "'\n")
    root, git, write, finding_id = prepare(git_repo)
    original = (root / ".env").read_bytes()
    plan = plan_fix(finding_id, Config(), cwd=root, store_secret=True)
    assert SECRET not in plan.preview() and OTHER not in plan.preview()
    apply_plan(plan, approved=True)
    assert (root / ".env").read_bytes() == original + f"API_KEY='{SECRET}'\n".encode()
    assert SECRET not in (root / ".env.example").read_text()
    assert not git("ls-files", "--", ".env")
    if os.name != "nt":
        assert stat.S_IMODE((root / ".env").stat().st_mode) == 0o600
    else:
        from codeshield.remediation.security import read_acl
        assert int.from_bytes(read_acl(root / ".env")[2:4], "little") & 0x1000


@pytest.mark.parametrize("name,package", [
    ("server.js", {"engines": {"node": ">=20"}}),
    ("server.cjs", {"dependencies": {"express": "synthetic"}}),
    ("server.mjs", {"type": "module", "engines": {"node": ">=20"}}),
])
def test_node_server_literal_fixed_and_revalidated(git_repo, name, package):
    root, git, write, finding_id = prepare(git_repo, f'const apiKey = "{SECRET}";\n', name, package)
    plan = plan_fix(finding_id, Config(), cwd=root)
    assert "process.env.API_KEY" in plan.preview()
    apply_plan(plan, approved=True)
    assert (root / name).read_text() == "const apiKey = process.env.API_KEY;\n"
    assert scan(Config(), cwd=root).summary.blocking == 1


@pytest.mark.parametrize("source", [
    f'"""Module documentation."""\nfrom __future__ import annotations\nAPI_KEY = "{SECRET}"\n',
    f'import os\nAPI_KEY: str = "{SECRET}"\n',
    f'#!/usr/bin/env python\n# coding: utf-8\nAPI_KEY = "{SECRET}"\n',
])
def test_import_placement_and_existing_os_import(git_repo, source):
    root, git, write, finding_id = prepare(git_repo, source)
    apply_plan(plan_fix(finding_id, Config(), cwd=root), approved=True)
    data = (root / "app.py").read_bytes()
    assert data.count(b"import os") == 1
    compile(data, "<synthetic>", "exec")


def test_crlf_bom_and_unicode_path_are_preserved(git_repo):
    root, git, write, finding_id = prepare(git_repo, b'\xef\xbb\xbf' + f'API_KEY = "{SECRET}"\r\n'.encode(), "café app.py")
    apply_plan(plan_fix(finding_id, Config(), cwd=root), approved=True)
    assert (root / "café app.py").read_bytes() == b'\xef\xbb\xbfimport os\r\nAPI_KEY = os.environ["API_KEY"]\r\n'


@pytest.mark.parametrize("source", [
    'def f():\n    API_KEY = "' + SECRET + '"\n',
    'class Settings:\n    API_KEY = "' + SECRET + '"\n',
    'API_KEY = """' + SECRET + '"""\n',
    'API_KEY = "' + SECRET + '" + suffix\n',
    'API_KEY = f"ghp_' + 'Z' * 36 + '"\n',
    'API_KEY = "' + SECRET + '"; x=1\n',
    'API_KEY = "' + SECRET + '"\nAPI_KEY = "another-value"\n',
    'os = object()\nAPI_KEY = "' + SECRET + '"\n',
    'import os\nos.environ = {}\nAPI_KEY = "' + SECRET + '"\n',
    'exec("x=1")\nAPI_KEY = "' + SECRET + '"\n',
])
def test_ambiguous_python_is_refused_without_changes(git_repo, source):
    root, git, write, finding_id = prepare(git_repo, source)
    before = state(root)
    with pytest.raises(ScanError):
        plan_fix(finding_id, Config(), cwd=root)
    assert state(root) == before


@pytest.mark.parametrize("source", [
    'function f(){ const apiKey = "' + SECRET + '"; }\n',
    'const config = {apiKey: "' + SECRET + '"};\n',
    'const apiKey = `' + SECRET + '`;\n',
    'const apiKey = "' + SECRET + '" + suffix;\n',
    'const apiKey = "' + SECRET + '", other = 1;\n',
    'const process = {};\nconst apiKey = "' + SECRET + '";\n',
    'const apiKey = "' + SECRET + '"; console.log(1);\n',
    'const apiKey = "' + SECRET + '";\napiKey="other";\n',
])
def test_ambiguous_node_is_refused(git_repo, source):
    root, git, write, finding_id = prepare(git_repo, source, "server.js", {"engines": {"node": ">=20"}})
    before = state(root)
    with pytest.raises(ScanError):
        plan_fix(finding_id, Config(), cwd=root)
    assert state(root) == before


@pytest.mark.parametrize("name,package,extra", [
    ("client/a.py", None, None),
    ("app.py", {"devDependencies": {"vite": "synthetic"}}, None),
    ("server.js", {"dependencies": {"next": "synthetic"}, "engines": {"node": "20"}}, None),
    ("server.js", {}, None),
    ("server.ts", {"engines": {"node": "20"}}, None),
    ("app.py", None, "vite.config.ts"),
])
def test_client_unknown_and_unsupported_runtimes_are_refused(git_repo, name, package, extra):
    root, git, write = git_repo
    if extra:
        write(extra, "export default {};\n")
    source = f'API_KEY = "{SECRET}"\n' if name.endswith(".py") else f'const apiKey = "{SECRET}";\n'
    root, git, write, finding_id = prepare(git_repo, source, name, package)
    with pytest.raises(ScanError):
        plan_fix(finding_id, Config(), cwd=root)


def test_unstaged_source_and_framework_metadata_are_protected(git_repo):
    root, git, write, finding_id = prepare(git_repo, f'const apiKey = "{SECRET}";\n', "server.js", {"engines": {"node": "20"}})
    write("server.js", f'const apiKey = "{SECRET}";\n// unsaved local change\n')
    with pytest.raises(ScanError, match="unstaged"):
        plan_fix(finding_id, Config(), cwd=root)
    write("server.js", f'const apiKey = "{SECRET}";\n')
    write("package.json", json.dumps({"dependencies": {"react": "synthetic"}}))
    with pytest.raises(ScanError, match="unstaged"):
        plan_fix(finding_id, Config(), cwd=root)


def test_changes_after_preview_are_not_overwritten(git_repo):
    root, git, write, finding_id = prepare(git_repo)
    plan = plan_fix(finding_id, Config(), cwd=root)
    write("app.py", f'API_KEY = "{OTHER}"\n')
    with pytest.raises(ScanError, match="stale"):
        apply_plan(plan, approved=True)
    assert OTHER in (root / "app.py").read_text()
    assert not (root / ".env.example").exists()


def test_manifest_added_after_preview_invalidates_plan(git_repo):
    root, git, write, finding_id = prepare(git_repo)
    plan = plan_fix(finding_id, Config(), cwd=root)
    write("vite.config.js", "export default {};\n")
    with pytest.raises(ScanError, match="stale"):
        apply_plan(plan, approved=True)


@pytest.mark.parametrize("approved", [False, None, "yes", 1])
def test_no_approval_means_no_writes(git_repo, approved):
    root, git, write, finding_id = prepare(git_repo)
    plan = plan_fix(finding_id, Config(), cwd=root)
    before = state(root)
    with pytest.raises(ScanError, match="approval"):
        apply_plan(plan, approved=approved)
    assert before == state(root)


@pytest.mark.parametrize("env_name", ["VITE_SECRET", "NEXT_PUBLIC_KEY", "NODE_OPTIONS", "PYTHONPATH", "bad-name", SECRET])
def test_unsafe_destination_names_rejected(git_repo, env_name):
    root, git, write, finding_id = prepare(git_repo)
    with pytest.raises(ScanError):
        plan_fix(finding_id, Config(), cwd=root, env_name=env_name)


def test_existing_env_key_is_never_overwritten(git_repo):
    root, git, write, finding_id = prepare(git_repo)
    write(".env", f"API_KEY='{OTHER}'\n")
    with pytest.raises(ScanError, match="already exists"):
        plan_fix(finding_id, Config(), cwd=root, store_secret=True)
    assert OTHER in (root / ".env").read_text()


def test_tracked_env_is_refused(git_repo):
    root, git, write, finding_id = prepare(git_repo)
    write(".env", "OTHER=\n")
    git("add", "-f", ".env")
    with pytest.raises(ScanError, match="Tracked .env"):
        plan_fix(finding_id, Config(), cwd=root, store_secret=True)


def test_validation_failure_rolls_back_all_files_and_permissions(git_repo, monkeypatch):
    root, git, write, finding_id = prepare(git_repo)
    plan = plan_fix(finding_id, Config(), cwd=root, store_secret=True)
    before, index = state(root), (root / ".git/index").read_bytes()

    def fail(*args):
        raise RuntimeError(SECRET + OTHER)

    monkeypatch.setattr("codeshield.remediation.patcher.validate_result", fail)
    with pytest.raises(ScanError, match="rolled back") as exc:
        apply_plan(plan, approved=True)
    assert SECRET not in str(exc.value) and OTHER not in str(exc.value)
    assert state(root) == before and index == (root / ".git/index").read_bytes()


def test_failure_after_atomic_replace_is_also_rolled_back(git_repo, monkeypatch):
    from codeshield.remediation import patcher
    root, git, write, finding_id = prepare(git_repo)
    plan = plan_fix(finding_id, Config(), cwd=root, store_secret=True)
    before = state(root)
    original = patcher.atomic_write
    failed = False

    def replace_then_fail(root, snapshot, data, **kwargs):
        nonlocal failed
        original(root, snapshot, data, **kwargs)
        if snapshot.relative == "app.py" and not failed:
            failed = True
            raise OSError(SECRET)

    monkeypatch.setattr(patcher, "atomic_write", replace_then_fail)
    with pytest.raises(ScanError, match="rolled back"):
        apply_plan(plan, approved=True)
    assert state(root) == before


def test_tampered_plan_cannot_bypass_deterministic_validation(git_repo):
    root, git, write, finding_id = prepare(git_repo)
    plan = plan_fix(finding_id, Config(), cwd=root)
    malicious = replace(plan, edits=(*plan.edits[:-1], Edit(plan.edits[-1].before, b"print('unexpected')\n")))
    with pytest.raises(ScanError, match="reviewed plan"):
        apply_plan(malicious, approved=True)
    assert SECRET in (root / "app.py").read_text()


def test_cli_explain_preview_apply_and_restage_exit_codes(git_repo, monkeypatch, capsys):
    root, git, write, finding_id = prepare(git_repo)
    monkeypatch.chdir(root)
    assert main(["explain", finding_id]) == 0
    assert main(["fix", finding_id, "--dry-run"]) == 0
    assert main(["fix", finding_id, "--apply", "--yes"]) == 1
    output = capsys.readouterr()
    assert SECRET not in output.out + output.err
    assert "requires_restage" in output.out
    git("add", "app.py")
    assert main(["scan", "--staged"]) == 0


def test_fix_never_initiates_gemini_or_reads_provider_credentials(git_repo, monkeypatch):
    root, git, write, finding_id = prepare(git_repo)
    monkeypatch.setattr("codeshield.agent.providers.load_api_key", lambda *args: pytest.fail("No credentials may be read"))
    with pytest.raises(ConfigError, match="offline deterministic"):
        plan_fix(finding_id, Config(provider="gemini"), cwd=root)
    assert plan_fix(finding_id, Config(), cwd=root)


def test_readonly_and_hardlinked_targets_are_refused(git_repo):
    root, git, write, finding_id = prepare(git_repo)
    target = root / "app.py"
    target.chmod(0o444)
    try:
        with pytest.raises(ScanError, match="Read-only"):
            plan_fix(finding_id, Config(), cwd=root)
    finally:
        target.chmod(0o644)
    os.link(target, root / "another.py")
    with pytest.raises(ScanError, match="hard link"):
        plan_fix(finding_id, Config(), cwd=root)


def test_negated_ignore_rules_are_replaced_by_explicit_protection(git_repo):
    root, git, write = git_repo
    write(".gitignore", ".env\n!.env\n.codeshield/\n!.codeshield/\n")
    root, git, write, finding_id = prepare(git_repo)
    apply_plan(plan_fix(finding_id, Config(), cwd=root, store_secret=True), approved=True)
    git("check-ignore", "-q", ".env")
    git("check-ignore", "-q", ".codeshield/")
    assert SECRET not in git("ls-files", "-s").decode()


def test_index_change_after_preview_prevents_apply(git_repo):
    root, git, write, finding_id = prepare(git_repo)
    plan = plan_fix(finding_id, Config(), cwd=root)
    write("other.py", "answer = 42\n")
    git("add", "other.py")
    with pytest.raises(ScanError, match="Index or HEAD"):
        apply_plan(plan, approved=True)
    assert not (root / ".env.example").exists()


@pytest.mark.parametrize("suffix,source,package", [
    (".py", 'open("unwanted.txt", "w").write("never-execute")\nAPI_KEY="' + SECRET + '"\n', None),
    (".js", 'require("fs").writeFileSync("unwanted.txt", "never-execute");\nconst apiKey="' + SECRET + '";\n', {"engines": {"node": "20"}}),
])
def test_validation_never_executes_application_code(git_repo, suffix, source, package, monkeypatch):
    root, git, write, finding_id = prepare(git_repo, source, "app" + suffix, package)
    monkeypatch.setenv("NODE_OPTIONS", "--require ./untrusted-loader.js")
    apply_plan(plan_fix(finding_id, Config(), cwd=root), approved=True)
    assert not (root / "unwanted.txt").exists()


def test_renamed_staged_file_is_refused(git_repo):
    root, git, write = git_repo
    write("old.py", "answer=1\n" * 30)
    git("add", ".")
    git("commit", "-m", "synthetic baseline")
    git("mv", "old.py", "new.py")
    write("new.py", "answer=1\n" * 30 + f'API_KEY="{SECRET}"\n')
    git("add", ".")
    finding_id = scan(Config(), cwd=root).findings[0].finding_id
    with pytest.raises(ScanError, match="Renames"):
        plan_fix(finding_id, Config(), cwd=root)


def test_environment_injection_and_invalid_dotenv_are_refused(git_repo):
    root, git, write, finding_id = prepare(git_repo)
    write(".env", "OTHER='unterminated\n")
    with pytest.raises(ScanError, match="dotenv syntax"):
        plan_fix(finding_id, Config(), cwd=root, store_secret=True)


def test_ci_apply_and_planning_are_disabled(git_repo, monkeypatch):
    root, git, write, finding_id = prepare(git_repo)
    plan = plan_fix(finding_id, Config(), cwd=root)
    before = state(root)
    monkeypatch.setenv("CI", "true")
    with pytest.raises(ScanError, match="CI"):
        apply_plan(plan, approved=True)
    with pytest.raises(ScanError, match="CI"):
        plan_fix(finding_id, Config(), cwd=root)
    assert state(root) == before


def test_interactive_decline_does_not_write(git_repo, monkeypatch, capsys):
    root, git, write, finding_id = prepare(git_repo)
    monkeypatch.chdir(root)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda *args: "no")
    before = state(root)
    assert main(["fix", finding_id, "--apply", "--store-secret"]) == 0
    output = capsys.readouterr()
    assert "declined" in output.out and SECRET not in output.out + output.err
    assert before == state(root)


def test_missing_node_validator_refuses_before_writing(git_repo, monkeypatch):
    root, git, write, finding_id = prepare(git_repo, f'const apiKey="{SECRET}";\n', "app.js", {"engines": {"node": "20"}})
    from codeshield.remediation import validator
    original = validator.shutil.which
    monkeypatch.setattr(validator.shutil, "which", lambda name: None if name == "node" else original(name))
    with pytest.raises(ScanError, match="Node.js executable"):
        plan_fix(finding_id, Config(), cwd=root)


def test_git_normalized_crlf_is_preserved_in_the_working_tree(git_repo):
    root, git, write = git_repo
    write("app.py", f'API_KEY = "{SECRET}"\r\n'.encode())
    git("config", "core.autocrlf", "true")
    subprocess.run(["git", "-c", "core.autocrlf=true", "-C", str(root), "add", "app.py"], check=True, capture_output=True)
    assert b"\r\n" not in git("show", ":app.py")
    finding_id = scan(Config(), cwd=root).findings[0].finding_id
    apply_plan(plan_fix(finding_id, Config(), cwd=root), approved=True)
    assert (root / "app.py").read_bytes() == b'import os\r\nAPI_KEY = os.environ["API_KEY"]\r\n'


def test_rollback_restores_existing_environment_bytes_mode_and_acl(git_repo, monkeypatch):
    from codeshield.remediation.security import read_acl
    root, git, write = git_repo
    write(".gitignore", ".env\n.codeshield/\n")
    write(".env", f"UNRELATED_KEY='{OTHER}'\n")
    root, git, write, finding_id = prepare(git_repo)
    env = root / ".env"
    before = env.read_bytes(), stat.S_IMODE(env.stat().st_mode), read_acl(env)
    plan = plan_fix(finding_id, Config(), cwd=root, store_secret=True)
    monkeypatch.setattr("codeshield.remediation.patcher.validate_result", lambda *args: (_ for _ in ()).throw(RuntimeError("synthetic validation failure")))
    with pytest.raises(ScanError, match="rolled back"):
        apply_plan(plan, approved=True)
    assert before == (env.read_bytes(), stat.S_IMODE(env.stat().st_mode), read_acl(env))


def test_incomplete_env_rollback_keeps_gitignore_protection(git_repo, monkeypatch):
    from codeshield.remediation import patcher
    root, git, write = git_repo
    write(".env", f"UNRELATED_KEY='{OTHER}'\n")
    write(".gitignore", ".env\n")
    root, git, write, finding_id = prepare(git_repo)
    plan = plan_fix(finding_id, Config(), cwd=root, store_secret=True)
    original = patcher.atomic_write

    def fail_restore(root, snapshot, data, **kwargs):
        if snapshot.relative == ".env" and data == f"UNRELATED_KEY='{OTHER}'\n".encode():
            raise OSError("synthetic rollback failure")
        return original(root, snapshot, data, **kwargs)

    monkeypatch.setattr(patcher, "atomic_write", fail_restore)
    monkeypatch.setattr(patcher, "validate_result", lambda *args: (_ for _ in ()).throw(RuntimeError("synthetic validation failure")))
    with pytest.raises(ScanError, match="incomplete") as exc:
        apply_plan(plan, approved=True)
    assert SECRET not in str(exc.value) and OTHER not in str(exc.value)
    git("check-ignore", "-q", ".env")
    assert not git("ls-files", "--", ".env")


def test_nested_yaml_secret_is_detected_but_not_auto_fixed(git_repo):
    root, git, write, finding_id = prepare(git_repo, f'credentials:\n  password: "{SECRET}"\n', "config.yaml")
    assert scan(Config(), cwd=root).findings[0].line == 2
    with pytest.raises(ScanError, match="Unsupported"):
        plan_fix(finding_id, Config(), cwd=root)


@pytest.mark.parametrize("metadata", [
    {"engines": {"node": ">=20"}},
    {"scripts": {"start": "node app.js"}, "peerDependencies": {"react": "synthetic"}},
    {"scripts": {"start": "node app.js"}, "optionalDependencies": {"vite": "synthetic"}},
    {"scripts": {"start": "node app.js"}, "exports": {"browser": "./app.js"}},
    {"scripts": {"start": "node app.js", "build": "esbuild app.js"}},
])
def test_node_tooling_and_hidden_browser_metadata_are_not_server_proof(git_repo, metadata):
    root, git, write, finding_id = prepare(git_repo, f'const apiKey="{SECRET}";\n', "app.js", {"scripts": {"start": "node app.js"}})
    write("package.json", json.dumps(metadata))
    git("add", "package.json")
    with pytest.raises(ScanError):
        plan_fix(finding_id, Config(), cwd=root)


@pytest.mark.parametrize("name,header", [
    ("generated/app.py", ""), ("__generated__/app.py", ""), ("app.py", "# @generated: do not edit\n"),
])
def test_generated_sources_are_not_remediated(git_repo, name, header):
    root, git, write, finding_id = prepare(git_repo, header + f'API_KEY="{SECRET}"\n', name)
    before = state(root)
    with pytest.raises(ScanError, match="generated|Generated"):
        plan_fix(finding_id, Config(), cwd=root)
    assert state(root) == before


def test_encrypted_file_attributes_are_refused(git_repo, monkeypatch):
    from types import SimpleNamespace
    root, git, write, finding_id = prepare(git_repo)
    target = root / "app.py"
    original = Path.stat

    def encrypted(self, *args, **kwargs):
        result = original(self, *args, **kwargs)
        if self == target:
            return SimpleNamespace(st_mode=result.st_mode, st_nlink=result.st_nlink,
                                   st_file_attributes=0x4000)
        return result

    monkeypatch.setattr(Path, "stat", encrypted)
    with pytest.raises(ScanError, match="Encrypted"):
        plan_fix(finding_id, Config(), cwd=root)
