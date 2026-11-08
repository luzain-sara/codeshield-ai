"""Release archive policy and initializer safety, using synthetic bytes only."""
from pathlib import Path
import runpy

import pytest

ROOT = Path(__file__).resolve().parents[2]
INSPECT = runpy.run_path(str(ROOT / "scripts/check_install.py"))["inspect_members"]


@pytest.mark.parametrize("name", [".env", "project/.env.local", "project/.aws/credentials", "project/.venv/a.py", "private.key", "../escape.py", "project\\.env", "/absolute.py"])
def test_archive_policy_refuses_sensitive_and_escaping_members(name):
    with pytest.raises(ValueError):
        INSPECT([(name, b"synthetic")])


def test_archive_policy_accepts_public_examples_but_not_canary_bytes():
    INSPECT([("project/.env.example", b"API_KEY=\n"), ("project/codeshield/cli.py", b"public code")])
    with pytest.raises(ValueError):
        INSPECT([("project/public.py", b"SyntheticPackaging" + b"Canary_74_not_a_credential")])


def test_initialize_never_reads_existing_files_or_env(git_repo, monkeypatch):
    from codeshield.initialization import initialize
    root, git, write = git_repo
    write(".env", "PRIVATE_TEST_INIT_CANARY")
    write("codeshield.toml", 'provider="rules"\n')
    original = Path.open

    def guard(self, *args, **kwargs):
        if self.name in {".env", "codeshield.toml"}:
            pytest.fail("Initialization may not read existing configuration or credentials")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guard)
    assert "existing files preserved" in initialize(root)


def test_initialize_write_failure_preserves_existing_files(git_repo, monkeypatch):
    import codeshield.initialization as initialization
    root, git, write = git_repo
    existing = write(".env.example", "UNRELATED=\n")
    before = existing.read_bytes()

    def fail(*args):
        raise OSError("SYNTHETIC_PRIVATE_ERROR")

    monkeypatch.setattr(initialization, "write_report", fail)
    with pytest.raises(OSError):
        initialization.initialize(root)
    assert existing.read_bytes() == before
