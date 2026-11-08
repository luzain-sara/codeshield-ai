import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from codeshield.agent.providers import load_api_key
from codeshield.config import ConfigError

KEY = "SYNTHETIC_GEMINI_KEY_12345"


def test_environment_takes_precedence_without_opening_dotenv(tmp_path, monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", KEY)
    (tmp_path / ".env").write_bytes(b"\xff")
    assert load_api_key(tmp_path) == KEY


def test_dotenv_load_is_local_and_does_not_expand_or_modify_environment(tmp_path):
    pytest.importorskip("dotenv")
    (tmp_path / ".env").write_text(f'export GEMINI_API_KEY="{KEY}"\nUNRELATED_KEY=never-export-this\n', encoding="utf-8")
    assert load_api_key(tmp_path) == KEY
    assert "GEMINI_API_KEY" not in os.environ and "UNRELATED_KEY" not in os.environ


@pytest.mark.parametrize("text", [
    "GEMINI_API_KEY=", 'GEMINI_API_KEY="${OTHER_KEY}"', "GEMINI_API_KEY=invalid key",
    "UNRELATED_KEY=not-used", "GEMINI_API_KEY=" + "X" * 70000,
], ids=["empty", "interpolation", "whitespace", "missing-key", "oversized"])
def test_invalid_missing_or_oversized_dotenv_is_safe(tmp_path, text):
    pytest.importorskip("dotenv")
    (tmp_path / ".env").write_text(text, encoding="utf-8")
    with pytest.raises(ConfigError) as exc:
        load_api_key(tmp_path)
    assert "OTHER_KEY" not in str(exc.value) and text not in str(exc.value)


def test_missing_dotenv_safe_error(tmp_path):
    with pytest.raises(ConfigError, match="credentials|extra"):
        load_api_key(tmp_path)


def test_non_regular_credential_path_is_rejected_before_open(tmp_path, monkeypatch):
    pytest.importorskip("dotenv")
    target = tmp_path / ".env"
    original = Path.stat

    def fake_stat(self, *args, **kwargs):
        return SimpleNamespace(st_mode=stat.S_IFIFO) if self == target else original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", fake_stat)
    monkeypatch.setattr(os, "open", lambda *args, **kwargs: pytest.fail("A pipe must not be opened"))
    with pytest.raises(ConfigError, match="regular file"):
        load_api_key(tmp_path)
