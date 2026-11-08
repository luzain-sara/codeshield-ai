from pathlib import Path

import pytest

from codeshield.config import ConfigError, load_config
from codeshield.models import Provider


def test_defaults_are_offline(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert load_config().provider == Provider.MOCK
    assert not list(tmp_path.iterdir())


def test_explicit_missing_config_is_an_error(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "missing.toml")


def test_load_config(tmp_path):
    path = tmp_path / "codeshield.toml"
    path.write_text('provider = "mock"\nmax_file_bytes = 512\n', encoding="utf-8")
    config = load_config(path)
    assert config.provider == Provider.MOCK
    assert config.max_file_bytes == 512


@pytest.mark.parametrize("text", [
    'provider = "unknown"',
    'api_key = "FAKE_CONFIG_SENTINEL"',
    'max_file_bytes = 0',
    'max_file_bytes = "512"',
    'max_file_bytes = true',
    'max_scan_bytes = 1',
    'git_timeout_seconds = 0',
    'exclude_dirs = [1]',
    'entropy_threshold = 9',
    'entropy_min_length = 0',
    'scan_timeout_seconds = 0',
    'max_files = 0',
    'max_findings = 0',
    'provider = "FAKE_CONFIG_SENTINEL',
])
def test_invalid_config_is_rejected_without_echoing_values(tmp_path, text):
    path = tmp_path / "config.toml"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ConfigError) as exc:
        load_config(path)
    assert "FAKE_CONFIG_SENTINEL" not in str(exc.value)


def test_directory_config_is_safe_error(tmp_path):
    with pytest.raises(ConfigError, match="unreadable or invalid"):
        load_config(Path(tmp_path))
