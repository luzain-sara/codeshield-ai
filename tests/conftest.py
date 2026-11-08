"""Synthetic repositories only; never stage or commit the actual project."""

import subprocess
import socket

import pytest


@pytest.fixture(autouse=True)
def offline_provider_environment(monkeypatch):
    for name in ("GEMINI_API_KEY", "GOOGLE_API_KEY", "CI", "GITHUB_ACTIONS", "GITLAB_CI", "TF_BUILD"):
        monkeypatch.delenv(name, raising=False)

    def deny_network(*args, **kwargs):
        raise AssertionError("Real network access is forbidden in tests.")

    monkeypatch.setattr(socket.socket, "connect", deny_network)


@pytest.fixture
def git_repo(tmp_path):
    def git(*args, input=None):
        return subprocess.run(["git", "-c", "core.autocrlf=false", "-C", str(tmp_path), *args],
                              input=input, capture_output=True, check=True).stdout

    git("init", "-b", "main")
    git("config", "user.name", "Synthetic Test")
    git("config", "user.email", "synthetic@example.invalid")

    def write(name, content):
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))
        return path

    return tmp_path, git, write
