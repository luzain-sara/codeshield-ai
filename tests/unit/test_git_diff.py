import subprocess
import sys
import time

import pytest

from codeshield.config import Config
from codeshield.errors import ScanError
from codeshield.git_diff import Change, Git, parse_added_lines, parse_changes, staged_additions, valid_path


def test_added_lines_headers_deletions_and_no_newline():
    patch = b'diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -2,2 +2,3 @@\n-old\n+++literal\n+new\n same\n\\ No newline at end of file\n'
    assert parse_added_lines(patch) == {2: b"++literal", 3: b"new"}


@pytest.mark.parametrize("patch", [
    b"@@ -1 +1 @@\n+only\n", b"@@ invalid\n", b"@@ -0,0 +1,2 @@\n+one\n",
    b"diff --git a/a b/a\ndiff --git a/b b/b\n",
    b"@@ -0,0 +1 @@\n+a\n@@ -0,0 +1 @@\n+b\n",
])
def test_malformed_diff_fails_closed(patch):
    with pytest.raises(ScanError):
        parse_added_lines(patch)


def test_nul_metadata_supports_spaces_unicode_and_rename():
    raw = (b":100644 100644 " + b"a" * 40 + b" " + b"b" * 40 +
           b" R090\0old name.py\0" + "new café.py".encode() + b"\0")
    result = parse_changes(raw)
    assert result[0].old_path == "old name.py"
    assert result[0].path == "new café.py"


@pytest.mark.parametrize("raw", [b"garbage\0", b":100644\0x\0", b"missing-nul"])
def test_malformed_metadata(raw):
    with pytest.raises(ScanError):
        parse_changes(raw)


@pytest.mark.parametrize("source,limit,error", [
    ("print('x'*10000)", 64, "exceeds"),
    ("import time; time.sleep(3)", 64, "timed out"),
    ("import sys; print('RAW_ERROR',file=sys.stderr); sys.exit(1)", 64, "failed"),
])
def test_git_reader_bounds_timeout_and_suppresses_stderr(monkeypatch, tmp_path, source, limit, error):
    original = subprocess.Popen
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs:
                        original([sys.executable, "-c", source], **kwargs))
    git = Git.__new__(Git)
    git.directory = tmp_path
    git.config = Config(git_timeout_seconds=1)
    git.deadline = time.monotonic() + 10
    git.executable = "git"
    with pytest.raises(ScanError, match=error) as exc:
        git.run("anything", limit=limit)
    assert "RAW_ERROR" not in str(exc.value)


@pytest.mark.parametrize("path", ["../escape.py", "/absolute.py", "C:/drive.py", "dir\\escape.py"])
def test_unsafe_paths_fail_closed(path):
    with pytest.raises(ScanError, match="Unsafe"):
        valid_path(path)


def test_added_bytes_must_match_selected_blob():
    class FakeGit:
        config = Config()

        def run(self, *args, **kwargs):
            return b"@@ -0,0 +1 @@\n+stale snapshot\n"

    change = Change("000000", "100644", "0" * 40, "a" * 40, "a.py", "a.py")
    with pytest.raises(ScanError, match="Index changed"):
        staged_additions(FakeGit(), change, b"different snapshot\n")
