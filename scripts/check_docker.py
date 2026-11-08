"""CI smoke check: read-only mounts, network disabled, synthetic credentials only."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile


def check(image):
    with tempfile.TemporaryDirectory(prefix="codeshield-container-") as directory:
        root = Path(directory)
        root.chmod(0o755)

        def git(*args):
            return subprocess.run(["git", "-C", directory, *args], check=True, capture_output=True)

        git("init", "-b", "main")
        source = root / "app.py"
        source.write_text("answer=1\n", encoding="utf-8")
        source.chmod(0o644)
        git("add", ".")

        def run(*args):
            result = subprocess.run(["docker", "run", "--rm", "--network=none", "--mount",
                                     f"type=bind,src={directory},dst=/repo,readonly", image, *args],
                                    capture_output=True, text=True, timeout=120)
            assert sentinel not in result.stdout + result.stderr, "Container output leaked fixture value"
            return result

        sentinel = "SyntheticContainerSentinel9_wQ!"
        assert run("--staged", "--format", "json").returncode == 0, "Clean staged scan failed"
        source.write_text(f'password="{sentinel}"\n', encoding="utf-8")  # codeshield: test-fixture
        git("add", ".")
        before = source.read_bytes(), (root / ".git/index").read_bytes()
        result = run("--staged", "--format", "json")
        assert result.returncode == 1, "Exposed fixture did not block"
        assert json.loads(result.stdout)["summary"]["blocking"] == 1
        assert before == (source.read_bytes(), (root / ".git/index").read_bytes()), "Scan modified repository"
        assert run("--base-ref", "unavailable", "--head-ref", "HEAD").returncode == 3
        assert run("--provider", "gemini").returncode == 2
        assert run("fix").returncode == 2
    print("Docker checks passed: clean, blocking, redaction, read-only, errors, offline-only.")


if __name__ == "__main__":
    check(sys.argv[1] if len(sys.argv) > 1 else "codeshield-ci")
