"""Build, inspect and install a clean source copy. No repository Git writes or model calls."""
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tarfile
import tempfile
import venv
import zipfile

SENTINEL = b"SyntheticPackaging" + b"Canary_74_not_a_credential"


def inspect_members(members):
    for name, data in members:
        path = PurePosixPath(name)
        if (path.is_absolute() or ".." in path.parts or "\\" in name
                or any(part in {".git", ".venv", ".aws", ".codeshield", "__pycache__"} for part in path.parts)
                or path.name == ".env" or (path.name.startswith(".env.") and path.name != ".env.example")
                or path.suffix in {".pem", ".key", ".pyc"} or SENTINEL in data):
            raise ValueError("Sensitive or generated content entered a distribution.")


def check():
    project = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="codeshield-install-") as directory:
        root = Path(directory)
        source = root / "source"
        source.mkdir()
        # Explicit source allowlist: the developer's .env, index and caches are never copied.
        for name in ("pyproject.toml", "MANIFEST.in", "README.md", "LICENSE", "CHANGELOG.md", "SECURITY.md", "CONTRIBUTING.md",
                     "requirements.lock", "requirements-dev.lock", "codeshield.toml", ".env.example"):
            shutil.copyfile(project / name, source / name)
        for name in ("codeshield", "tests", "docs", "scripts", "examples"):
            for path in (project / name).rglob("*"):
                if path.is_file() and (path.suffix in {".py", ".md"} or path.name in {".env.example", ".gitignore"}):
                    target = source / path.relative_to(project)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(path, target)
        for name in (".env", ".env.private", ".aws/credentials", ".venv/private.py", ".codeshield/private.py", "private.key"):
            path = source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(SENTINEL)
        environment = root / "environment"
        venv.create(environment, with_pip=True)
        python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        env = os.environ.copy()
        env.update(CI="true", CODESHIELD_AUTOMATED="1", GEMINI_API_KEY="", GOOGLE_API_KEY="")

        def run(args, cwd=root):
            result = subprocess.run(args, cwd=cwd, env=env, input="", capture_output=True, text=True, timeout=300)
            if result.returncode:
                raise ValueError("Installation check failed; captured output withheld for privacy.")

        run([str(python), "-m", "pip", "install", "--require-hashes", "--only-binary=:all:", "-r", str(source / "requirements.lock")])
        print("Fresh hash-locked runtime dependencies installed.", flush=True)
        artifacts = root / "artifacts"
        artifacts.mkdir()
        run([str(python), "-I", "-c", "import sys; from setuptools.build_meta import build_sdist; build_sdist(sys.argv[1])", str(artifacts)], cwd=source)
        archive, = artifacts.glob("*.tar.gz")
        with tarfile.open(archive) as stream:
            if any(member.issym() or member.islnk() for member in stream.getmembers()):
                raise ValueError("Distribution links require manual review.")
            inspect_members((member.name, stream.extractfile(member).read()) for member in stream.getmembers() if member.isfile())
            names = {PurePosixPath(member.name).name for member in stream.getmembers()}
            if not {"LICENSE", "README.md", "pyproject.toml", "requirements.lock"} <= names:
                raise ValueError("Source distribution is incomplete.")
        # Build the wheel from the inspected sdist, proving it contains the build inputs.
        run([str(python), "-m", "pip", "wheel", "--no-build-isolation", "--no-deps", "--wheel-dir", str(artifacts), str(archive)])
        wheel, = artifacts.glob("*.whl")
        with zipfile.ZipFile(wheel) as stream:
            inspect_members((name, stream.read(name)) for name in stream.namelist() if not name.endswith("/"))
            metadata, = [name for name in stream.namelist() if name.endswith(".dist-info/METADATA")]
            if b"License-Expression: MIT" not in stream.read(metadata):
                raise ValueError("Wheel license metadata is missing.")
        run([str(python), "-m", "pip", "install", "--no-deps", str(wheel)])
        run([str(python), "-m", "pip", "check"])
        run([str(python), "-I", "-c", "import importlib.metadata as m; assert 'google-genai' not in {d.metadata['Name'].lower() for d in m.distributions()}"])
        for module in (["codeshield"], ["codeshield.integrations", "hook"], ["codeshield.integrations", "ci"], ["codeshield.integrations", "docker"]):
            run([str(python), "-I", "-m", *module, "--help"])
        for name in ("codeshield", "codeshield-hook", "codeshield-ci", "codeshield-docker"):
            executable = python.parent / (name + ".exe" if os.name == "nt" else name)
            run([str(executable), "--help"])
    print("Installation checks passed: sdist, wheel, excluded canaries, MIT metadata, isolated CLI, entry points, no Gemini SDK.")


if __name__ == "__main__":
    try:
        check()
    except (OSError, ValueError, subprocess.TimeoutExpired, tarfile.TarError, zipfile.BadZipFile):
        print("Installation verification failed; no clean build claim is made.", file=sys.stderr)
        raise SystemExit(3)
