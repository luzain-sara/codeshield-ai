"""Create public, offline defaults exclusively; never inspect or create .env."""

from pathlib import Path

from codeshield.config import Config
from codeshield.git_diff import Git
from codeshield.reporting import write_report

DEFAULTS = {
    "codeshield.toml": 'provider = "mock"\nblocking_severity = "high"\n',
    ".env.example": "# Blank placeholders only; configure values outside Git.\nAPI_KEY=\nGEMINI_API_KEY=\n",
    ".gitignore": "/.env\n/.env.*\n!/.env.example\n/.codeshield/\n/.venv/\n__pycache__/\n.pytest_cache/\nbuild/\ndist/\n*.egg-info/\n",
}


def initialize(cwd: Path) -> str:
    root = Git(cwd, Config()).root
    created = 0
    for name, content in DEFAULTS.items():
        target = root / name
        # Includes dangling symlinks: never follow, replace or read existing files.
        if target.exists() or target.is_symlink():
            continue
        write_report(target, content)
        created += 1
    return (f"Initialization complete: {created} default files created; existing files preserved.\n"
            "Review .gitignore: exclude .env, .env.*, .codeshield/ and virtual environments; allow blank .env.example.\n"
            "Run codeshield doctor, then codeshield scan --staged. No hooks were installed and no .env was read.\n")
