# CodeShield-AI

Local-first Python credential security CLI. **Only Phase 0 is implemented.**
This release provides installation, configuration, typed result contracts, setup
diagnostics, and a CLI skeleton. It does not detect credentials or assess commit safety.

## Windows PowerShell setup

Requires Python 3.12+ and Git; verified on Python 3.14. Use the virtual environment
executables directly, so PowerShell activation policy does not need to change.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e '.[dev]'
.\.venv\Scripts\codeshield.exe --help
.\.venv\Scripts\codeshield.exe --version
.\.venv\Scripts\codeshield.exe doctor
.\.venv\Scripts\pytest.exe
.\.venv\Scripts\python.exe -m compileall codeshield
```

`python -m pip install -e .` installs the package without test dependencies.
After activating `.venv`, the equivalent commands are `codeshield --help`,
`codeshield doctor`, and `pytest`. `python -m codeshield` is also supported.
On Linux/macOS use `.venv/bin/python`, `.venv/bin/codeshield`, and `.venv/bin/pytest`.

## Configuration

`codeshield doctor` loads `codeshield.toml` from the current directory, or uses safe
defaults when absent. `codeshield doctor --config PATH` requires that file to exist.
No parent-directory search or environment-file loading takes place.

The included TOML lists every supported field: provider (`rules`, `mock`, `gemini`),
blocking severity (`critical`, `high`, `medium`, `low`), positive integer file/scan byte
limits, Git timeout (1–300 seconds), and excluded directory names. The scan limit
must be at least the file limit. Unknown keys and invalid values are rejected
without echoing their values. Detection settings are contracts for later phases.

Rules is the offline default. Mock and Gemini are reserved configuration values;
doctor rejects them as unavailable in this phase. API keys never belong in config.
The blank `GEMINI_API_KEY` entry in `.env.example` is future setup guidance only.
Phase 0 reads no provider keys and makes no provider requests.

## Commands and exit codes

`--help`, `--version`, and `doctor` work. Doctor checks config, Git availability,
working-tree repository presence, and that `.env` is ignored and untracked. Its
success means setup checks passed, not that a repository is safe to commit.

`scan`, `explain`, `fix`, and `init` expose reserved help/arguments and exit **3**
without scanning, writing reports, or modifying files. A JSON scan request does
not emit a fabricated empty report. Git-ref scan arguments must be paired.

| Code | Contract |
| --- | --- |
| 0 | Successful implemented operation; future scans: no blocking findings |
| 1 | Blocking findings (reserved for a real scanner) |
| 2 | Invocation/configuration error, including unavailable provider |
| 3 | Scan/validation failure or an unimplemented operation (fail closed) |

## Project structure

- `codeshield/cli.py`: argument contract and non-mutating setup diagnostics.
- `codeshield/config.py`: validated TOML configuration and offline defaults.
- `codeshield/models.py`: enums, safe finding metadata, summary and result schema.
- `tests/unit/`: configuration/schema validation.
- `tests/integration/`: installed CLI, Git diagnostics, failure and no-write checks.
- `docs/architecture.md`: boundaries and deferred work.

The CLI uses standard-library `argparse`; Pydantic validates contracts and pytest
runs tests. Direct dependencies are pinned in `pyproject.toml`. No frontend,
server, database, provider SDK, or runtime network dependency is included.

Do not commit real credentials. `.env` and local caches are ignored; only the blank
`.env.example` is intended for version control. Schemas reject unknown fields but
cannot prove arbitrary text is sanitized: later detection/reporting must enforce
redaction before constructing findings. AI advice, remediation, and credential
rotation are not implemented. No security guarantee is made by this foundation.

Phase 1 (staged-diff scanning) requires a separate go-ahead.
