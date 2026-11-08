# CodeShield-AI

Local-first Python credential security CLI. **Phases 0 and 1 are implemented.**
Detect likely hardcoded credentials offline in Git-staged additions, or opt into
a working-tree scan. Reports contain sanitized metadata and fully redacted samples.
No AI verification, remediation, pre-commit integration, or CI integration is implemented.

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
without echoing their values.

Detection settings include `min_secret_length` (default 8), `entropy_min_length`
(20), `entropy_threshold` (3.5 bits/character), `max_files` (10000), `max_findings`
(1000), and `scan_timeout_seconds` (60). Entropy requires credential-related
context; random identifiers alone do not qualify. Strong credential assignments
do not require high entropy. Limits fail closed, rather than silently truncating.

Additional rules can be configured with `[[patterns]]`, a unique `rule_id`, an
`expression` containing a named `(?P<secret>...)` capture, and `severity`. See the
commented example in `codeshield.toml`. Custom rules supplement built-ins and run
with a 50 ms matching timeout. Empty candidate captures and timeouts fail closed.

Rules is the offline default. Mock and Gemini are reserved configuration values;
doctor and scan reject them as unavailable in this phase. API keys never belong in config.
The blank `GEMINI_API_KEY` entry in `.env.example` is future setup guidance only.
Scanning reads no provider keys from the environment and makes no provider requests.

## Commands and exit codes

`--help`, `--version`, `doctor`, and `scan` work. Doctor checks config, Git availability,
working-tree repository presence, and that `.env` is ignored and untracked. Its
success means setup checks passed, not that a repository is safe to commit.

```powershell
.\.venv\Scripts\codeshield.exe scan --staged
.\.venv\Scripts\codeshield.exe scan --format json --output codeshield-report.json
.\.venv\Scripts\codeshield.exe scan --path .
```

`scan` defaults to staged additions across the entire repository, even when run
from a subdirectory. It reads index blobs, not unstaged contents. Unchanged and
removed lines do not produce findings. Renames retain new-path line numbers.

`--path PATH` explicitly scans current files in a Git working-tree repository,
including untracked files, honoring Git ignore rules. An explicitly named file
(including an ignored `.env`) is opted in. Tracked ignored files are still checked;
Git ignore rules never suppress staged credentials. Protected/vendor directories,
known lock/minified files, unsupported extensions, binaries, links, and submodules
are skipped with reasons in both report formats. Symlinks/junctions are not followed.

Supported text: UTF-8 (optional BOM, LF/CRLF) Python, JS/JSX, TS/TSX, JSON, YAML,
and `.env` files. Detectors cover credential prefixes, authorization headers,
credential-named literal assignments, and contextual high entropy. Comment-only
appearances, standalone Python triple docstrings, obvious placeholders, benign
public identifiers/hashes/UUIDs, and variable references are filtered. A comment
`codeshield: test-fixture` suppresses only its marked line; test directories are
not automatically exempt. Credential-named hexadecimal values remain suspicious.

Human/JSON reports have stable finding IDs and ordering. Run UUIDs and timestamps
vary by execution. Samples are completely replaced with `<REDACTED_SECRET>`;
surrounding source is omitted. Findings disclose `rules` provenance, severity,
confidence, evidence, location and review advice. Existing output files are never
overwritten. Failed scans emit a safe stderr diagnostic and no success report.
The output destination must be new, writable, outside `.git`, with no linked parents.

`explain`, `fix`, and `init` remain explicit placeholders returning **3** without
changing files. Git-ref scan arguments must be paired, but ref comparison itself
is deferred to Phase 4. This release does not interpret a checkout index as a PR diff.

| Code | Contract |
| --- | --- |
| 0 | Successful operation; selected scan has no findings at/above blocking severity |
| 1 | Findings at/above configured blocking severity |
| 2 | Invocation/configuration error, including unavailable provider |
| 3 | Scan/validation failure or an unimplemented operation (fail closed) |

## Project structure

- `codeshield/cli.py`: argument contract and non-mutating setup diagnostics.
- `codeshield/config.py`: validated TOML configuration and offline defaults.
- `codeshield/models.py`: enums, safe finding metadata, summary and result schema.
- `codeshield/git_diff.py`: bounded Git reads and validated added-line parsing.
- `codeshield/detectors/`: regex rules, lexical comment filtering and entropy.
- `codeshield/scanner.py`: snapshot selection, safety limits and stable findings.
- `codeshield/reporting.py`: sanitized human/JSON rendering and exclusive output.
- `tests/unit/`: configuration/schema validation.
- `tests/integration/`: installed CLI, Git diagnostics, failure and no-write checks.
- `docs/architecture.md`: boundaries and deferred work.

The CLI uses standard-library `argparse`; Pydantic validates contracts, `regex`
provides matching timeouts, and pytest runs tests. Direct dependencies are pinned
in `pyproject.toml`. No frontend,
server, database, provider SDK, or runtime network dependency is included.

Do not commit real credentials. `.env` and local caches are ignored; only the blank
`.env.example` is intended for version control. Schemas reject unknown fields but
cannot prove arbitrary text is sanitized: later detection/reporting must enforce
redaction before constructing findings. AI advice, remediation, and credential
rotation are not implemented. No security guarantee is made by this foundation.

Detection is heuristic, not a complete language parser. Split/encoded/dynamically
assembled secrets, unfamiliar formats, and complex multiline literals may be
missed. Unsupported encodings and ambiguous/racing diffs fail closed. IDs depend
on rule/path/line/column and can change when code moves. Skips and configured
exemptions reduce coverage; exit 0 never guarantees that a repository is secure.
Previously committed history is not scanned. Scan limits count both sides of
changed files to bound diff generation. Phase 2 requires a separate go-ahead.
