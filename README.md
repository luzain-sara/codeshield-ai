# CodeShield-AI

Local-first Python credential security CLI. **Phases 0 through 4 are implemented.**
Detect likely hardcoded credentials offline in Git-staged additions, or opt into
a working-tree scan. Reports contain sanitized metadata and fully redacted samples.
Verification defaults to a deterministic offline mock. Explicitly enabled Gemini
verification receives only sanitized structural context. Conservative remediation
requires a validated plan and developer approval. Offline pre-commit hooks,
Git-ref comparisons, GitHub Actions gates and Docker packaging are available.
See [developer integrations](docs/integrations.md) for installation and limits.

## Windows PowerShell setup

Requires Python 3.12+ and Git; verified on Python 3.14. Use the virtual environment
executables directly, so PowerShell activation policy does not need to change.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --require-hashes --only-binary=:all: -r requirements-dev.lock
.\.venv\Scripts\python.exe -m pip install --no-build-isolation --no-deps -e .
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
No parent-directory config search takes place. Configuration itself never loads keys.

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

Mock is the offline default (changed from Phase 1 at the user's request). Explicit
`--provider rules` preserves deterministic rules-only operation. Neither mode
loads credentials, imports the optional SDK, calls a provider, or writes a cache.
Mock decisions are marked `mock`, never presented as real model assessments.

## Optional live Gemini verification

Install the optional, pinned official Google Gen AI SDK and dotenv parser:

```powershell
.\.venv\Scripts\python.exe -m pip install -e '.[dev,gemini]'
# Set GEMINI_API_KEY securely in your environment or in an ignored .env.
.\.venv\Scripts\codeshield.exe scan --staged --provider gemini --allow-live
```

Both selecting `gemini` and passing `--allow-live` are required. Setting a provider
in TOML alone cannot authorize a request. Live verification is disabled when CI,
GITHUB_ACTIONS, GITLAB_CI, or TF_BUILD is set to a true value. A notice explains
external context transmission before scanning. No live request is made for a
clean scan or a cache hit. Model availability and quota depend on your account;
`gemini_model` is configurable (default `gemini-3.5-flash-lite`).

Credential precedence is `GEMINI_API_KEY` from the existing environment, then
`GEMINI_API_KEY` from `.env` at the scanned repository root. An explicitly empty
environment variable is an error, not permission to fall back to another key.
No parent search, shell expansion, dotenv interpolation, or modification of the
process environment occurs. Linked, oversized, missing, unreadable, or invalid
credential files are rejected with fixed diagnostics. The blank `.env.example`
is safe to track; actual credentials must never go in TOML or source control.
Only an explicitly selected `doctor --provider gemini` checks credential loading;
doctor makes no model request. Run doctor at the repository root.

The sanitizer projects code into a finite schema: language, operation, framework
hint, example/environment/comparison flags, and a fixed code skeleton containing
`<REDACTED_SECRET_1>`. Original values, source literals, identifiers, comments,
paths, custom regex expressions, and unrelated code are never sent. This is
deliberately lossy, including for sensitive strings the detector did not recognize.
Framework hints are conservative context metadata, not an authorization to edit.

The bounded workflow executes only `inspect_context` and `detect_framework` on
already-sanitized in-memory data, assesses once through a bounded verifier, then
chooses a read-only policy. Gemini function calling and automatic tool execution
are disabled; any returned tool call is rejected. Decisions require strict enums
for classification, reason, and recommendation. Free-text, extra fields, malformed
JSON, refusals, truncated output and unknown decisions cannot authorize a fix.

All verification advice is advisory: even `false_positive` leaves the original
finding, severity, detection confidence, and blocking count intact. Only a valid
Gemini response or safe cache hit is labeled `gemini`; failures retain `rules`
provenance, an `uncertain` decision, and a failed validation status. Such runs
return exit **3**, with a sanitized report if detection completed. No edits occur.

Quota controls: tiny prompts, 512 output tokens, a shared `max_api_calls` budget
(default 5, including retries), `api_max_retries` (2), exponential backoff bounded
at 5 seconds, request timeout (10 seconds), and a separate verification deadline
(60 seconds). Only transient network errors, 429, and selected 5xx errors retry.
The SDK's own retries are disabled, so budgets cannot multiply. A failed provider
is not repeatedly queried for subsequent findings in the same run. SDK/HTTP logs
are suppressed during serialized transport operations and logging is restored.
Requests use the fixed Google endpoint with environment proxies and redirects disabled.

Successful Gemini decisions are cached locally under
`.codeshield/verification-cache.json` (Git-ignored by this project). Equivalent
sanitized contexts share results across files/runs. Keys hash only the nonsecret
projection, provider/model and prompt/policy version; values contain enum decisions
and expiry times. No source, candidates, finding paths, raw responses, API keys,
or hashes of credential values are cached. Cache TTL defaults to 86400 seconds;
set `verification_cache_ttl_seconds=0` to disable it. The cache is bounded to 256
entries, rejects unsafe data/links, and tolerates corruption or unavailable storage.
Other repositories should also ignore `.codeshield/`. Cache failures do not permit
findings to be dismissed. The cache is a performance hint, never trusted authorization.

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
surrounding source is omitted. Findings disclose assessment provenance, severity,
detection confidence, evidence, location, verification status and review advice. Existing output files are never
overwritten. Failed scans emit a safe stderr diagnostic and no success report.
The output destination must be new, writable, outside `.git`, with no linked parents.

`explain` reconstructs a current staged finding without persisting secrets. `fix`
previews or applies an approved deterministic patch. `init` remains an explicit
placeholder returning **3**. Git-ref arguments must be paired; endpoint and PR merge-base
comparisons read immutable commit snapshots. See [integrations](docs/integrations.md).

| Code | Contract |
| --- | --- |
| 0 | Successful operation; selected scan has no findings at/above blocking severity |
| 1 | Findings at/above configured blocking severity |
| 2 | Invocation/configuration/credential error or missing live consent |
| 3 | Scan/validation failure or an unimplemented operation (fail closed) |

## Safe remediation

```powershell
.\.venv\Scripts\codeshield.exe scan --staged
.\.venv\Scripts\codeshield.exe explain FINDING_ID
.\.venv\Scripts\codeshield.exe fix FINDING_ID --dry-run
.\.venv\Scripts\codeshield.exe fix FINDING_ID --apply
```

Fixing defaults to dry-run. Apply shows a redacted structural diff and requires
interactive approval, or explicit `--apply --yes` for trusted local automation.
Only plain module-level Python string assignments and identified server-side
Node.js declarations are eligible. Browser frameworks and ambiguous transformations
are refused. Python uses AST validation; Node uses Tree-sitter plus trusted
`node --check` without executing the application. Node.js is required for Node fixes.

The default adds a blank `.env.example` entry, never a credential. Explicit
`--store-secret` additionally approves storing the current value in a private,
untracked, Git-ignored `.env`. Existing values are not overwritten. Writes use
guarded snapshots, atomic replacements and in-memory rollback copies. No operation
automatically stages, commits, pushes or rotates credentials. An applied fix exits
**1** with `fix_applied_to_worktree_requires_restage`: review all changes, restage
intentionally, and rerun the staged scan. The original index remains blocked.

Remediation requires no Gemini calls. Mock remains the default, and explicit
rules-only operation works offline. Fix/explain refuse `gemini` selection rather
than silently falling back after a provider failure; optional advisory Gemini
verification stays a separate explicit scan with the existing cache/budget limits.
See [remediation safety, environment setup, rollback and limitations](docs/remediation.md).

## Project structure

- `codeshield/cli.py`: argument contract and non-mutating setup diagnostics.
- `codeshield/config.py`: validated TOML configuration and offline defaults.
- `codeshield/models.py`: enums, safe finding metadata, summary and result schema.
- `codeshield/git_diff.py`: bounded Git reads and validated added-line parsing.
- `codeshield/detectors/`: regex rules, lexical comment filtering and entropy.
- `codeshield/scanner.py`: snapshot selection, safety limits and stable findings.
- `codeshield/reporting.py`: sanitized human/JSON rendering and exclusive output.
- `codeshield/agent/`: finite-vocabulary sanitizer, read-only tools, providers,
  strict verification, bounded workflow, conservative policy and safe cache.
- `codeshield/remediation/`: runtime identification, guarded snapshots, byte-range
  plans, permissions, atomic apply/rollback and allowlisted syntax validation.
- `tests/unit/`: configuration/schema validation.
- `tests/integration/`: installed CLI, Git diagnostics, failure and no-write checks.
- `docs/architecture.md`: boundaries and deferred work.

The CLI uses standard-library `argparse`; Pydantic validates contracts, `regex`
provides matching timeouts, and pytest runs tests. Direct dependencies are pinned
in `pyproject.toml`. Tree-sitter and its JavaScript grammar support safe Node
planning. The optional `gemini` extra adds the official `google-genai`
SDK and `python-dotenv`. The base install remains offline and has no provider SDK.

Do not commit real credentials. `.env` and local caches are ignored; only the blank
`.env.example` is intended for version control. Schemas reject unknown fields but
cannot prove arbitrary text is sanitized: later detection/reporting must enforce
redaction before constructing findings. Verification is advisory; remediation is
conservative and approval-based. Credential rotation is not implemented. No
security guarantee is made.

Detection is heuristic, not a complete language parser. Split/encoded/dynamically
assembled secrets, unfamiliar formats, and complex multiline literals may be
missed. Unsupported encodings and ambiguous/racing diffs fail closed. IDs depend
on rule/path/line/column and can change when code moves. Skips and configured
exemptions reduce coverage; exit 0 never guarantees that a repository is secure.
Full commit history and intermediate commits are not scanned. Scan limits count both sides of
changed files to bound diff generation. Sanitized structural context omits
semantic details, so verification can be uncertain or incorrect. The SDK path is
tested with an intercepted HTTP transport; account access, model availability,
actual billing, and end-to-end live API connectivity are not tested automatically.
The verification deadline gates attempts and rejects late responses; SDK I/O
timeouts are not a hard process-cancellation mechanism.
Remediation proves the supported transformation and syntax, not full runtime
behavior or deployment configuration. Phase 5 has not been started.
