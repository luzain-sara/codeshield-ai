# Phase 4 developer integrations

All provided gates scan without modifying source or staged content. They force
the offline mock provider even if `codeshield.toml` selects Gemini. No API key is
needed. The optional SDK is absent from the runtime lock and Docker image.
Tests use synthetic credentials and intercepted transports, never Gemini calls.

## Reproducible installation

Requires Python 3.12+ and Git. In a fresh virtual environment:

```sh
python -m pip install --require-hashes --only-binary=:all: -r requirements.lock
python -m pip install --no-build-isolation --no-deps .
python -m pip check
codeshield --help
```

Use `requirements-dev.lock` instead for tests and optional SDK tests, then install
the project with `--no-build-isolation --no-deps -e .`. Locks pin transitive and
build dependencies and permit only published wheel SHA-256 hashes. They support
the CI matrix (Windows/Linux, Python 3.12/3.14); other platforms need compatible
wheels. Update versions and hashes together after reviewing dependencies and
rerunning tests. These locks do not guarantee byte-identical build timestamps.

## Native Git hook

From the repository, using the installed virtual environment executable:

```sh
codeshield hook install
git commit
codeshield hook uninstall
```

On PowerShell, use `.\.venv\Scripts\codeshield.exe`. The installer records that
environment's absolute Python path, with isolated imports and shell-safe quoting;
keep it installed. A missing interpreter blocks commits. Git for Windows supplies
the hook shell. Installation is explicit and does not happen during pip install.
Existing hooks are preserved; compose them manually or use the pre-commit framework.
Repository-local `core.hooksPath` and linked-worktree common Git directories are
honored; external shared hook directories and linked paths are refused. Removal
only removes the exact managed hook for this interpreter.

The repository also supplies `.pre-commit-hooks.yaml` for the pre-commit framework:

```yaml
repos:
  - repo: https://github.com/luzain-sara/codeshield-ai
    rev: REPLACE_WITH_REVIEWED_PHASE_4_COMMIT_SHA
    hooks:
      - id: codeshield
```

Replace the revision after these changes are published; no release/tag is created
here. Pre-commit installs its own environment; use the locked native installation
above when transitive dependency reproducibility is required. The hook ignores
filename arguments and scans the entire staged diff, including partial staging.
Unstaged contents do not replace staged bytes. Git may refresh its own index stat
metadata during `commit`; CodeShield never stages or rewrites blobs. Git hooks can
be bypassed with `--no-verify`; require the CI check in branch protection separately.

## Git-ref comparisons

```sh
codeshield scan --base-ref BASE --head-ref HEAD --format json
codeshield scan --base-ref BASE --head-ref HEAD --merge-base --format json
codeshield scan --base-ref EMPTY --head-ref HEAD --format json
```

The default compares commit endpoints. `--merge-base` scans additions between the
unique merge base and head (PR semantics). `EMPTY` scans every supported file in
the head tree for a newly created branch; it cannot be paired with `--merge-base`.
Refs resolve once to immutable commit IDs; reports contain IDs, not supplied ref
expressions. Diffs, file contents and context come from Git objects, independent
of the staged index and working tree. Renames scan only new lines. Deletions and
unchanged credentials are outside the comparison; intermediate commits and full
history are not scanned. Existing file filters, severity thresholds and limits
apply. Review reported skips; exit zero is not a security guarantee.

Missing/shallow/unrelated/ambiguous history fails closed. Fetch required history
explicitly before retrying; the scanner never fetches or substitutes the index.
An orphaned force-push base may need to be fetched by SHA, if the server retains it.

## GitHub Actions

`.github/workflows/codeshield.yml` runs on pull requests and pushes, with read-only
permissions, pinned actions, full checkout history and no persisted credentials.
PRs use event base/head SHAs and their unique merge base. Pushes use event
before/after SHAs. New branches use `EMPTY`; branch-deletion pushes are skipped.
No `pull_request_target`, model key, live provider or remediation is used.

The entry point can also be exercised with a saved event:

```sh
codeshield-ci --event pull_request --event-file event.json --output report.json
```

GitHub supplies `GITHUB_EVENT_NAME` and `GITHUB_EVENT_PATH` automatically. Event
metadata is parsed as JSON, not interpolated into shell commands. Only full
commit IDs are accepted. A report is created exclusively, never overwritten.
Successful scans emit the normal redacted schema, including comparison metadata.
Event/history/configuration failures emit a small `validation_status: failed`
envelope without a fabricated clean summary. The workflow uploads only that
report, even when findings block, and then enforces the scanner's outcome.
Reports remain untrusted data and should not be rendered as executable content.

Exit codes: **0** completed with no blocking findings (or deleted-push no-op),
**1** blocking findings, **2** invalid arguments/configuration, **3** scan,
history, report or verification failure. Every nonzero exit blocks a hook/CI gate.
The CI event adapter maps invalid event metadata to 3. API failures in explicitly
enabled manual scans retain the existing bounded retries and fail-closed behavior.

`.github/workflows/tests.yml` runs the complete offline suite on Windows/Linux
and Python 3.12/3.14, plus a Docker build and network-disabled container smoke test.
Workflows operate on checked-out code; normal repository review and branch
protection remain necessary. No local changes are committed or pushed for you.

## Docker scan-only packaging

```sh
docker build -t codeshield .
docker run --rm --network=none --mount "type=bind,src=$PWD,dst=/repo,readonly" codeshield --staged --format json
python scripts/check_docker.py codeshield
```

In PowerShell use `src=$($PWD.Path)` in the mount string. The source mount must be
readable by UID 10001 and contain Git metadata and referenced objects (linked
worktrees need their common directory mounted too). The image pins the official
Python base by digest, installs hash-locked wheels, runs as a non-root user and
trusts only `/repo` for Git ownership checks. Its build context is allowlisted;
`.env`, Git metadata, private keys, tests and local virtual environments are not
copied. Git is supplied by the pinned full Bookworm image, avoiding unpinned apt
resolution. That choice increases image size.

The entry point accepts scan options only; Gemini and fix commands are rejected.
Use JSON stdout for read-only mounts; `--output` requires a separate writable
destination. Building needs package/image downloads; runtime scans need no
network. The smoke check tests clean/blocking results, redaction, no mutation and
error codes with networking disabled. Docker is unavailable on the implementation
machine; the actual build/run is delegated to the supplied CI job and has not
been executed locally. See [release readiness](release-readiness.md) for final validation.
