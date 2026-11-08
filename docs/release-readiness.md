# Release-readiness record

Phase 5 prepares the existing 0.1.0 development version; it does not publish a
package, tag a release, create a GitHub release, commit or push. The user's explicit
no-release instruction takes precedence over the PRD's suggested release tag.

## Verification scope

Local environment: Windows, Python 3.14, Git for Windows. Default mock remains
unchanged. Test sockets are blocked; SDK requests use intercepted fake HTTP
transports. Child-process journeys explicitly select mock/default-mock in new
disposable repositories. No live Gemini requests or quota were used.

The final test and installation results are recorded below.
Docker/podman and actionlint are unavailable locally. GitHub-hosted jobs cannot
verify uncommitted changes; no remote workflow or branch protection was changed.
Linux/Python 3.12 and actual Docker build/run remain external CI gates, not claimed
local successes. The real filesystem-symlink test may skip on Windows without
symlink privileges; portable Git-index link tests still run.

## Security and packaging checks

- Argument errors use fixed diagnostics; invalid values and abbreviated live
  opt-in flags cannot leak credentials or enable a provider.
- CLI tests prove default mock, approved Python/Node changes, failed/unapproved
  operations without source/index writes, rollback/retry and restage requirements.
- Existing tests cover missing keys, cache corruption, bounded calls/retries,
  rate limits, provider failures, malformed decisions and secret redaction.
- Public pinned dependency versions were queried against the OSV advisory API.
  The initial audit found affected pytest 9.0.1 and setuptools 80.9.0 pins;
  these were replaced with pytest 9.2.0 and setuptools 84.2.1, with refreshed
  published wheel hashes. The final audit result is recorded below.
  References: [pytest security fix](https://github.com/pytest-dev/pytest/releases/tag/9.0.3),
  [setuptools Windows advisory](https://github.com/pypa/setuptools/security/advisories/GHSA-xmj3-9gf7-h52w).
- `scripts/check_install.py` builds an allowlisted current-source copy, inspects
  wheel/sdist content and MIT metadata, checks synthetic sensitive-file canaries
  are excluded, and installs the wheel in a fresh hash-locked environment.
  The actual `.env`, Git metadata and virtual environment are never copied.
- A fresh **remote clone of Phase 5** cannot be tested until the user publishes
  these changes. The clean-source export and sdist-to-wheel install cover the
  current uncommitted implementation without changing Git history.
- The working-tree/added-line preflight completed with zero blocking candidates
  on the changed lines, without staging them. Whole-tree heuristic scans also
  encounter existing synthetic test strings and code-in-string/enum false positives;
  test directories are not globally ignored. Fixture markers are explicit and
  are not propagated into the disposable credential-bearing test sources.
  Only the blank `.env.example` is tracked among environment/key paths. This is
  not a full-history credential audit; gitleaks is unavailable locally.

## Remaining gates and limitations

Before publishing, review the diff and MIT license, publish only intended files,
run the supplied GitHub Actions matrix and Docker job, and inspect uploaded
redacted reports. A required branch-protection check is a separate repository
setting. Hooks can be bypassed; checked-out code and local Git configuration are
trusted. No hosted credentials or extra repository permissions are needed.

No universal detection, runtime-correctness, crash-atomic multi-file transaction,
live provider availability or credential-revocation guarantee is made. Detection
skips/fixture markers and configured exclusions reduce coverage. Full history and
intermediate commits are not scanned. Syntax-safe environment refactors can still
require application/deployment configuration. Consult SECURITY.md and remediation.md
before recovering a stale lock or an incomplete rollback. Vulnerability databases
are incomplete and time-sensitive; an advisory scan is not a security guarantee.

## Executed results

The Phase 4 gate follow-up is documented in
[security-gate-fixtures.md](security-gate-fixtures.md). It reproduces the original
18 synthetic findings and verifies the entire Phase 4 + Phase 5 candidate in a
disposable CI mirror, avoiding the earlier preflight's Phase 5-only scope.

Verified locally on 2026-11-08:

| Check | Actual outcome |
| --- | --- |
| Complete suite after CI fixture correction: `python -m pytest -q -p no:cacheprovider` | **419 passed, 1 skipped** in 465.31 seconds |
| Skip | Windows filesystem-symlink creation unavailable; portable Git-index link tests passed |
| Focused final journey/archive/init suite | 27 passed |
| Focused CI fixture/integration/detection regressions | 101 passed |
| `python -m compileall -q codeshield scripts` | Passed |
| `python -m pip check` | No broken requirements |
| `python scripts/check_install.py` | Passed: fresh hash-locked dependencies, sdist-to-wheel build, exclusion canaries, MIT metadata, isolated CLI and all four console entry points; optional Gemini SDK absent |
| Documented synthetic demo | Both preview-only and explicitly approved paths passed in tests |
| CLI, native hook, refs, CI event adapter and workflow policy tests | Passed in complete suite |
| OSV query of all runtime/development/build pins | 38 packages checked; zero advisory matches after updates |
| Changed-line secret preflight | Zero blocking candidates; actual index untouched |
| Full Phase 4 + Phase 5 candidate CI mirror: push | Exit 0; refs/endpoints; zero total and blocking findings; validation passed |
| Full Phase 4 + Phase 5 candidate CI mirror: PR | Exit 0; refs/merge-base; zero total and blocking findings; validation passed |
| Documentation relative links / Git whitespace | Passed |
| Docker build/run, GitHub-hosted matrix, actionlint, gitleaks | Unverified/unavailable locally |
| Live Gemini/account/quota/billing | Intentionally untested; no live requests made |

Assessment: **prepared for release review, with external validation outstanding**.
The local Windows/offline gates pass. The PRD's full release gate is not claimed
complete until the supplied hosted matrix and Docker job run successfully on the
published changes. Review the license and final diff before publishing. No release,
tag, commit or push has been created, and no frontend was added.
