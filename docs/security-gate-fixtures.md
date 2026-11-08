# Phase 4 CI fixture findings

The local reproduction of the Phase 3-to-Phase 4 commit comparison returned the
reported **18 blocking `secret-assignment` findings**: 17 in
`tests/integration/test_integrations.py` and one in `scripts/check_docker.py`.
Inspection traced one finding to an invented sentinel constant and the other 17
to string expressions that construct synthetic test sources. None of these
reported findings was a genuine credential exposure. Review used local source
inspection and redacted scan metadata. Actual environment files and provider keys
were not inspected, and no live model requests were made.

## Narrow correction

The 18 findings occupied 17 physical source lines (one line constructed two
assignments). Those reviewed synthetic lines now carry the existing explicit
`codeshield: test-fixture` comment. The annotation belongs to the test/helper's
source line; it is **not** part of the string written into the disposable test
repository. The staged/hook/CI tests must therefore still detect and block their
generated credentials. No detector patterns, severity thresholds, fail-closed
behavior, provider defaults, security workflow, or test-directory exclusions were
changed for this correction.

`tests/integration/test_ci_fixtures.py` scans the actual two source files and
checks clean staged, ref, push-event and PR-event results. Negative regressions
append an unmarked credential to both a previously annotated test file and a new
test file. They cover the identical sentinel value, a generated known-key prefix,
and a marker inside a quoted string. All must still block with redacted reports.
A separate adjacent-line regression proves a comment marker cannot suppress the
following line. These are invented probes; no real credential is used or tested
against a service.

## Comparison scope and local reproduction

The earlier Phase 5 added-line preflight compared only uncommitted changes against
the Phase 4 HEAD. It missed the already-committed Phase 4 findings. The corrective
check instead exports the Phase 3 baseline and overlays the complete current
working snapshot into a disposable Git mirror, then invokes the actual
`python -I -m codeshield.integrations ci` entry point for both event types.
Only that disposable mirror receives snapshot commits; the project's HEAD and
index remain unchanged, and nothing is pushed. Actual `.env`, private key paths,
virtual environments and Git metadata are not copied from the working directory.

The mirror must use the same Git CRLF-to-LF normalization as this Windows
repository. A first run with normalization disabled incorrectly treated unchanged
CRLF fixture lines as additions and failed closed. With repository-equivalent
normalization, push endpoint and PR merge-base checks each returned **exit 0,
zero total findings, zero blocking findings, validation passed** for the full
Phase 4 + Phase 5 candidate snapshot. This checks real Git objects and CI event
handling, rather than substituting an empty checkout index.

Historical commit objects remain immutable: rescanning the old Phase 4 commit
still reproduces 18 findings until its content is superseded by these changes in
a new published commit. No history was rewritten. Hosted GitHub Actions cannot
verify the uncommitted correction yet. Docker runtime remains unavailable
locally. Whole-history or whole-worktree audits are separate scopes; a clean CI
comparison is not a universal security guarantee.

Verification: **101 focused tests passed**; the complete suite finished with
**419 passed, 1 skipped** in 465.31 seconds. The skip is unavailable Windows
filesystem-symlink creation; portable Git-index link tests passed. Compilation,
dependency consistency and Git whitespace checks also passed. Further release
status is recorded in [release readiness](release-readiness.md).
