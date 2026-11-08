# Foundation contracts

Phases 0–3 contain CLI, configuration, offline detection, Git diff selection,
reporting, bounded verification and approved remediation. Hooks and CI security
integration remain unimplemented. Phase 4 has not begun.

Configuration flows from a local TOML file into immutable, validated Pydantic
models. Unknown fields fail validation. CLI errors never echo parser/schema
payloads; those may contain credentials supplied accidentally. Standard-library
argument parsing keeps the command skeleton small and avoids a CLI dependency.

Doctor runs bounded Git subprocesses with argument arrays, captured output, and
timeouts. It does not print Git output, read source files, stage,
commit, or modify working-tree files. It checks the `.env` path relative to the
current directory; run it at the repository root for the project-level check.
It is a setup diagnostic, not an audit of every environment file or Git history.
Only explicit `doctor --provider gemini` loads the credential securely for a local
setup check. No doctor mode makes an API request.

Finding metadata separates severity, confidence, evidence and assessment provenance.
ScanResult carries a run UUID, scope, timezone-aware timestamps, version/provider,
findings, summary, and validation status (default `not_run`). Raw credential fields
are forbidden. Text fields must already be sanitized by future producers; the
schema is not a redactor. The scanner constructs samples from a fixed placeholder,
never source snippets. Paths remove known candidate values, recognizable tokens,
URLs/emails, and terminal control characters. Raw candidates are transient only.

## Offline detection flow

`git_diff.py` lists NUL-delimited staged metadata with full blob IDs and rename
detection. It reads immutable staged blobs, caps both old/new sizes, then parses
`git diff --cached --unified=0` for each selected change. Paths come from metadata,
never quoted patch headers. Added bytes/line numbers must match the selected
index blob, and metadata is checked again before success. Unmerged indices,
ambiguous multi-file rename diffs and snapshot changes fail closed.

Git invocations use argument arrays and literal pathspecs. External diff drivers,
textconv, color and filesystem-monitor commands are disabled. Captured stdout is
bounded, stderr is discarded, and subprocess/global scan deadlines are enforced.
The Git reader never writes, stages, commits, pushes, or accesses a remote.

`scanner.py` builds lexical comment context from the full snapshot, then detects
only candidate values on added lines. `--path` instead selects current files from
Git's tracked/untracked listing, honors ignores for discovery and checks containment
and links before reading. Explicit files opt into scanning ignored paths. Whole-file
scans detect literal assignments whose value begins on the following line too.

`detectors/` combines prefix regexes, authorization values, credential assignment
names and entropy with contextual evidence. Overlapping candidates are deduplicated.
Custom regex rules have matching timeouts. Detection stays deterministic while
verification provenance is disclosed separately. Fingerprints hash only sanitized location and rule,
not candidate values. Findings are ordered by path/line/column/rule, while run
metadata remains unique. `passed` means the selected scan completed, not that
remediation or syntax validation took place.

`reporting.py` creates sanitized human/JSON output. Explicit output uses exclusive
creation; existing files and Git metadata cannot be overwritten. Errors use fixed
diagnostics, never exception payloads from files/config/Git.

Limitations: UTF-8 text only; a lexical detector cannot prove full language semantics
or detect every split/encoded secret. Filesystem link checks cannot provide a
transactional snapshot against a hostile process concurrently replacing directories;
staged scans avoid this by reading Git blobs. Skip reasons and selected scope are
visible. No claim of universal detection or commit safety is made.

## Phase 2 verification boundary

The scanner creates safe structural contexts from the same snapshot used for
detection. `agent/sanitizer.py` exports only schema-constrained enums, booleans and
fixed code skeletons. Quoted literal contents are removed before deriving hints.
No original source names, literals, comments or filenames enter provider payloads.
Context is intentionally less expressive than a source snippet to cover unrelated
credentials missed by detection and to prevent source-based prompt instructions.

`tools.py` accepts only typed requests for known finding IDs. Tools inspect safe
in-memory context or return a finite framework hint; they cannot open paths,
execute shell/network requests, or write files. `workflow.py` has six fixed states
per finding and two fixed tool calls; no model-driven loop or tool dispatcher exists.
The model's structured output cannot request additional tools or new transitions.
`policy.py` denies fixes for every decision, including likely secrets.

`providers.py` keeps rules/mock entirely offline. Gemini is lazy, requires explicit
live consent outside CI, uses the official pinned `google-genai` SDK, and loads only
GEMINI_API_KEY (environment first, then the repository-root .env without interpolation).
SDK automatic function calls, SDK retries, alternate endpoint/proxy environment
settings and redirects are disabled. Transport logs are suppressed under a lock
during SDK operations; this briefly suppresses process logging in this CLI.

`verifier.py` strictly validates classification/reason/recommendation enums and
enforces request count, retry/backoff and verification deadlines. Failures become
uncertain, never lower deterministic risk, and produce scan validation failure.
Malformed results are not retried or cached. After a terminal API error, later
uncached findings are marked unavailable instead of consuming more quota.

`cache.py` caches successful enum decisions with TTL under .codeshield, using a
versioned hash of sanitized context and model. No credential hashes or source are
stored. Equivalent projections deduplicate calls. Cache data is untrusted and
cannot affect blocking policy; corruption/storage failures only remove the
optimization. Mock/rules do not create persistent state. No raw response is saved.

Phase 1 rule/path/line/column finding IDs, detection confidence/severity and blocking
counts are preserved. `Finding.verification` adds truthful source/status/cache/state
metadata; a false-positive assessment is still advisory. Failed requested Gemini
verification has rules provenance and causes CLI exit 3, with safe uncertainty in
the report. Verification itself never authorizes remediation; local plan
eligibility and explicit apply approval are separate boundaries.

The optional provider tests use Google's real SDK with an HTTP MockTransport and
synthetic keys; socket connections are blocked in tests. Live access, quota, model
availability and billing remain environment/account-dependent and are not probed.

## Phase 3 local planning boundary

`agent.workflow.plan_fix` invokes the fixed local planner, reconstructing current
staged findings through an internal transient callback. Raw bytes stay inside the
trusted local scanner/planner; the callback is not a provider tool or persistence
interface. No model receives a Plan, raw candidate, source, secret hash or patch.
Provider `fix_allowed` remains false. Six fixed planning states stop at approval.

`remediation/framework.py` reads guarded metadata and rejects client/unknown
runtimes. `planner.py` proves a single literal assignment using Python AST or
Tree-sitter, creates minimal byte-range edits, and syntax-checks the candidate.
Its private frozen Plan retains original/proposed bytes only in memory. Previews
contain structural redaction, safe location, approved names and auxiliary changes.
The Phase 2 scan chain remains read-only and does not create or apply plans.

`snapshot.py` rejects links, hard links, non-regular, oversized and cross-filesystem
files. `security.py` handles permissions/Windows DACLs. `patcher.py` revalidates
the reviewed plan, locks, checks guards/index/HEAD before each write, uses ignored
private temporaries and atomic replacement, then runs allowlisted syntax checks
and fresh working-tree/index scans. Handled failures roll back without disk
backups; unsafe/incomplete rollback fails closed. Apply never stages changes and
returns blocking until intentional restaging. See [remediation.md](remediation.md)
for supported syntax, environment consent, operational limits and failure states.
