# Configuration and AI verification

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
.\.venv\Scripts\python.exe -m pip install --require-hashes --only-binary=:all: -r requirements-dev.lock
.\.venv\Scripts\python.exe -m pip install --no-build-isolation --no-deps -e .
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

