# Phase 3 remediation contract

This release implements conservative, developer-approved working-tree fixes.
Hooks, CI integration, PR diff scanning and Docker packaging remain Phase 4 work.

## Workflow and approval

Run a staged scan and use its 24-character finding ID. `explain ID` reconstructs
safe metadata in another process. `fix ID` and `fix ID --dry-run` perform the
fixed chain: finding → offline assessment → deterministic policy → candidate
patch → syntax validation → await approval. No dry-run files or caches are written.

`fix ID --apply` displays a sanitized structural diff and prompts for approval.
Rejecting approval or EOF changes nothing. Noninteractive automation requires
`--apply --yes`; `--yes` alone is an invocation error. Every approved plan is
reconstructed/revalidated before writing. AI advice cannot grant approval.
The preview shows file/line, runtime, environment variable, necessary Python
import, and auxiliary-file edits. Original literals and surrounding code are
omitted, so unknown neighboring credentials cannot leak through a diff.

## Supported code and refusals

Python supports one plain single-line string assigned to one module-level name,
including a `str` annotation. The literal is replaced by `os.environ["NAME"]`.
An unaliased `import os` is reused when available earlier in the module; otherwise
it is inserted immediately before the assignment, preserving docstrings, future
imports, BOM, encoding declarations, and existing LF/CRLF bytes.

Server-side JavaScript supports one plain top-level `const`, `let`, or `var`
declaration in `.js`, `.cjs`, or `.mjs`. The literal becomes `process.env.NAME`.
A staged package manifest must declare a simple `node path.js` startup command or a known
backend dependency. A Node tooling engine version alone is not server proof.
CommonJS and ESM modes follow extension and nearest package metadata.
Python AST and Tree-sitter prove the selected literal and binding before patch
construction; there are no regex code rewrites.

Refusals include browser/public/static/client paths; generated directories or
generated-file headers; Vite, Next.js, React and other known browser frameworks/configs;
`NEXT_PUBLIC_`/`VITE_` exposure; browser
APIs and `use client`; unknown runtimes; TS/JSX, Go, JSON, YAML, or .env fixes;
object properties, exported declarations, constructors, nested assignments,
templates, concatenation, escapes, multiline literals and repeated/ambiguous
bindings. Shadowed/mutated `os`/`process` and dynamic Python namespace mutation
require manual remediation. Framework heuristics cannot prove that all code is
server-only: deployment/data-flow review remains the developer's responsibility.

Only current staged findings are accepted. The target must have a tracked regular
index entry matching the worktree, allowing CRLF/LF normalization while retaining
the worktree's line endings. Other unstaged changes are refused. Dirty inspected
metadata, unstaged manifests, renames/type changes, readonly/encrypted targets, symlinks,
junctions, hard links, and cross-filesystem paths require manual handling.
All inspected files and absent config paths, plus index and HEAD, are snapshotted
and checked again after approval. File/scan limits remain enforced.

## Environment handling

The default fix writes a **blank** `NAME=` entry to `.env.example`. It does not
retain the original value. `--env-name SERVICE_API_KEY` chooses the reviewed name;
public/unsafe names, collisions and nonblank/duplicate example entries are refused.
Existing auxiliary project files that need editing must match staged snapshots.

`--store-secret` is separate explicit consent to write the original development
value into `.env`, still subject to apply approval. The file must remain untracked
and Git-ignored. A tracked .env blocks planning immediately. The plan adds root
ignore protection for `.env` and `.codeshield/` when needed, including overriding
a negative rule, before any credential is written. Existing keys/bytes are
preserved and destination keys are never overwritten. Only safe, single-line
dotenv literals and simple existing dotenv files are accepted; control/newline,
quote, backslash, dollar-expansion and complex cases require manual handling.

Environment temporaries/final files use POSIX 0600 or a protected Windows DACL
granting access only to the file owner and SYSTEM. Credentials never enter
`.env.example`, reports, caches, logs, LLM payloads, or new Git writes by this tool.
Configure environment injection/loading at application startup yourself: no dotenv
loader, application dependency change, or constructor rewrite is added by a fix.
Never put genuine credentials into examples, tests or source control.

## Apply, rollback and validation

Apply uses an exclusive `.codeshield/remediation.lock` and private transaction
directory. Temporaries live on the same filesystem, are ignored before source
or environment writes, and have restrictive permissions before data is written.
Each replacement is flushed/fsynced and atomic. Source/config permissions and
Windows ACLs are preserved. Original bytes and permissions stay in memory, not
`.bak` files or persisted finding metadata. Full index/HEAD and file guards are
rechecked before each write; the tool never stages, commits or pushes.

Python validation compiles/parses without importing or executing the module.
Node validation runs only trusted `node --check` on stdin, with Node preload/options
and credential environment variables removed. There are no package scripts,
arbitrary shell validators, model-provided commands, or remote tools. The changed
working-tree file and staged additions are rescanned offline after apply. Other
findings remain unresolved and visible as counts.

Handled failures/interruptions roll completed writes back, including original
environment bytes, modes and Windows ACLs. Rollback never overwrites a differing
concurrent edit. Incomplete rollback returns failure for manual review and retains
ignore protection if .env restoration fails. Abrupt process death/power loss
cannot guarantee multi-file rollback; private ignored temporaries or a stale lock
may require manual cleanup. Use a trusted repository/filesystem, avoid concurrent
edits while applying, and review stale locks before removing them.

An applied fix exits **1**, reports `fix_applied_to_worktree_requires_restage`, and
states that the unchanged index still contains the original finding. Review all
source/ignore/example changes, stage intended changes yourself, and rerun the
staged scan. Preview/explain/declined approval exit 0 for successful operations,
not security clearance. Refusals/stale plans/validation failures exit 3; invalid
invocations/provider selection exit 2. Apply never claims commit safety.
Previously exposed credentials must be rotated/revoked; refactoring does not
invalidate them. Syntax checks do not prove application runtime behavior or that
deployment environment variables are configured correctly.

## Gemini usage

Supported transformations have a local eligibility proof. Fix and explain use
mock (default) or rules, make **zero API calls**, load no provider keys, and refuse
Gemini selection instead of bypassing an API error. Explicit advisory Gemini
scans remain available separately, with sanitized-context caching, request limits,
rate-limit backoff and fail-closed errors. Neither a cached nor fresh model
response can authorize an ambiguous patch.
