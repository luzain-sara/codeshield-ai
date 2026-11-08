# Foundation contracts

Phases 0 and 1 contain CLI, configuration, public result models, offline detectors,
Git diff selection and reporting. No AI workflow, patch engine, hook, or CI
security gate exists. Those remain in their respective future phases.

Configuration flows from a local TOML file into immutable, validated Pydantic
models. Unknown fields fail validation. CLI errors never echo parser/schema
payloads; those may contain credentials supplied accidentally. Standard-library
argument parsing keeps the command skeleton small and avoids a CLI dependency.

Doctor runs bounded Git subprocesses with argument arrays, captured output, and
timeouts. It does not print Git output, read source files, load `.env`, stage,
commit, or modify working-tree files. It checks the `.env` path relative to the
current directory; run it at the repository root for the project-level check.
It is a setup diagnostic, not an audit of every environment file or Git history.

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
No Git write, stage, commit, push or network operation runs in the scanner.

`scanner.py` builds lexical comment context from the full snapshot, then detects
only candidate values on added lines. `--path` instead selects current files from
Git's tracked/untracked listing, honors ignores for discovery and checks containment
and links before reading. Explicit files opt into scanning ignored paths. Whole-file
scans detect literal assignments whose value begins on the following line too.

`detectors/` combines prefix regexes, authorization values, credential assignment
names and entropy with contextual evidence. Overlapping candidates are deduplicated.
Custom regex rules have matching timeouts. Provider provenance is always `rules`;
mock/Gemini remain unavailable. Fingerprints hash only sanitized location and rule,
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
visible. No claim of universal detection or commit safety is made. Phase 2 and all
remediation/integration work remain unimplemented.
