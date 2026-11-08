# Foundation contracts

Phase 0 contains only CLI, configuration, and public result models. No detector,
Git diff parser, AI workflow, patch engine, hook, or CI security gate exists yet.
Create those modules with their implementing phases rather than empty placeholders.

Configuration flows from a local TOML file into immutable, validated Pydantic
models. Unknown fields fail validation. CLI errors never echo parser/schema
payloads; those may contain credentials supplied accidentally. Standard-library
argument parsing keeps the command skeleton small and avoids a CLI dependency.

Doctor runs bounded Git subprocesses with argument arrays, captured output, and
timeouts. It does not print Git output, read source files, load `.env`, stage,
commit, or modify working-tree files. It checks the `.env` path relative to the
current directory; run it at the repository root for the project-level check.
It is a setup diagnostic, not an audit of every environment file or Git history.

Finding metadata separates severity, confidence, and assessment provenance.
ScanResult carries a run UUID, scope, timezone-aware timestamps, version/provider,
findings, summary, and validation status (default `not_run`). Raw credential fields
are forbidden. Text fields must already be sanitized by future producers; the
schema is not a redactor. Result models are contracts only and are never emitted
by placeholder commands as evidence of a completed scan.

Later phases must implement staged-only boundaries, safe finding fingerprints,
redaction, and deterministic detection before introducing provider assessment.
Remediation and external integrations remain separate future phases. No code in
this phase sends data externally or claims that a staged index is commit-safe.
