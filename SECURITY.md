# Security policy

CodeShield is a local heuristic security assistant, not a guarantee that a
repository is secret-free. Review findings and proposed edits. Rotate or revoke
any credential already exposed; moving it into an environment does not revoke it.

Report vulnerabilities using GitHub private vulnerability reporting when available.
If unavailable, open an issue requesting a private reporting channel without
including sensitive details. Never include real keys, source containing live
credentials, `.env`, raw provider responses, private repository archives or
unredacted logs in issues, discussions or pull requests. Use synthetic reproductions.

The supported development line is 0.1.x; no response-time or security-update SLA
is promised. Live Gemini is optional, explicitly enabled, and receives only a
finite sanitized projection. Model advice cannot authorize edits. Mock mode is
the default; hooks, CI and Docker interfaces cannot opt into live verification.

Local Git configuration, installed dependencies, repository code and the host
account remain trust boundaries. Directory/link checks are not an OS sandbox.
Handled remediation failures attempt rollback; power loss, process termination or
concurrent hostile writes can require manual recovery. Inspect a stale transaction
lock before removing it; ensure no remediation process is running, preserve
ignore rules, review files and the index, and rerun scans before committing.

See [architecture](docs/architecture.md), [remediation](docs/remediation.md), and
[release validation](docs/release-readiness.md) for tested boundaries and gaps.
