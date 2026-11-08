# Contributing

Use Python 3.12+ and Git. Install `requirements-dev.lock` with `--require-hashes
--only-binary=:all:`, then `pip install --no-build-isolation --no-deps -e .` in a
virtual environment. Run `python -m pytest -q`, `python -m compileall -q codeshield
scripts`, and `python -m pip check` before requesting review.

Tests must be offline: use mock providers or intercepted SDK HTTP transports.
Never add an opt-in integration test that reads a developer's real key or calls
Gemini. Test Git writes belong only in disposable repositories. Use invented
credentials, check every output channel for leakage, and withhold raw child-process
output in failure messages. Keep default mock, strict enums, call/retry budgets,
sanitization, deterministic edit validation and approval requirements intact.

Add a focused regression for each security fix. Test the unchanged Git index,
explicit approval, rollback/recovery and both clean/blocking exit codes when
changing remediation or integrations. No automatic staging, publishing or pushes.
Dependency updates must refresh exact versions and wheel hashes together and pass
fresh installation checks on the supported CI matrix. Report vulnerabilities as
described in [SECURITY.md](SECURITY.md).
