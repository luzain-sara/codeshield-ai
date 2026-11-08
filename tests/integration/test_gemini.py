"""Official SDK tests against a local fake HTTP transport; no real API requests."""

import json
import logging
from types import SimpleNamespace

import pytest

genai = pytest.importorskip("google.genai")
httpx = pytest.importorskip("httpx")

from codeshield.agent.providers import GeminiProvider, ProviderFailure
from codeshield.agent.sanitizer import sanitize
from codeshield.agent.verifier import Verifier, uncertain
from codeshield.cli import main
from codeshield.config import Config
from codeshield.models import Classification, Provider
from codeshield.scanner import scan

SECRET = "SyntheticVerificationSentinel9_qZ!"  # codeshield: test-fixture
OTHER = "SyntheticUnrelatedSentinel3_wX!"
KEY = "SYNTHETIC_GEMINI_KEY_12345"


def response_body(decision=None, *, finish="STOP", parts=None):
    return {"candidates": [{"content": {"role": "model", "parts": parts if parts is not None else
            [{"text": json.dumps(decision or {"classification": "likely_secret", "reason": "credential_context", "recommendation": "review_and_rotate"})}]},
            "finishReason": finish}]}


@pytest.fixture
def intercepted_sdk(monkeypatch):
    original = genai.Client
    requests, options, queue = [], [], []

    def handle(request):
        requests.append(request)
        # Even a malicious transport's logs must not expose headers/exception payloads.
        logging.getLogger("google.genai.test").critical("private transport value %s", KEY)
        if not queue:
            raise AssertionError("Unexpected SDK request")
        outcome = queue.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        status, body = outcome
        return httpx.Response(status, json=body)

    def factory(**kwargs):
        options.append(kwargs)
        http_options = kwargs["http_options"].model_copy(update={
            "httpx_client": httpx.Client(transport=httpx.MockTransport(handle), trust_env=False),
        })
        return original(**(kwargs | {"http_options": http_options}))

    monkeypatch.setattr(genai, "Client", factory)
    monkeypatch.setenv("GEMINI_API_KEY", KEY)
    return SimpleNamespace(requests=requests, options=options, queue=queue)


def test_official_sdk_request_is_sanitized_schema_bound_and_tools_disabled(tmp_path, intercepted_sdk, caplog):
    intercepted_sdk.queue.append((200, response_body()))
    context = sanitize("sensitive-file.py", f'password="{SECRET}"; unrelated="{OTHER}"', "secret-assignment")
    provider = GeminiProvider(Config(provider="gemini"), tmp_path)
    try:
        decision = provider.assess(context, 2)
    finally:
        provider.close()
    assert decision.classification == Classification.LIKELY_SECRET
    request = intercepted_sdk.requests[0]
    payload = request.content.decode()
    assert all(value not in payload for value in (SECRET, OTHER, KEY, "sensitive-file.py"))
    assert "REDACTED_SECRET_1" in payload
    body = json.loads(payload)
    assert body["generationConfig"]["responseMimeType"] == "application/json"
    assert "responseJsonSchema" in body["generationConfig"]
    assert not body.get("tools")
    assert intercepted_sdk.options[0]["http_options"].retry_options.attempts == 1
    assert request.url.host == "generativelanguage.googleapis.com"
    assert request.headers["x-goog-api-key"] == KEY
    assert request.extensions["timeout"]["read"] <= 2
    assert KEY not in caplog.text


@pytest.mark.parametrize("body", [
    response_body({"classification": "likely_secret", "reason": SECRET, "recommendation": "review_and_rotate"}),
    response_body({"classification": "false_positive", "reason": "public_example", "recommendation": "manual_review", "raw": SECRET}),
    response_body(finish="MAX_TOKENS"),
    {"candidates": []},
    response_body(parts=[{"text": "not JSON"}]),
    response_body(parts=[{"functionCall": {"name": "run_shell", "args": {"command": SECRET}}}]),
], ids=["unsafe-reason", "extra-field", "truncated", "refusal", "malformed", "tool-call"])
def test_malformed_refused_or_tool_response_is_rejected(tmp_path, intercepted_sdk, body, caplog):
    intercepted_sdk.queue.append((200, body))
    provider = GeminiProvider(Config(provider="gemini"), tmp_path)
    try:
        with pytest.raises(ProviderFailure) as exc:
            provider.assess(sanitize("app.py", "", "secret-assignment"), 1)
    finally:
        provider.close()
    assert exc.value.kind == "invalid_response"
    assert SECRET not in str(exc.value) and KEY not in caplog.text


def test_sdk_rate_limits_retry_once_per_budget_and_never_log_payload(tmp_path, intercepted_sdk, monkeypatch, caplog):
    sleeps = []
    monkeypatch.setattr("codeshield.agent.verifier.time.sleep", sleeps.append)
    intercepted_sdk.queue.extend([
        (429, {"error": {"code": 429, "message": KEY + SECRET, "status": "RESOURCE_EXHAUSTED"}}),
        (503, {"error": {"code": 503, "message": KEY, "status": "UNAVAILABLE"}}),
        (200, response_body()),
    ])
    config = Config(provider="gemini")
    provider = GeminiProvider(config, tmp_path)
    try:
        result = Verifier(provider, config, None).assess(sanitize("app.py", "", "secret-assignment"))
    finally:
        provider.close()
    assert result[1] == "ok"
    assert len(intercepted_sdk.requests) == 3 and sleeps == [1, 2]
    assert KEY not in caplog.text and SECRET not in caplog.text


@pytest.mark.parametrize("status", [400, 401, 403])
def test_nonretryable_errors_are_uncertain_and_safe(tmp_path, intercepted_sdk, status, caplog):
    intercepted_sdk.queue.append((status, {"error": {"code": status, "message": KEY + SECRET, "status": "INVALID_ARGUMENT"}}))
    config = Config(provider="gemini")
    provider = GeminiProvider(config, tmp_path)
    try:
        decision, state, cached = Verifier(provider, config, None).assess(sanitize("app.py", "", "secret-assignment"))
    finally:
        provider.close()
    assert decision == uncertain() and state == "provider_error" and not cached
    assert len(intercepted_sdk.requests) == 1
    assert KEY not in caplog.text and SECRET not in caplog.text


def test_scanner_live_transport_never_receives_staged_or_unrelated_literals_and_caches(git_repo, intercepted_sdk):
    root, git, write = git_repo
    write("app.py", f'password="{SECRET}"; unrelated="{OTHER}"\n')
    git("add", ".")
    intercepted_sdk.queue.append((200, response_body()))
    config = Config(provider="gemini")
    first = scan(config, cwd=root, live_enabled=True)
    second = scan(config, cwd=root, live_enabled=True)
    assert first.provider == Provider.GEMINI
    assert first.verification_model == config.gemini_model
    assert first.findings[0].assessment_source == Provider.GEMINI
    assert not first.findings[0].verification.cached and second.findings[0].verification.cached
    assert len(intercepted_sdk.requests) == 1
    output = first.model_dump_json() + second.model_dump_json()
    output += (root / ".codeshield/verification-cache.json").read_text()
    assert all(value not in output for value in (SECRET, OTHER, KEY))


def test_model_false_positive_does_not_remove_blocking_staged_finding(git_repo, intercepted_sdk):
    root, git, write = git_repo
    write("app.py", f'password="{SECRET}"\n')
    git("add", ".")
    intercepted_sdk.queue.append((200, response_body({"classification": "false_positive", "reason": "public_example", "recommendation": "review_false_positive"})))
    result = scan(Config(provider="gemini"), cwd=root, live_enabled=True)
    assert result.summary.blocking == 1 and len(result.findings) == 1
    assert result.findings[0].verification.decision.classification == "false_positive"
    assert not result.findings[0].verification.fix_allowed


def test_intercepted_sdk_verification_to_explicit_offline_remediation(git_repo, intercepted_sdk):
    from codeshield.agent.workflow import plan_fix
    from codeshield.remediation.patcher import apply_plan
    root, git, write = git_repo
    write("app.py", f'API_KEY="{SECRET}"\n')  # codeshield: test-fixture
    git("add", ".")
    intercepted_sdk.queue.append((200, response_body()))
    report = scan(Config(provider="gemini"), cwd=root, live_enabled=True)
    finding, = report.findings
    assert finding.assessment_source == Provider.GEMINI and not finding.verification.fix_allowed
    plan = plan_fix(finding.finding_id, Config(), cwd=root)
    preview = plan.preview()
    result = apply_plan(plan, approved=True)
    assert len(intercepted_sdk.requests) == 1  # Planning/apply never initiate another provider call.
    payload = intercepted_sdk.requests[0].content.decode()
    assert all(value not in report.model_dump_json() + preview + result + payload for value in (SECRET, OTHER, KEY))
    assert scan(Config(), cwd=root).summary.blocking == 1
    git("add", "app.py")
    assert scan(Config(), cwd=root).summary.blocking == 0


def test_cli_api_failure_reports_uncertain_and_exits_three(git_repo, intercepted_sdk, monkeypatch, capsys):
    root, git, write = git_repo
    write("app.py", f'password="{SECRET}"\n')
    git("add", ".")
    intercepted_sdk.queue.append((403, {"error": {"code": 403, "message": KEY + SECRET, "status": "PERMISSION_DENIED"}}))
    monkeypatch.chdir(root)
    assert main(["scan", "--provider", "gemini", "--allow-live", "--format", "json"]) == 3
    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert report["validation_status"] == "failed" and report["summary"]["blocking"] == 1
    assert report["findings"][0]["verification"]["decision"]["classification"] == "uncertain"
    assert all(value not in captured.out + captured.err for value in (SECRET, OTHER, KEY))
    assert "sanitized structural context" in captured.err


def test_empty_scan_does_not_initialize_sdk_or_load_credentials(git_repo, monkeypatch):
    root, git, write = git_repo
    monkeypatch.setattr(genai, "Client", lambda **kwargs: pytest.fail("No client should be initialized"))
    monkeypatch.setattr("codeshield.agent.providers.load_api_key", lambda *args: pytest.fail("No key should be read"))
    result = scan(Config(provider="gemini"), cwd=root, live_enabled=True)
    assert not result.findings


def test_sdk_timeout_retry_is_bounded(tmp_path, intercepted_sdk, monkeypatch):
    monkeypatch.setattr("codeshield.agent.verifier.time.sleep", lambda delay: None)
    intercepted_sdk.queue.extend([httpx.ReadTimeout(KEY), (200, response_body())])
    config = Config(provider="gemini", api_max_retries=1)
    provider = GeminiProvider(config, tmp_path)
    try:
        assert Verifier(provider, config, None).assess(sanitize("a.py", "", "secret-assignment"))[1] == "ok"
    finally:
        provider.close()
    assert len(intercepted_sdk.requests) == 2


def test_distinct_contexts_respect_shared_live_call_budget(git_repo, intercepted_sdk):
    root, git, write = git_repo
    write("app.py", f'password="{SECRET}"\nheaders={{"Authorization": "Bearer {OTHER}"}}\n')
    git("add", ".")
    intercepted_sdk.queue.append((200, response_body()))
    result = scan(Config(provider="gemini", max_api_calls=1), cwd=root, live_enabled=True)
    assert result.validation_status == "failed" and result.summary.blocking == 2
    assert len(intercepted_sdk.requests) == 1
    assert result.findings[1].verification.status == "budget_exhausted"


def test_cache_hits_do_not_read_credentials_or_initialize_sdk(git_repo, intercepted_sdk, monkeypatch):
    root, git, write = git_repo
    write("app.py", f'password="{SECRET}"\n')
    git("add", ".")
    intercepted_sdk.queue.append((200, response_body()))
    scan(Config(provider="gemini"), cwd=root, live_enabled=True)
    monkeypatch.setattr(genai, "Client", lambda **kwargs: pytest.fail("Cache hit cannot initialize a client"))
    monkeypatch.setattr("codeshield.agent.providers.load_api_key", lambda *args: pytest.fail("Cache hit cannot read a key"))
    result = scan(Config(provider="gemini"), cwd=root, live_enabled=True)
    assert result.findings[0].verification.cached


def test_endpoint_and_other_provider_environment_cannot_redirect_requests(tmp_path, intercepted_sdk, monkeypatch):
    monkeypatch.setenv("GOOGLE_GEMINI_BASE_URL", "https://synthetic-untrusted.invalid")
    monkeypatch.setenv("GOOGLE_API_KEY", "SYNTHETIC_OTHER_KEY_98765")
    monkeypatch.setenv("HTTPS_PROXY", "https://synthetic-proxy.invalid")
    intercepted_sdk.queue.append((200, response_body()))
    provider = GeminiProvider(Config(provider="gemini"), tmp_path)
    try:
        provider.assess(sanitize("a.py", "", "secret-assignment"), 1)
    finally:
        provider.close()
    assert intercepted_sdk.requests[0].url.host == "generativelanguage.googleapis.com"
    assert intercepted_sdk.requests[0].headers["x-goog-api-key"] == KEY
    assert not intercepted_sdk.options[0]["http_options"].client_args["trust_env"]
