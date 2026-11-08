from datetime import datetime, timezone
from io import StringIO
import json
import os
from uuid import uuid4

import pytest

from codeshield.models import Finding, ScanResult, Summary, Verification, Decision, ScanScope, SkippedFile
from codeshield.reporting import render
from codeshield.terminal import render_notice, render_plan, terminal_options


def result(*, severity="high", blocking=1, status="passed", verification_status="ok", classification="likely_secret"):
    now = datetime.now(timezone.utc)
    decision = Decision(classification=classification, reason="credential_context", recommendation="review_and_rotate")
    finding = Finding(finding_id="a" * 24, rule_id="secret-assignment", path="src/service.py", line=7, column=4,
                      severity=severity, confidence=0.85, assessment_source="mock", redacted_sample="<REDACTED_SECRET>",
                      evidence=("Credential-named literal assignment",), recommendation="Rotate exposed credentials; review a safe local fix.",
                      verification=Verification(decision=decision, requested_provider="mock", source="mock", status=verification_status))
    return ScanResult(run_id=uuid4(), scan_scope="staged", started_at=now, finished_at=now, tool_version="0.1.0",
                      provider="mock", findings=(finding,), summary=Summary(total=1, blocking=blocking),
                      validation_status=status, files_scanned=2)


def test_numbered_panels_include_safe_metadata_evidence_and_gate():
    scan = result()
    scan = scan.model_copy(update={"findings": (scan.findings[0], scan.findings[0].model_copy(update={"finding_id": "b"*24})),
                                   "summary": Summary(total=2, blocking=2)})
    text = render(scan, "human")
    for value in ("CodeShield-AI", "Scope: staged", "provider: mock", "Scan summary", "Files scanned:", "Skipped files:",
                  "Total findings:", "Blocking findings:", "Finding 1 | HIGH", "Finding 2 | HIGH", "src/service.py:7:4",
                  "secret-assignment", "85%", "Source:", "mock", "likely_secret", "a"*24, "b"*24,
                  "Evidence: <REDACTED_SECRET>", "Credential-named literal assignment", "Explanation:", "Next:", "Security gate: BLOCKED"):
        assert value in text
    assert "\x1b" not in text and "not a security" in text


@pytest.mark.parametrize("status,blocking,expected", [("passed", 0, "PASS"), ("passed", 1, "BLOCKED"),
                                                     ("failed", 0, "ERROR"), ("failed", 1, "ERROR"), ("not_run", 0, "ERROR")])
def test_gate_does_not_claim_success_when_validation_incomplete(status, blocking, expected):
    text = render(result(status=status, blocking=blocking), "human")
    assert "Security gate: " + expected in text
    if expected != "PASS":
        assert "Security gate: PASS" not in text


@pytest.mark.parametrize("severity,escape", [("critical", "\x1b[1;31m"), ("high", "\x1b[31m"),
                                           ("medium", "\x1b[33m"), ("low", "\x1b[36m")])
def test_severity_color_and_text_labels(severity, escape):
    text = render(result(severity=severity), "human", color=True, ascii_box=False)
    assert escape in text and severity.upper() in text


@pytest.mark.parametrize("width", [24, 40, 64, 88, 120])
def test_narrow_reports_fold_long_paths_and_never_overflow(width):
    scan = result()
    finding = scan.findings[0].model_copy(update={"path": "very_long_directory/" * 8 + "[red]file.py"})
    text = render(scan.model_copy(update={"findings": (finding,)}), "human", width=width)
    assert all(len(line) <= min(96, width) for line in text.splitlines())
    assert "[red]file.py" in "".join(text.splitlines()).replace(" ", "").replace("|", "")
    assert "a"*24 in "".join(text.splitlines()).replace(" ", "").replace("|", "")
    assert "BLOCKED" in text


def test_json_serialization_is_byte_identical_and_does_not_call_rich(monkeypatch):
    scan = result()
    before = scan.model_dump_json()
    render(scan, "human")
    assert scan.model_dump_json() == before
    def deny(*args, **kwargs):
        raise AssertionError("JSON must never use terminal rendering")
    monkeypatch.setattr("codeshield.terminal.render_scan", deny)
    text = render(scan, "json", color=True, width=24, ascii_box=False)
    assert text == scan.model_dump_json(indent=2) + "\n"
    assert json.loads(text)["schema_version"] == "1" and "\x1b" not in text


def test_sample_is_fixed_and_metadata_is_not_rich_markup_or_terminal_control():
    scan = result()
    finding = scan.findings[0].model_copy(update={"redacted_sample": "PRIVATE_SAMPLE_MUST_NOT_APPEAR",
                                                "path": "[bold]file.py\x1b[31m"})
    text = render(scan.model_copy(update={"findings": (finding,)}), "human")
    assert "PRIVATE_SAMPLE_MUST_NOT_APPEAR" not in text
    assert "[bold]file.py" in text and "\x1b" not in text


class Stream(StringIO):
    def __init__(self, tty, encoding="utf-8"):
        super().__init__()
        self.tty, self.codec = tty, encoding

    def isatty(self):
        return self.tty

    @property
    def encoding(self):
        return self.codec


@pytest.mark.parametrize("environment", [{"NO_COLOR": ""}, {"TERM": "dumb"}, {"CLICOLOR": "0"}])
def test_terminal_color_preferences_are_honored(monkeypatch, environment):
    for key, value in environment.items():
        monkeypatch.setenv(key, value)
    options = terminal_options(stream=Stream(True))
    assert not options["color"]
    assert "\x1b" not in render(result(), "human", **options)


def test_non_tty_ignores_forced_color_and_legacy_encoding_gets_ascii(monkeypatch):
    monkeypatch.setenv("FORCE_COLOR", "1")
    monkeypatch.setenv("CLICOLOR_FORCE", "1")
    assert not terminal_options(stream=Stream(False))["color"]
    options = terminal_options(no_color=True, stream=Stream(True, "cp1252"))
    assert options["ascii_box"]
    render(result(), "human", **options).encode("cp1252")


def test_terminal_width_is_bounded_and_explicit_no_color_wins(monkeypatch):
    monkeypatch.setattr("codeshield.terminal.shutil.get_terminal_size", lambda **kwargs: os.terminal_size((200, 24)))
    options = terminal_options(no_color=True, stream=Stream(True))
    assert options["width"] == 96 and not options["color"]


def test_false_positive_advice_does_not_change_gate_and_failures_remain_errors():
    assert "Security gate: BLOCKED" in render(result(classification="false_positive"), "human")
    text = render(result(status="failed", verification_status="provider_error"), "human")
    assert "provider_error" in text and "Security gate: ERROR" in text


def test_plan_and_decline_are_never_presented_as_clean_security_gates():
    text = render_plan('- <credential> = "<REDACTED_SECRET>"\n+ <credential> = os.environ["API_KEY"]\n')
    assert "Remediation plan | PREVIEW" in text and "<REDACTED_SECRET>" in text
    assert "Security gate: PASS" not in text
    assert "DECLINED" in render_notice("No files changed.", "Approval result: DECLINED")


@pytest.mark.parametrize("encoding", ["ascii", "cp1252", "utf-8"])
def test_unicode_paths_are_readable_in_legacy_encodings_without_overflow(encoding):
    scan = result()
    finding = scan.findings[0].model_copy(update={"path": "caf\u00e9/\u6587\u4ef6.py"})
    text = render(scan.model_copy(update={"findings": (finding,)}), "human", encoding=encoding)
    text.encode(encoding)
    assert "Security gate: BLOCKED" in text
    assert all(len(line) <= 88 for line in text.splitlines())


@pytest.mark.parametrize("scope", list(ScanScope))
def test_scope_and_skipped_files_are_disclosed(scope):
    scan = result().model_copy(update={"scan_scope": scope, "skipped_files": (
        SkippedFile(path="vendor/library.py", reason="protected_directory"),
        SkippedFile(path="image.py", reason="binary"))})
    text = render(scan, "human")
    assert "Scope: " + scope.value in text
    assert "Skipped files:" in text and "coverage reduced" in text
    assert "vendor/library.py (protected_directory)" in text and "image.py (binary)" in text
