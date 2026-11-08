from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError

from codeshield.models import Finding, ScanResult, Summary


def finding(**changes):
    values = dict(
        finding_id="example-id", rule_id="example-rule", path="example.py", line=1,
        severity="high", confidence=0.9, assessment_source="rules",
        redacted_sample="<REDACTED_SECRET_1>", recommendation="Review locally.",
    )
    return Finding(**(values | changes))


def test_result_json_roundtrip():
    now = datetime.now(timezone.utc)
    result = ScanResult(
        run_id=uuid4(), scan_scope="staged", started_at=now, finished_at=now,
        tool_version="0.1.0", provider="rules", findings=(finding(),),
        summary=Summary(total=1, blocking=1),
    )
    assert ScanResult.model_validate_json(result.model_dump_json()) == result
    assert result.validation_status == "not_run"


@pytest.mark.parametrize("changes", [
    {"line": 0}, {"confidence": 1.1}, {"confidence": float("nan")},
    {"severity": "urgent"}, {"assessment_source": "imaginary"},
    {"raw_secret": "FAKE_MODEL_SENTINEL"},
])
def test_invalid_findings_are_rejected(changes):
    with pytest.raises(ValidationError) as exc:
        finding(**changes)
    assert "FAKE_MODEL_SENTINEL" not in str(exc.value)


@pytest.mark.parametrize("changes", [
    {"summary": Summary(total=1)},
    {"started_at": datetime(2026, 1, 1)},
    {"finished_at": datetime(2026, 1, 1, tzinfo=timezone.utc) - timedelta(days=1)},
])
def test_inconsistent_results_are_rejected(changes):
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    values = dict(run_id=uuid4(), scan_scope="staged", started_at=now,
                  finished_at=now, tool_version="0.1.0", provider="rules")
    with pytest.raises(ValidationError):
        ScanResult(**(values | changes))


def test_invalid_summary_is_rejected():
    with pytest.raises(ValidationError):
        Summary(total=0, blocking=1)
