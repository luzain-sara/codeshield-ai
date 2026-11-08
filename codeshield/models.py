"""Validated public contracts. Callers must sanitize text before constructing results."""

from datetime import datetime
from enum import IntEnum, StrEnum
from uuid import UUID
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ExitCode(IntEnum):
    SUCCESS = 0
    BLOCKING_FINDINGS = 1
    CONFIG_ERROR = 2
    VALIDATION_FAILURE = 3


class Provider(StrEnum):
    RULES = "rules"
    MOCK = "mock"
    GEMINI = "gemini"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ScanScope(StrEnum):
    STAGED = "staged"
    WORKTREE = "worktree"
    REFS = "refs"


class ValidationStatus(StrEnum):
    NOT_RUN = "not_run"
    PASSED = "passed"
    FAILED = "failed"


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)


class Classification(StrEnum):
    LIKELY_SECRET = "likely_secret"
    UNCERTAIN = "uncertain"
    FALSE_POSITIVE = "false_positive"


class DecisionReason(StrEnum):
    CREDENTIAL_CONTEXT = "credential_context"
    PUBLIC_EXAMPLE = "public_example"
    INSUFFICIENT_CONTEXT = "insufficient_context"


class Advice(StrEnum):
    REVIEW_AND_ROTATE = "review_and_rotate"
    MANUAL_REVIEW = "manual_review"
    REVIEW_FALSE_POSITIVE = "review_false_positive"


class Decision(Contract):
    classification: Classification
    reason: DecisionReason
    recommendation: Advice


class Verification(Contract):
    decision: Decision
    requested_provider: Provider
    source: Provider
    status: str = Field(pattern=r"^(ok|provider_error|invalid_response|budget_exhausted)$")
    cached: bool = False
    # Provider advice stays separate from deterministic remediation approval.
    fix_allowed: bool = Field(default=False, frozen=True)
    states: tuple[str, ...] = ()

    @model_validator(mode="after")
    def deny_fixes(self) -> "Verification":
        if self.fix_allowed:
            raise ValueError("Provider verification cannot authorize writes")
        return self


class Finding(Contract):
    """Safe metadata only; no raw match, credential, or source-content field."""

    finding_id: str = Field(min_length=1)
    rule_id: str = Field(min_length=1)
    path: str = Field(min_length=1)
    line: int = Field(ge=1, strict=True)
    column: int = Field(default=1, ge=1, strict=True)
    severity: Severity
    confidence: float = Field(ge=0, le=1, allow_inf_nan=False)
    assessment_source: Provider
    redacted_sample: str
    recommendation: str
    evidence: tuple[str, ...] = ()
    verification: Verification | None = None


class SkippedFile(Contract):
    path: str
    reason: str


class Summary(Contract):
    total: int = Field(default=0, ge=0, strict=True)
    blocking: int = Field(default=0, ge=0, strict=True)

    @model_validator(mode="after")
    def check_counts(self) -> "Summary":
        if self.blocking > self.total:
            raise ValueError("Blocking count exceeds total")
        return self


class ScanResult(Contract):
    schema_version: str = "1"
    run_id: UUID
    scan_scope: ScanScope
    started_at: datetime
    finished_at: datetime
    tool_version: str
    provider: Provider
    verification_model: str | None = Field(default=None, pattern=r"^gemini-[a-z0-9.-]{1,80}$")
    findings: tuple[Finding, ...] = ()
    summary: Summary = Field(default_factory=Summary)
    validation_status: ValidationStatus = ValidationStatus.NOT_RUN
    files_scanned: int = Field(default=0, ge=0, strict=True)
    skipped_files: tuple[SkippedFile, ...] = ()
    base_commit: str | None = Field(default=None, pattern=r"^(?:EMPTY|[0-9a-f]{40}|[0-9a-f]{64})$")
    head_commit: str | None = Field(default=None, pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
    comparison: Literal["endpoints", "merge_base"] | None = None

    @model_validator(mode="after")
    def check_consistency(self) -> "ScanResult":
        if self.started_at.utcoffset() is None or self.finished_at.utcoffset() is None:
            raise ValueError("Timestamps must include timezones")
        if self.finished_at < self.started_at:
            raise ValueError("Finish precedes start")
        if self.summary.total != len(self.findings):
            raise ValueError("Summary does not match findings")
        return self
