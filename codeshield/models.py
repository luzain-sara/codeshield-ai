"""Validated public contracts. Callers must sanitize text before constructing results."""

from datetime import datetime
from enum import IntEnum, StrEnum
from uuid import UUID

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
    findings: tuple[Finding, ...] = ()
    summary: Summary = Field(default_factory=Summary)
    validation_status: ValidationStatus = ValidationStatus.NOT_RUN
    files_scanned: int = Field(default=0, ge=0, strict=True)
    skipped_files: tuple[SkippedFile, ...] = ()

    @model_validator(mode="after")
    def check_consistency(self) -> "ScanResult":
        if self.started_at.utcoffset() is None or self.finished_at.utcoffset() is None:
            raise ValueError("Timestamps must include timezones")
        if self.finished_at < self.started_at:
            raise ValueError("Finish precedes start")
        if self.summary.total != len(self.findings):
            raise ValueError("Summary does not match findings")
        return self
