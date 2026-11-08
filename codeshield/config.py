"""Load local TOML configuration without reading environment files or API keys."""

import tomllib
from pathlib import Path

import regex
from pydantic import Field, ValidationError, model_validator

from codeshield.models import Contract, Provider, Severity

DEFAULT_CONFIG_NAME = "codeshield.toml"


class ConfigError(ValueError):
    """Safe diagnostic suitable for display without including configuration values."""


class DetectionPattern(Contract):
    rule_id: str = Field(pattern=r"^[a-z][a-z0-9-]{0,63}$")
    expression: str = Field(min_length=1, max_length=512)
    severity: Severity = Severity.HIGH

    @model_validator(mode="after")
    def check_expression(self) -> "DetectionPattern":
        try:
            compiled = regex.compile(self.expression, regex.VERSION0)
            if "secret" not in compiled.groupindex or compiled.search("", timeout=0.05):
                raise ValueError("Pattern requires a nonempty named secret group")
        except (regex.error, TimeoutError):
            raise ValueError("Invalid detection pattern") from None
        return self


class Config(Contract):
    provider: Provider = Provider.MOCK
    blocking_severity: Severity = Severity.HIGH
    max_file_bytes: int = Field(default=1_048_576, gt=0, strict=True)
    max_scan_bytes: int = Field(default=10_485_760, gt=0, strict=True)
    git_timeout_seconds: int = Field(default=10, ge=1, le=300, strict=True)
    scan_timeout_seconds: int = Field(default=60, ge=1, le=3600, strict=True)
    max_files: int = Field(default=10000, ge=1, le=100000, strict=True)
    max_findings: int = Field(default=1000, ge=1, le=100000, strict=True)
    entropy_threshold: float = Field(default=3.5, ge=0, le=8, allow_inf_nan=False)
    entropy_min_length: int = Field(default=20, ge=8, le=4096, strict=True)
    min_secret_length: int = Field(default=8, ge=4, le=4096, strict=True)
    patterns: tuple[DetectionPattern, ...] = Field(default=(), max_length=32)
    gemini_model: str = Field(default="gemini-3.5-flash-lite", pattern=r"^gemini-[a-z0-9.-]{1,80}$")
    verification_timeout_seconds: int = Field(default=60, ge=1, le=300, strict=True)
    api_timeout_seconds: int = Field(default=10, ge=1, le=30, strict=True)
    max_api_calls: int = Field(default=5, ge=0, le=100, strict=True)
    api_max_retries: int = Field(default=2, ge=0, le=3, strict=True)
    api_backoff_seconds: float = Field(default=1, ge=0, le=5, allow_inf_nan=False)
    verification_cache_ttl_seconds: int = Field(default=86400, ge=0, le=604800, strict=True)
    exclude_dirs: tuple[str, ...] = (
        ".git", ".venv", "node_modules", "vendor", "dist", "build"
    )

    @model_validator(mode="after")
    def check_limits(self) -> "Config":
        if self.max_scan_bytes < self.max_file_bytes:
            raise ValueError("Scan limit must cover at least one file")
        if len({p.rule_id for p in self.patterns}) != len(self.patterns):
            raise ValueError("Duplicate pattern identifiers")
        return self


def load_config(path: Path | None = None) -> Config:
    """Missing implicit config uses defaults; missing explicit config is an error."""
    target = path if path is not None else Path(DEFAULT_CONFIG_NAME)
    try:
        with target.open("rb") as stream:
            data = tomllib.load(stream)
        return Config.model_validate(data)
    except FileNotFoundError:
        if path is None:
            return Config()
        raise ConfigError("Explicit configuration file was not found.") from None
    except (OSError, ValueError, ValidationError):
        # Parser and schema exceptions may contain user-supplied secrets.
        raise ConfigError("Configuration is unreadable or invalid; check the documented schema.") from None
