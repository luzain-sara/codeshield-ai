"""Load local TOML configuration without reading environment files or API keys."""

import tomllib
from pathlib import Path

from pydantic import Field, ValidationError, model_validator

from codeshield.models import Contract, Provider, Severity

DEFAULT_CONFIG_NAME = "codeshield.toml"


class ConfigError(ValueError):
    """Safe diagnostic suitable for display without including configuration values."""


class Config(Contract):
    provider: Provider = Provider.RULES
    blocking_severity: Severity = Severity.HIGH
    max_file_bytes: int = Field(default=1_048_576, gt=0, strict=True)
    max_scan_bytes: int = Field(default=10_485_760, gt=0, strict=True)
    git_timeout_seconds: int = Field(default=10, ge=1, le=300, strict=True)
    exclude_dirs: tuple[str, ...] = (
        ".git", ".venv", "node_modules", "vendor", "dist", "build"
    )

    @model_validator(mode="after")
    def check_limits(self) -> "Config":
        if self.max_scan_bytes < self.max_file_bytes:
            raise ValueError("Scan limit must cover at least one file")
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
