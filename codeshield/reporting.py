"""Render sanitized contracts. Never accept source contents or raw candidates."""

import os
from pathlib import Path

from codeshield.errors import ScanError
from codeshield.models import ScanResult
from codeshield.scanner import is_link


def render(result: ScanResult, format: str, **terminal_options) -> str:
    if format == "json":
        return result.model_dump_json(indent=2) + "\n"
    from codeshield.terminal import render_scan
    return render_scan(result, **terminal_options)


def write_report(path: Path, report: str):
    """Exclusive creation protects sources and existing reports from accidental overwrite."""
    absolute = Path(os.path.abspath(path))
    if any(part.casefold() == ".git" for part in absolute.parts):
        raise ScanError("Report destination must be outside Git metadata.")
    if any(is_link(parent) for parent in (absolute, *absolute.parents)):
        raise ScanError("Report destination must not traverse links.")
    try:
        with path.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(report)
    except OSError:
        raise ScanError("Report could not be created; use a new writable destination.") from None
