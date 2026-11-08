"""Render sanitized contracts. Never accept source contents or raw candidates."""

import os
from pathlib import Path

from codeshield.errors import ScanError
from codeshield.models import ScanResult
from codeshield.scanner import is_link


def render(result: ScanResult, format: str) -> str:
    if format == "json":
        return result.model_dump_json(indent=2) + "\n"
    lines = [f"Scope: {result.scan_scope.value}; provider: rules (offline)",
             f"Files scanned: {result.files_scanned}; skipped: {len(result.skipped_files)}",
             f"Findings: {result.summary.total}; blocking: {result.summary.blocking}"]
    for finding in result.findings:
        lines.append(f"{finding.path}:{finding.line}:{finding.column} [{finding.severity.value}] "
                     f"{finding.rule_id} confidence={finding.confidence:.2f} source=rules id={finding.finding_id}")
        lines.append(f"  {finding.redacted_sample} | {finding.recommendation}")
    for skipped in result.skipped_files:
        lines.append(f"Skipped: {skipped.path} ({skipped.reason})")
    lines.append("Only the selected scope and supported files were checked; this is not a security guarantee.")
    return "\n".join(lines) + "\n"


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
