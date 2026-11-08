"""Human-only presentation of sanitized metadata, never source or private plans."""

from io import StringIO
from functools import partial
import os
import re
import shutil
import sys

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from codeshield.models import ScanResult

SEVERITY_STYLES = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "cyan"}


def terminal_options(no_color=False, stream=None):
    stream = stream if stream is not None else sys.stdout
    try:
        tty = stream.isatty()
    except (AttributeError, OSError):
        tty = False
    color = bool(tty and not no_color and "NO_COLOR" not in os.environ
                 and os.environ.get("TERM") != "dumb" and os.environ.get("CLICOLOR") != "0")
    ascii_box = not tty or os.environ.get("TERM") == "dumb"
    encoding = getattr(stream, "encoding", None) or "utf-8"
    try:
        "\u250c\u2500\u2510".encode(encoding)
    except (UnicodeError, LookupError):
        ascii_box = True
    width = shutil.get_terminal_size(fallback=(88, 24)).columns if tty else 88
    return {"color": color, "width": max(12, min(96, width)), "ascii_box": ascii_box, "encoding": encoding}


def encodable(value: str, encoding="utf-8") -> str:
    try:
        return value.encode(encoding, errors="backslashreplace").decode(encoding)
    except LookupError:
        return value.encode("ascii", errors="backslashreplace").decode("ascii")


def literal(value: str, style="", encoding="utf-8") -> Text:
    # Rich markup is never parsed; terminal controls cannot become executable output.
    clean = re.sub(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]", "", value)
    return Text(encodable(clean, encoding), style=style, overflow="fold")


def canvas(width=88, color=False, ascii_box=True, encoding="utf-8"):
    output = StringIO()
    console = Console(file=output, width=max(12, min(96, width)), force_terminal=color,
                      color_system="standard" if color else None, no_color=not color,
                      markup=False, highlight=False, emoji=False, legacy_windows=False)
    try:
        "\u250c\u2500\u2510".encode(encoding)
    except (UnicodeError, LookupError):
        ascii_box = True
    return output, console, box.ASCII if ascii_box else box.SQUARE


def fields(rows, encoding="utf-8"):
    table = Table.grid(padding=(0, 1), expand=True)
    table.add_column(style="dim")
    table.add_column(ratio=1, overflow="fold")
    for key, value in rows:
        style = SEVERITY_STYLES.get(value.lower(), "") if key == "Severity" else ""
        table.add_row(literal(key + ":", encoding=encoding), literal(value.replace("\n", " "), style, encoding))
    return table


def explanation(finding):
    verification = finding.verification
    if verification and verification.status != "ok":
        return "Verification is incomplete. The finding remains unresolved."
    if verification and verification.decision.classification == "false_positive":
        return "The verifier suggests a false positive; deterministic blocking policy is unchanged."
    if verification and verification.decision.classification == "uncertain":
        return "Verification is uncertain. Review the finding locally."
    return "A credential-like literal was detected. Verification is advisory and cannot authorize a fix."


def render_scan(result: ScanResult, *, width=88, color=False, ascii_box=True, encoding="utf-8") -> str:
    output, console, border = canvas(width, color, ascii_box, encoding)
    text = partial(literal, encoding=encoding)
    console.print(text("CodeShield-AI", "bold cyan"))
    console.print(text(f"Scope: {result.scan_scope.value}  |  provider: {result.provider.value}"))
    if result.verification_model:
        console.print(text(f"Verification model: {result.verification_model}", "dim"))
    console.print()
    summary = fields([("Files scanned", str(result.files_scanned)), ("Skipped files", str(len(result.skipped_files))),
                      ("Total findings", str(result.summary.total)), ("Blocking findings", str(result.summary.blocking))], encoding)
    console.print(Panel(summary, title=text("Scan summary", "bold"), title_align="left", box=border, padding=(0, 1)))
    for number, finding in enumerate(result.findings, 1):
        verification = finding.verification
        status = (f"{verification.status} | {verification.decision.classification.value} | cached={str(verification.cached).lower()}"
                  if verification else "not run")
        metadata = fields([("Severity", finding.severity.value.upper()),
                           ("Location", f"{finding.path}:{finding.line}:{finding.column}"),
                           ("Rule", finding.rule_id), ("Confidence", f"{finding.confidence:.0%}"),
                           ("Source", finding.assessment_source.value), ("Verification", status),
                           ("Finding ID", finding.finding_id)], encoding)
        detail = text("Evidence: <REDACTED_SECRET>\nDetection: " + "; ".join(finding.evidence)
                         + "\nExplanation: " + explanation(finding)
                         + "\nNext: " + finding.recommendation)
        console.print()
        console.print(Panel(Group(metadata, text(""), detail),
                            title=text(f"Finding {number} | {finding.severity.value.upper()}", "bold"),
                            title_align="left", border_style=SEVERITY_STYLES[finding.severity.value],
                            box=border, padding=(0, 1)))
    if result.skipped_files:
        console.print()
        console.print(text("Skipped files (coverage reduced)", "bold"))
        for skipped in result.skipped_files:
            console.print(text(f"  {skipped.path} ({skipped.reason})"))
    console.print()
    if result.validation_status != "passed":
        gate, style = "ERROR", "bold red"
        message = "Verification did not complete. Findings remain unresolved; no fixes are authorized."
    elif result.summary.blocking:
        gate, style = "BLOCKED", "bold yellow"
        message = "Blocking findings remain. Review locally, remediate safely, and rescan staged changes."
    else:
        gate, style = "PASS", "bold green"
        message = "No blocking findings in the selected scope."
    console.print(Panel(Group(text("Security gate: " + gate, style), text(message)),
                        border_style=style, box=border, padding=(0, 1)))
    console.print(text("Only the selected scope and supported files were checked; this is not a security guarantee.", "dim"))
    return encodable(output.getvalue(), encoding)


def render_plan(preview: str, **options) -> str:
    """Accept only Plan.preview(), never a Plan containing original/proposed bytes."""
    output, console, border = canvas(**options)
    text = partial(literal, encoding=options.get("encoding", "utf-8"))
    console.print(Panel(Group(text("Remediation plan | PREVIEW", "bold cyan"), text(preview.rstrip())),
                        box=border, padding=(0, 1)))
    return encodable(output.getvalue(), options.get("encoding", "utf-8"))


def render_notice(message: str, title: str, *, style="yellow", **options) -> str:
    output, console, border = canvas(**options)
    text = partial(literal, encoding=options.get("encoding", "utf-8"))
    console.print(Panel(Group(text(title, "bold " + style), text(message)),
                        border_style=style, box=border, padding=(0, 1)))
    return encodable(output.getvalue(), options.get("encoding", "utf-8"))
