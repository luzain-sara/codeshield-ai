"""Project code into a finite vocabulary. No original code bytes cross this boundary."""

from pathlib import PurePosixPath
import re
from typing import Literal

from codeshield.models import Contract


class SafeContext(Contract):
    version: Literal["1"] = "1"
    language: Literal["python", "javascript", "json", "yaml", "env", "unknown"]
    operation: Literal["credential_assignment", "authorization_header", "known_prefix", "contextual_entropy", "custom_pattern"]
    code: Literal['credential = "<REDACTED_SECRET_1>"',
                  'Authorization: "Bearer <REDACTED_SECRET_1>"',
                  'literal = "<REDACTED_SECRET_1>"']
    framework: Literal["python_server", "node_server", "browser", "unknown"]
    example_context: bool
    environment_lookup: bool
    comparison_context: bool


def sanitize(path: str, code_context: str, rule_id: str) -> SafeContext:
    """Original literals, identifiers, comments, paths and regex expressions are omitted.

    This deliberately lossy projection also removes sensitive strings the detector
    did not recognize. Model quality cannot weaken the local privacy boundary.
    """
    suffix = PurePosixPath(path).suffix.lower()
    language = ({".py": "python", ".js": "javascript", ".jsx": "javascript",
                 ".ts": "javascript", ".tsx": "javascript", ".json": "json",
                 ".yaml": "yaml", ".yml": "yaml"}.get(suffix, "unknown"))
    if PurePosixPath(path).name.lower().startswith(".env"):
        language = "env"
    if rule_id == "secret-assignment":
        operation, code = "credential_assignment", 'credential = "<REDACTED_SECRET_1>"'
    elif rule_id == "authorization-header":
        operation, code = "authorization_header", 'Authorization: "Bearer <REDACTED_SECRET_1>"'
    elif rule_id == "high-entropy-secret":
        operation, code = "contextual_entropy", 'literal = "<REDACTED_SECRET_1>"'
    elif rule_id.startswith("custom-"):
        operation, code = "custom_pattern", 'literal = "<REDACTED_SECRET_1>"'
    else:
        operation, code = "known_prefix", 'literal = "<REDACTED_SECRET_1>"'
    # Derive hints from syntax, not the contents of quoted credentials/literals.
    structure = re.sub(r'''(["'`])(?:\\.|(?!\1).)*\1''', "<literal>", code_context)
    if language in ("env", "yaml", "json"):
        structure = ""
    lowered = structure.lower()
    parts = {part.lower() for part in PurePosixPath(path).parts[:-1]}
    browser = suffix in (".jsx", ".tsx") or any(token in lowered for token in ("next_public_", "vite_", "window.", "document."))
    framework = ("browser" if browser else "python_server" if language == "python" else
                 "node_server" if language == "javascript" and "process.env" in lowered else "unknown")
    return SafeContext(
        language=language, operation=operation, code=code, framework=framework,
        example_context=bool(parts & {"tests", "test", "fixtures", "examples", "samples"}),
        environment_lookup=any(token in lowered for token in ("os.environ", "os.getenv", "process.env")),
        comparison_context="==" in structure or "!=" in structure,
    )
