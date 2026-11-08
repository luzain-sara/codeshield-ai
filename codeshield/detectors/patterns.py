"""Bounded regex/entropy detection. Never expose Candidate outside the scan."""

from dataclasses import dataclass, field

import regex

from codeshield.config import Config
from codeshield.detectors.context import HASH_OR_UUID, is_placeholder, is_reference
from codeshield.detectors.entropy import shannon_entropy
from codeshield.errors import ScanError
from codeshield.models import Severity

TIMEOUT = 0.05
PREFIX_RULES = (
    ("aws-access-key", r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", Severity.CRITICAL),
    ("github-token", r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})\b", Severity.CRITICAL),
    ("google-api-key", r"\bAIza[A-Za-z0-9_-]{35}\b", Severity.HIGH),
    ("openai-api-key", r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}", Severity.HIGH),
    ("slack-token", r"\bxox[baprs]-[A-Za-z0-9-]{20,}", Severity.HIGH),
    ("stripe-secret-key", r"\bsk_live_[A-Za-z0-9]{16,}", Severity.HIGH),
)
PREFIXES = tuple((rule, regex.compile(expr), severity) for rule, expr, severity in PREFIX_RULES)
AUTH = regex.compile(r'''(?i)\b(?:proxy-)?authorization["']?\s*[:=]\s*["']?(?:bearer|basic)\s+(?P<secret>[^\s"'`,;}]+)''')
ASSIGNMENT = regex.compile(
    r'''(?P<keyquote>["']?)(?P<name>[A-Za-z_$][\w$.-]{0,100})(?P=keyquote)\s*'''
    r'''(?::\s*(?:str|bytes|string)\s*)?[:=]\s*'''
    r'''(?:(?P<quote>"{3}|'{3}|["'`])(?P<quoted>(?:\\.|(?!(?P=quote))[^\r\n])*)(?P=quote)|(?P<bare>[^\s,;}]+))'''
)
STRONG_CONTEXT = regex.compile(r"(?i)(?:password|passwd|^pwd$|secret|credential|"
                               r"(?:api|private|signing|encryption)[_.-]?key|(?:access|auth|refresh)?[_.-]?token)")
WEAK_CONTEXT = regex.compile(r"(?i)(?:auth|session|signing|private|connection)")
PUBLIC_CONTEXT = regex.compile(r"(?i)(?:public[_.-]?key|(?:client|tenant|user|project)[_.-]?id|checksum|hash|uuid)")


@dataclass(frozen=True)
class Candidate:
    start: int
    end: int
    rule_id: str
    severity: Severity
    confidence: float
    evidence: str
    value: str = field(repr=False)


class Detector:
    def __init__(self, config: Config):
        self.config = config
        self.custom = tuple((p, regex.compile(p.expression, regex.VERSION0)) for p in config.patterns)

    def find(self, line: str, *, allow_bare: bool = True) -> list[Candidate]:
        found: list[Candidate] = []

        def add(start, end, value, rule, severity, confidence, evidence):
            if not value or is_placeholder(value) or is_reference(value):
                return
            if not any(start < item.end and end > item.start for item in found):
                found.append(Candidate(start, end, rule, severity, confidence, evidence, value))
                if len(found) > self.config.max_findings:
                    raise ScanError("Finding limit exceeded; scan incomplete.")

        try:
            for rule, pattern, severity in PREFIXES:
                for match in pattern.finditer(line, timeout=TIMEOUT):
                    add(*match.span(), match[0], rule, severity, 0.98, "Known credential prefix")
            for match in AUTH.finditer(line, timeout=TIMEOUT):
                add(*match.span("secret"), match["secret"], "authorization-header", Severity.HIGH,
                    0.95, "Literal authorization value")
            for definition, pattern in self.custom:
                for match in pattern.finditer(line, timeout=TIMEOUT):
                    value = match["secret"]
                    if not value:
                        raise ScanError("Detection pattern returned an empty candidate.")
                    add(*match.span("secret"), value, "custom-" + definition.rule_id,
                        definition.severity, 0.9, "Configured credential pattern")
            for match in ASSIGNMENT.finditer(line, timeout=TIMEOUT):
                if not allow_bare and not match["quote"]:
                    continue
                name = match["name"]
                value = match["quoted"] if match["quote"] else match["bare"]
                if PUBLIC_CONTEXT.search(name, timeout=TIMEOUT) or is_reference(value):
                    continue
                group = "quoted" if match["quote"] else "bare"
                if STRONG_CONTEXT.search(name, timeout=TIMEOUT) and len(value) >= self.config.min_secret_length:
                    add(*match.span(group), value, "secret-assignment", Severity.HIGH,
                        0.85, "Credential-named literal assignment")
                elif (WEAK_CONTEXT.search(name, timeout=TIMEOUT)
                      and not HASH_OR_UUID.fullmatch(value)
                      and len(value) >= self.config.entropy_min_length
                      and shannon_entropy(value) >= self.config.entropy_threshold):
                    add(*match.span(group), value, "high-entropy-secret", Severity.MEDIUM,
                        0.75, "High entropy with credential context")
        except TimeoutError:
            raise ScanError("Detection pattern timed out; scan incomplete.") from None
        return sorted(found, key=lambda item: item.start)


def safe_path(path: str, secrets: tuple[str, ...] = ()) -> str:
    """Remove candidates, URLs, email addresses, token prefixes and terminal controls."""
    for value in sorted(set(secrets), key=len, reverse=True):
        if value:
            path = path.replace(value, "<REDACTED>")
    path = regex.sub(r"(?i)[a-z][a-z0-9+.-]*://[^\s]+", "<REDACTED_URL>", path, timeout=TIMEOUT)
    path = regex.sub(r"[^\s/@]+@[^\s/]+", "<REDACTED_EMAIL>", path, timeout=TIMEOUT)
    for _, pattern, _ in PREFIXES:
        path = pattern.sub("<REDACTED>", path, timeout=TIMEOUT)
    return "".join(char if char.isprintable() else f"\\u{ord(char):04x}" for char in path)
