"""Allowlisted local tools operate only on already-sanitized in-memory contexts."""

from typing import Literal

from pydantic import Field, ValidationError

from codeshield.agent.sanitizer import SafeContext
from codeshield.errors import ScanError
from codeshield.models import Contract


class ToolRequest(Contract):
    tool: Literal["inspect_context", "detect_framework"]
    finding_id: str = Field(min_length=1, max_length=128)


class ToolResult(Contract):
    context: SafeContext | None = None
    framework: Literal["python_server", "node_server", "browser", "unknown"] | None = None


class Tools:
    def __init__(self, contexts: dict[str, SafeContext]):
        self.contexts = dict(contexts)
        self.calls = 0

    def execute(self, request: ToolRequest) -> ToolResult:
        try:
            request = ToolRequest.model_validate(request)
        except ValidationError:
            raise ScanError("Tool request rejected.") from None
        if request.finding_id not in self.contexts:
            raise ScanError("Tool access denied for unknown finding.")
        self.calls += 1
        context = self.contexts[request.finding_id]
        if request.tool == "inspect_context":
            return ToolResult(context=context)
        return ToolResult(framework=context.framework)
