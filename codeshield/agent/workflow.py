"""A fixed state machine: local inspection -> assessment -> conservative policy -> done."""

from pathlib import Path

from codeshield.agent.cache import VerificationCache
from codeshield.agent.policy import allow_fix
from codeshield.agent.providers import make_provider, require_live_opt_in
from codeshield.agent.sanitizer import SafeContext
from codeshield.agent.tools import ToolRequest, Tools
from codeshield.agent.verifier import Verifier
from codeshield.config import Config
from codeshield.models import Finding, Provider, Verification


def verify_findings(findings: tuple[Finding, ...], contexts: dict[str, SafeContext],
                    config: Config, root: Path, *, live_enabled: bool = False) -> tuple[Finding, ...]:
    if config.provider == Provider.GEMINI:
        require_live_opt_in(live_enabled)
    if not findings:
        return findings
    tools = Tools(contexts)
    cache = VerificationCache(root, config.verification_cache_ttl_seconds) if config.provider == Provider.GEMINI else None
    provider = make_provider(config, root)
    verifier = Verifier(provider, config, cache)
    updated = []
    try:
        for finding in findings:
            # Exactly two allowlisted tool executions and one bounded verifier per finding.
            context = tools.execute(ToolRequest(tool="inspect_context", finding_id=finding.finding_id)).context
            tools.execute(ToolRequest(tool="detect_framework", finding_id=finding.finding_id))
            decision, status, cached = verifier.assess(context)
            source = provider.source if status == "ok" else Provider.RULES
            verification = Verification(
                decision=decision, requested_provider=config.provider, source=source, status=status,
                cached=cached, fix_allowed=allow_fix(decision),
                states=("finding", "inspect_context", "detect_framework", "assess_finding", "choose_policy", "complete"),
            )
            updated.append(finding.model_copy(update={"assessment_source": source, "verification": verification}))
    finally:
        provider.close()
    return tuple(updated)


def plan_fix(finding_id: str, config: Config, *, cwd: Path | None = None,
             env_name: str | None = None, store_secret: bool = False):
    """Trusted, fixed Phase 3 chain; never exposed as an LLM function/tool."""
    from codeshield.remediation.planner import plan_remediation
    return plan_remediation(finding_id, config, cwd=cwd, env_name=env_name, store_secret=store_secret)
