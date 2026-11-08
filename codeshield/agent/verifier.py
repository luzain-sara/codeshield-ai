"""Shared typed verification, strict decisions and bounded quota-aware retries."""

import time

from codeshield.agent.cache import VerificationCache, cache_key
from codeshield.agent.providers import ProviderFailure, VerifierProvider
from codeshield.agent.sanitizer import SafeContext
from codeshield.config import Config
from codeshield.models import Advice, Classification, Decision, DecisionReason, Provider


def uncertain() -> Decision:
    return Decision(classification=Classification.UNCERTAIN, reason=DecisionReason.INSUFFICIENT_CONTEXT,
                    recommendation=Advice.MANUAL_REVIEW)


class Verifier:
    def __init__(self, provider: VerifierProvider, config: Config, cache: VerificationCache | None):
        self.provider, self.config, self.cache = provider, config, cache
        self.calls = 0
        self.deadline = time.monotonic() + config.verification_timeout_seconds
        self.unavailable = False

    def assess(self, context: SafeContext) -> tuple[Decision, str, bool]:
        key = cache_key(context, self.config.gemini_model)
        if self.cache:
            cached = self.cache.get(key)
            if cached:
                return cached, "ok", True
        if self.unavailable:
            return uncertain(), "provider_error", False
        live = self.provider.source == Provider.GEMINI
        for attempt in range(self.config.api_max_retries + 1):
            remaining = self.deadline - time.monotonic()
            if remaining <= 0 or (live and self.calls >= self.config.max_api_calls):
                return uncertain(), "budget_exhausted", False
            if live:
                self.calls += 1
            try:
                decision = self.provider.assess(context, min(remaining, self.config.api_timeout_seconds))
                decision = Decision.model_validate_json(decision.model_dump_json(), strict=True)
                if time.monotonic() > self.deadline:
                    return uncertain(), "budget_exhausted", False
                if self.cache:
                    self.cache.put(key, decision)
                return decision, "ok", False
            except ProviderFailure as exc:
                if (not live or not exc.retryable or attempt >= self.config.api_max_retries
                        or self.calls >= self.config.max_api_calls):
                    self.unavailable = live
                    return uncertain(), exc.kind, False
                delay = min(self.config.api_backoff_seconds * (2 ** attempt), 5)
                if delay + self.config.api_timeout_seconds > self.deadline - time.monotonic():
                    return uncertain(), "budget_exhausted", False
                time.sleep(delay)
            except (ValueError, AttributeError, TypeError):
                return uncertain(), "invalid_response", False
        return uncertain(), "provider_error", False
