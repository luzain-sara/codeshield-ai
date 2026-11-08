"""Provider advice cannot remove deterministic findings or authorize edits."""

from codeshield.models import Decision


def allow_fix(decision: Decision) -> bool:
    return False  # Phase 3 is deliberately unavailable, including for likely secrets.
