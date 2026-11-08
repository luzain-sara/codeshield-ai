"""Provider advice cannot remove deterministic findings or authorize edits."""

from codeshield.models import Decision


def allow_fix(decision: Decision) -> bool:
    return False  # Provider advice alone never authorizes a plan or a working-tree write.
