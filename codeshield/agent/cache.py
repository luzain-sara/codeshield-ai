"""Bounded local cache of enum-only decisions keyed by nonsecret projected context."""

import hashlib
import json
import os
import re
import stat
import time
from pathlib import Path

from codeshield.agent.sanitizer import SafeContext
from codeshield.models import Decision

VERSION = "phase2-prompt-policy-1"
MAX_BYTES = 262144
MAX_ENTRIES = 256


def cache_key(context: SafeContext, model: str) -> str:
    payload = [VERSION, "gemini", model, context.model_dump(mode="json")]
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


def linked(path: Path) -> bool:
    return any(p.is_symlink() or (hasattr(p, "is_junction") and p.is_junction()) for p in (path, *path.parents))


class VerificationCache:
    def __init__(self, root: Path, ttl: int):
        self.path = root / ".codeshield" / "verification-cache.json"
        self.ttl = ttl
        self.entries: dict[str, tuple[float, Decision]] = {}
        try:
            if linked(self.path):
                return
            if not stat.S_ISREG(self.path.stat(follow_symlinks=False).st_mode):
                return
            flags = (os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
                     | getattr(os, "O_NONBLOCK", 0))
            with os.fdopen(os.open(self.path, flags), "rb") as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    return
                data = stream.read(MAX_BYTES + 1)
            if len(data) > MAX_BYTES:
                return
            values = json.loads(data)
            if not isinstance(values, dict) or len(values) > MAX_ENTRIES:
                return
            for key, value in values.items():
                if not re.fullmatch("[0-9a-f]{64}", key) or not isinstance(value, dict) or set(value) != {"expires", "decision"}:
                    continue
                expiry = value["expires"]
                if (isinstance(expiry, (float, int)) and time.time() < expiry <= time.time() + ttl
                        and not isinstance(expiry, bool)):
                    decision = Decision.model_validate_json(json.dumps(value["decision"]), strict=True)
                    self.entries[key] = (expiry, decision)
        except (OSError, ValueError, TypeError, RecursionError):
            self.entries.clear()

    def get(self, key: str) -> Decision | None:
        if self.ttl and key in self.entries and self.entries[key][0] > time.time():
            return self.entries[key][1]
        return None

    def put(self, key: str, decision: Decision):
        if not self.ttl:
            return
        self.entries[key] = (time.time() + self.ttl, decision)
        self.entries = dict(list(self.entries.items())[-MAX_ENTRIES:])
        # No raw text, response bodies, filenames, candidate hashes, or credentials are stored.
        data = {key: {"expires": expiry, "decision": decision.model_dump(mode="json")}
                for key, (expiry, decision) in self.entries.items()}
        temporary = self.path.with_name(f"cache-{os.getpid()}.tmp")
        created = False
        try:
            if linked(self.path) or linked(temporary):
                return
            self.path.parent.mkdir(mode=0o700, exist_ok=True)
            with temporary.open("x", encoding="utf-8") as stream:
                created = True
                json.dump(data, stream, sort_keys=True)
            os.replace(temporary, self.path)
        except OSError:
            pass  # Cache failures never suppress findings or authorize a fix.
        finally:
            try:
                if created and not temporary.is_symlink():
                    temporary.unlink(missing_ok=True)
            except OSError:
                pass
