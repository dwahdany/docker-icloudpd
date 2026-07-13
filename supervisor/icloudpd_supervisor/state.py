"""Supervisor state: the in-memory state machine, the status file consumed by
the Docker healthcheck, and the small persisted state that must survive
container restarts.

The persisted auth-attempt history is the core of the lockout protection:
the old container reset all memory on restart, so a crash-loop performed a
fresh Apple password sign-in every couple of minutes. Persisting the budget
makes restarts harmless.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)


class SupervisorState(Enum):
    STARTING = "starting"
    IDLE = "idle"
    SYNCING = "syncing"
    WAITING_FOR_MFA = "waiting_for_mfa"
    PASSWORD_NEEDED = "password_needed"
    AUTH_RATE_LIMITED = "auth_rate_limited"


class StatusFile:
    """Liveness beacon for the Docker healthcheck.

    Deliberately liveness-only: every *state* is healthy as long as the
    supervisor loop is alive. Marking "waiting for user input" or "sync
    failed" unhealthy invites autoheal-style restart loops, which do not fix
    anything and (before this rewrite) hammered Apple until the account was
    locked.
    """

    def __init__(self, path: str) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, state: SupervisorState, **details: object) -> None:
        payload = {"state": state.value, "updated_at": time.time(), **details}
        try:
            tmp = self._path.with_suffix(".tmp")
            tmp.write_text(json.dumps(payload))
            tmp.replace(self._path)
        except OSError as exc:
            logger.warning("Cannot write status file: %s", exc)


@dataclass
class PersistedState:
    auth_attempts: list[float] = field(default_factory=list)  # epoch seconds
    last_sync_time: float | None = None
    last_sync_ok: bool | None = None
    last_expiry_warning: float = 0.0

    @classmethod
    def load(cls, path: str) -> "PersistedState":
        try:
            raw = json.loads(Path(path).read_text())
            if not isinstance(raw, dict):
                # Valid JSON that is not an object ("null", an array, ...)
                # must be tolerated like any other corrupt state file.
                return cls()
            return cls(
                auth_attempts=[float(t) for t in raw.get("auth_attempts", [])],
                last_sync_time=raw.get("last_sync_time"),
                last_sync_ok=raw.get("last_sync_ok"),
                last_expiry_warning=float(raw.get("last_expiry_warning", 0.0)),
            )
        except (OSError, ValueError, TypeError):
            return cls()

    def save(self, path: str) -> None:
        try:
            target = Path(path)
            tmp = target.with_suffix(".tmp")
            tmp.write_text(
                json.dumps(
                    {
                        "auth_attempts": self.auth_attempts,
                        "last_sync_time": self.last_sync_time,
                        "last_sync_ok": self.last_sync_ok,
                        "last_expiry_warning": self.last_expiry_warning,
                    }
                )
            )
            tmp.replace(target)
        except OSError as exc:
            logger.warning("Cannot persist supervisor state: %s", exc)

    # --- auth budget ------------------------------------------------------

    def record_auth_attempt(self) -> None:
        self.auth_attempts.append(time.time())
        self._prune()

    def auth_attempts_last_day(self) -> int:
        self._prune()
        return len(self.auth_attempts)

    def _prune(self) -> None:
        cutoff = time.time() - 86400
        self.auth_attempts = [t for t in self.auth_attempts if t > cutoff]
