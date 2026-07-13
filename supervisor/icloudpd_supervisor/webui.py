"""Bridge to icloudpd's --mfa-provider webui HTTP interface.

When icloudpd runs with --mfa-provider webui it serves a small web app
(waitress, 0.0.0.0:8080 by default) whose /status page reflects an internal
state machine (icloudpd/status.py):

    NO_INPUT_NEEDED -> NEED_MFA -> SUPPLIED_MFA -> CHECKING_MFA
        -> success: NO_INPUT_NEEDED
        -> failure: NEED_MFA (+ error text)

Crucially, request_2fa_web() triggers Apple's push notification itself and
then *pauses indefinitely* waiting for the code — exactly one authentication
attempt per human action, which is what keeps Apple from locking the account.

/status returns rendered HTML, not JSON, so we detect states via stable
markers in the pinned icloudpd version's templates:
  - code.html has an <input ... name="code">      -> NEED_MFA
  - password.html has <input ... name="password"> -> NEED_PASSWORD
  - status.html renders "Status: SUPPLIED_MFA" / "Status: CHECKING_MFA"
    while a submitted code is being verified     -> CHECKING
  - anything else (no_input.html)                -> IDLE
Errors render inside <div class="fw-bold">...</div> — but ONLY the prompt
pages use that class exclusively for errors; no_input.html uses it for
unconditional labels, so error extraction is restricted to prompt pages.

The port must NOT be published outside the container: anyone who can reach
it can submit or cancel authentication.
"""

from __future__ import annotations

import html
import logging
import re
from dataclasses import dataclass
from enum import Enum

import requests

logger = logging.getLogger(__name__)

_ERROR_RE = re.compile(r'<div class="fw-bold">\s*(.*?)\s*</div>', re.DOTALL)


class WebUIState(Enum):
    UNREACHABLE = "unreachable"  # server not (yet) running
    IDLE = "idle"  # NO_INPUT_NEEDED / anything not requiring input
    CHECKING = "checking"  # a submitted code/password is being verified
    NEED_MFA = "need_mfa"
    NEED_PASSWORD = "need_password"


@dataclass
class WebUIStatus:
    state: WebUIState
    error: str | None = None


class WebUIBridge:
    def __init__(self, port: int = 8080, host: str = "127.0.0.1") -> None:
        self._base = f"http://{host}:{port}"
        self._session = requests.Session()

    def status(self) -> WebUIStatus:
        try:
            response = self._session.get(f"{self._base}/status", timeout=10)
        except requests.RequestException:
            return WebUIStatus(WebUIState.UNREACHABLE)
        body = response.text
        if 'name="code"' in body or 'name="password"' in body:
            error_match = _ERROR_RE.search(body)
            error = html.unescape(error_match.group(1)) if error_match else None
            state = WebUIState.NEED_MFA if 'name="code"' in body else WebUIState.NEED_PASSWORD
            return WebUIStatus(state, error)
        if "Status: SUPPLIED_MFA" in body or "Status: CHECKING_MFA" in body:
            return WebUIStatus(WebUIState.CHECKING)
        return WebUIStatus(WebUIState.IDLE)

    def submit_code(self, code: str) -> bool:
        """POST the MFA code. True means accepted for checking (not yet valid)."""
        try:
            response = self._session.post(
                f"{self._base}/code", data={"code": code}, timeout=10
            )
            return response.status_code == 200
        except requests.RequestException as exc:
            logger.warning("Failed to submit MFA code to webui: %s", exc)
            return False

    def cancel(self) -> None:
        """Ask icloudpd to abort the current wait (best effort)."""
        try:
            self._session.post(f"{self._base}/cancel", timeout=10)
        except requests.RequestException:
            pass
