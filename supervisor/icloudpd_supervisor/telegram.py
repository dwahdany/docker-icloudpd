"""Telegram bot client: outbound notifications and an always-on command listener.

Design notes, learned from the old container's failures:
- The listener runs in its own thread for the whole life of the supervisor,
  so commands (including MFA codes) are received in EVERY state — most
  importantly while authentication is required. The old container only
  polled Telegram between successful syncs.
- Only messages from the configured chat_id are honoured. The old container
  accepted commands from anyone who could message the bot.
- Messages are sent as plain text: the old container used parse_mode=markdown
  and silently dropped messages containing underscores or brackets.
"""

from __future__ import annotations

import logging
import queue
import re
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import requests

logger = logging.getLogger(__name__)

# ASCII digits only: \d would also match e.g. Arabic-Indic digits, which
# Apple's endpoint will never accept.
MFA_CODE_RE = re.compile(r"^[0-9]{6}$")


@dataclass
class Command:
    kind: str  # "sync" | "reauth" | "status" | "code" | "help"
    value: str = ""


def parse_command(
    text: str, aliases: tuple[str, ...] = (), require_prefix: bool = False
) -> Command | None:
    """Parse a Telegram message into a Command.

    Accepts bare commands ("sync", "123456") and the old container's
    "<name> <command>" convention ("a 123456"), where <name> is any of the
    provided aliases. A bare "<name>" on its own means "sync now" (the
    legacy convention).

    With require_prefix=True, UNprefixed commands are ignored — necessary
    when several supervisor instances share one chat, so a bare "sync" or
    2FA code is not consumed by every instance at once.
    """
    words = text.strip().split()
    if not words:
        return None
    lowered = [w.lower() for w in words]
    prefixed = False
    if lowered[0] in tuple(a.lower() for a in aliases if a):
        if len(words) == 1:
            return Command("sync")  # bare "<name>" = sync now
        words = words[1:]
        lowered = lowered[1:]
        prefixed = True
    if require_prefix and not prefixed:
        return None
    if len(words) != 1:
        return None
    word, low = words[0], lowered[0]
    if MFA_CODE_RE.match(word):
        return Command("code", word)
    if low in ("sync", "download"):
        return Command("sync")
    if low in ("auth", "reauth"):
        return Command("reauth")
    if low == "status":
        return Command("status")
    if low == "help":
        return Command("help")
    return None


class TelegramClient:
    def __init__(
        self,
        base_url: str,
        chat_id: str,
        offset_file: str,
        sender_id: str = "",
    ) -> None:
        self._base_url = base_url
        self._chat_id = str(chat_id)
        self._sender_id = str(sender_id) if sender_id else ""
        self._offset_path = Path(offset_file)
        self._session = requests.Session()

    def _redact(self, text: str) -> str:
        """Strip the bot token out of error strings before they hit the log.

        requests exceptions embed the full request URL, which contains
        /bot<token>/ — logging them verbatim leaks the token.
        """
        token_part = self._base_url.rsplit("/bot", 1)[-1]
        return text.replace(token_part, "***") if token_part else text

    def send(self, text: str, silent: bool = False) -> bool:
        """Send a message. Returns False on failure; never raises."""
        try:
            response = self._session.post(
                f"{self._base_url}/sendMessage",
                data={
                    "chat_id": self._chat_id,
                    "text": text,
                    "disable_notification": "true" if silent else "false",
                },
                timeout=30,
            )
            ok = response.status_code == 200 and response.json().get("ok", False)
            if not ok:
                logger.warning("Telegram sendMessage failed: HTTP %s", response.status_code)
            return ok
        except (requests.RequestException, ValueError) as exc:
            logger.warning("Telegram sendMessage error: %s", self._redact(str(exc)))
            return False

    # --- update polling -------------------------------------------------

    def _load_offset(self) -> int:
        try:
            return int(self._offset_path.read_text().strip() or 0)
        except (OSError, ValueError):
            return 0

    def _store_offset(self, offset: int) -> None:
        try:
            self._offset_path.write_text(str(offset))
        except OSError as exc:
            logger.warning("Cannot persist Telegram offset: %s", exc)

    def poll_updates(self, timeout: int = 50) -> list[str]:
        """Long-poll for new messages from the configured chat.

        Returns the message texts and advances the persisted offset past
        every update received (including ones from other chats, which are
        dropped after being acknowledged).
        """
        offset = self._load_offset()
        try:
            response = self._session.post(
                f"{self._base_url}/getUpdates",
                data={
                    "offset": offset + 1,
                    "timeout": timeout,
                    "allowed_updates": '["message"]',
                },
                timeout=timeout + 15,
            )
            payload = response.json()
        except (requests.RequestException, ValueError) as exc:
            logger.warning("Telegram getUpdates error: %s", self._redact(str(exc)))
            time.sleep(5)  # do not hot-loop when the API is unreachable
            return []
        if not payload.get("ok", False):
            logger.warning("Telegram getUpdates not ok: %s", payload.get("description"))
            time.sleep(5)
            return []

        texts: list[str] = []
        max_update_id = offset
        for update in payload.get("result", []):
            max_update_id = max(max_update_id, update.get("update_id", 0))
            message = update.get("message") or {}
            chat = str((message.get("chat") or {}).get("id", ""))
            sender = str((message.get("from") or {}).get("id", ""))
            text = message.get("text")
            if text is None:
                continue
            if chat != self._chat_id:
                logger.warning("Ignoring Telegram message from unauthorised chat %s", chat)
            elif self._sender_id and sender != self._sender_id:
                # chat_id alone is not a sender check: in group chats every
                # member shares the chat. The optional sender allowlist
                # closes that hole.
                logger.warning("Ignoring Telegram message from unauthorised sender %s", sender)
            else:
                texts.append(text)
        if max_update_id > offset:
            self._store_offset(max_update_id)
        return texts


class TelegramListener(threading.Thread):
    """Background thread feeding parsed commands into a queue."""

    def __init__(
        self,
        client: TelegramClient,
        commands: "queue.Queue[Command]",
        aliases: tuple[str, ...] = (),
        require_prefix: bool = False,
    ) -> None:
        super().__init__(name="telegram-listener", daemon=True)
        self._client = client
        self._commands = commands
        self._aliases = aliases
        self._require_prefix = require_prefix
        self._stop_event = threading.Event()

    def stop(self) -> None:
        self._stop_event.set()

    def run(self) -> None:
        logger.info("Telegram listener started")
        while not self._stop_event.is_set():
            for text in self._client.poll_updates():
                command = parse_command(text, self._aliases, self._require_prefix)
                if command:
                    logger.info("Telegram command received: %s", command.kind)
                    self._commands.put(command)
                else:
                    # Do not log the text itself: it may contain an MFA code.
                    logger.debug("Ignoring unrecognised Telegram message (%d chars)", len(text))
