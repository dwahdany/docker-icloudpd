"""Security-focused adversarial tests for icloudpd_supervisor.

Hermetic: no network, no real Telegram/Apple endpoints, no real icloudpd
binary. Failing behaviours in the implementation are kept as xfail tests
per review rules (implementation must not be modified).
"""

from __future__ import annotations

import logging
import queue
from types import SimpleNamespace

import pytest
import requests

from icloudpd_supervisor.telegram import TelegramClient

TOKEN = "123456:SECRET-BOT-TOKEN"
BASE_URL = f"https://api.telegram.org/bot{TOKEN}"


class _RaisingSession:
    """Mimics requests.Session raising a ConnectionError whose message embeds
    the request URL path, exactly like urllib3's MaxRetryError does."""

    def post(self, url: str, **_kwargs: object) -> object:
        path = url.split("api.telegram.org", 1)[-1]
        raise requests.exceptions.ConnectionError(
            f"HTTPSConnectionPool(host='api.telegram.org', port=443): "
            f"Max retries exceeded with url: {path} "
            "(Caused by NewConnectionError(...))"
        )


def _client(tmp_path) -> TelegramClient:
    client = TelegramClient(
        base_url=BASE_URL, chat_id="42", offset_file=str(tmp_path / "offset.num")
    )
    client._session = _RaisingSession()
    return client


def test_send_does_not_leak_token_into_logs(tmp_path, caplog):
    client = _client(tmp_path)
    with caplog.at_level(logging.WARNING, logger="icloudpd_supervisor.telegram"):
        assert client.send("hello") is False
    assert TOKEN not in caplog.text


def test_poll_updates_does_not_leak_token_into_logs(tmp_path, caplog, monkeypatch):
    monkeypatch.setattr("icloudpd_supervisor.telegram.time.sleep", lambda _s: None)
    client = _client(tmp_path)
    with caplog.at_level(logging.WARNING, logger="icloudpd_supervisor.telegram"):
        assert client.poll_updates() == []
    assert TOKEN not in caplog.text


class _GroupUpdateSession:
    """getUpdates returns a message in the configured (group) chat but sent
    by a user other than the operator."""

    def post(self, url: str, **_kwargs: object) -> object:
        assert url.endswith("/getUpdates")
        return SimpleNamespace(
            status_code=200,
            json=lambda: {
                "ok": True,
                "result": [
                    {
                        "update_id": 7,
                        "message": {
                            "message_id": 1,
                            "from": {"id": 999999, "first_name": "Mallory"},
                            "chat": {"id": -100123, "type": "supergroup"},
                            "text": "reauth",
                        },
                    }
                ],
            },
        )


def test_group_chat_members_are_all_authorised(tmp_path):
    """Demonstrates the authorization scope: filtering is by chat.id only.

    If telegram_chat_id is a group, ANY member's message (here from.id
    999999, not the operator) is accepted as a command — including 6-digit
    MFA codes and 'reauth', which spends the Apple auth budget. This is a
    documented-behaviour test (not xfail): it pins the current semantics
    that the security review flags as sender-spoofable in group chats.
    """
    client = TelegramClient(
        base_url=BASE_URL, chat_id="-100123", offset_file=str(tmp_path / "o.num")
    )
    client._session = _GroupUpdateSession()
    assert client.poll_updates() == ["reauth"]  # attacker-controlled text accepted
