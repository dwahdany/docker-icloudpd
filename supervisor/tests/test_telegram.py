"""Tests for icloudpd_supervisor.telegram.

Hermetic: requests.Session is monkeypatched with an in-process fake, and
time.sleep is stubbed in the error-path tests (poll_updates sleeps 5s when
the API misbehaves).  No network, no real Telegram, no real icloudpd.
"""

from __future__ import annotations

import queue
import threading

import pytest
import requests

import icloudpd_supervisor.telegram as telegram_mod
from icloudpd_supervisor.telegram import (
    Command,
    TelegramClient,
    TelegramListener,
    parse_command,
)

CHAT_ID = "1000"
BASE_URL = "https://api.telegram.invalid/botTEST"


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class FakeResponse:
    def __init__(self, status_code=200, payload=None, json_exc=None):
        self.status_code = status_code
        self._payload = payload
        self._json_exc = json_exc

    def json(self):
        if self._json_exc is not None:
            raise self._json_exc
        return self._payload


class FakeSession:
    """Stands in for requests.Session; records calls, replays scripted results.

    Each scripted item is either a FakeResponse or an Exception to raise.
    """

    def __init__(self):
        self.script = []
        self.calls = []

    def post(self, url, data=None, timeout=None):
        self.calls.append({"url": url, "data": data, "timeout": timeout})
        if not self.script:
            raise AssertionError("unexpected extra HTTP call to %s" % url)
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


@pytest.fixture
def fake_session(monkeypatch):
    """Monkeypatch requests.Session (as used by telegram.py) with a fake."""
    session = FakeSession()
    monkeypatch.setattr(telegram_mod.requests, "Session", lambda: session)
    return session


@pytest.fixture
def sleeps(monkeypatch):
    """Neutralise time.sleep in the telegram module; record durations."""
    calls = []
    monkeypatch.setattr(telegram_mod.time, "sleep", lambda s: calls.append(s))
    return calls


def make_client(tmp_path, name="offset"):
    return TelegramClient(BASE_URL, CHAT_ID, str(tmp_path / name))


def update(update_id, chat_id=CHAT_ID, text=None, message=True):
    upd = {"update_id": update_id}
    if message:
        msg = {"chat": {"id": int(chat_id)}}
        if text is not None:
            msg["text"] = text
        upd["message"] = msg
    return upd


def ok_payload(*updates):
    return FakeResponse(200, {"ok": True, "result": list(updates)})


# ---------------------------------------------------------------------------
# parse_command
# ---------------------------------------------------------------------------


class TestParseCommandBare:
    @pytest.mark.parametrize(
        ("text", "kind"),
        [
            ("sync", "sync"),
            ("download", "sync"),
            ("auth", "reauth"),
            ("reauth", "reauth"),
            ("status", "status"),
            ("help", "help"),
        ],
    )
    def test_bare_commands(self, text, kind):
        cmd = parse_command(text)
        assert cmd is not None
        assert cmd.kind == kind
        assert cmd.value == ""

    @pytest.mark.parametrize("text", ["SYNC", "Sync", "ReAuth", "AUTH", "Status", "HELP", "DownLoad"])
    def test_case_insensitive(self, text):
        assert parse_command(text) is not None

    def test_surrounding_whitespace_tolerated(self):
        cmd = parse_command("  sync \n")
        assert cmd == Command("sync")

    def test_six_digit_code(self):
        cmd = parse_command("123456")
        assert cmd == Command("code", "123456")

    def test_six_digit_code_with_whitespace(self):
        assert parse_command(" 123456 ") == Command("code", "123456")

    @pytest.mark.parametrize(
        "text",
        [
            "12345",       # 5 digits
            "1234567",     # 7 digits
            "12345a",      # not all digits
            "+123456",     # sign prefix
            "123 456",     # split code
            "hello world", # multi-word junk
            "sync now please",
            "",            # empty
            "   ",         # whitespace only
            "resync",      # unknown verb
        ],
    )
    def test_rejects_junk(self, text):
        assert parse_command(text) is None


class TestParseCommandAliasPrefix:
    ALIASES = ("Boris", "icloudpd")

    def test_alias_then_command(self):
        assert parse_command("boris sync", self.ALIASES) == Command("sync")

    def test_alias_then_code(self):
        assert parse_command("boris 654321", self.ALIASES) == Command("code", "654321")

    def test_alias_case_insensitive_both_ways(self):
        assert parse_command("BORIS ReAuth", self.ALIASES) == Command("reauth")
        assert parse_command("IcLoUdPd STATUS", self.ALIASES) == Command("status")

    def test_unknown_prefix_rejected(self):
        assert parse_command("alice sync", self.ALIASES) is None

    def test_alias_alone_is_not_a_command(self):
        assert parse_command("boris", self.ALIASES) is None

    def test_alias_with_multiword_junk_rejected(self):
        assert parse_command("boris sync now", self.ALIASES) is None

    def test_alias_with_bad_code_rejected(self):
        assert parse_command("boris 12345", self.ALIASES) is None
        assert parse_command("boris 1234567", self.ALIASES) is None

    def test_prefix_form_requires_aliases_configured(self):
        # with no aliases, "boris sync" is just two-word junk
        assert parse_command("boris sync") is None


def test_non_ascii_digits_are_not_a_code():
    assert parse_command("١٢٣٤٥٦") is None


# ---------------------------------------------------------------------------
# TelegramClient.poll_updates
# ---------------------------------------------------------------------------


class TestPollUpdates:
    def test_returns_texts_from_configured_chat_and_persists_offset(
        self, fake_session, tmp_path
    ):
        client = make_client(tmp_path)
        fake_session.script = [
            ok_payload(
                update(11, text="sync"),
                update(12, text="123456"),
            )
        ]
        assert client.poll_updates() == ["sync", "123456"]
        assert (tmp_path / "offset").read_text() == "12"
        call = fake_session.calls[0]
        assert call["url"] == f"{BASE_URL}/getUpdates"
        assert call["data"]["offset"] == 1  # no prior offset -> 0 + 1
        assert call["data"]["timeout"] == 50
        assert call["timeout"] == 65  # long-poll timeout + 15s slack

    def test_unauthorised_chat_dropped_but_offset_advances(
        self, fake_session, tmp_path, caplog
    ):
        client = make_client(tmp_path)
        fake_session.script = [ok_payload(update(21, chat_id="666", text="sync"))]
        with caplog.at_level("WARNING", logger="icloudpd_supervisor.telegram"):
            assert client.poll_updates() == []
        # acknowledged: offset advances past the hostile update so it is not
        # re-fetched forever
        assert (tmp_path / "offset").read_text() == "21"
        assert any("unauthorised" in rec.message for rec in caplog.records)

    def test_mixed_chats_filters_but_keeps_order(self, fake_session, tmp_path):
        client = make_client(tmp_path)
        fake_session.script = [
            ok_payload(
                update(31, chat_id="666", text="reauth"),
                update(32, text="status"),
                update(33, chat_id="666", text="123456"),
                update(34, text="654321"),
            )
        ]
        assert client.poll_updates() == ["status", "654321"]
        assert (tmp_path / "offset").read_text() == "34"

    def test_persisted_offset_is_used_on_next_poll(self, fake_session, tmp_path):
        client = make_client(tmp_path)
        (tmp_path / "offset").write_text("41")
        fake_session.script = [ok_payload(update(42, text="sync"))]
        assert client.poll_updates() == ["sync"]
        assert fake_session.calls[0]["data"]["offset"] == 42  # 41 + 1
        assert (tmp_path / "offset").read_text() == "42"

    def test_corrupt_offset_file_treated_as_zero(self, fake_session, tmp_path):
        client = make_client(tmp_path)
        (tmp_path / "offset").write_text("not-a-number")
        fake_session.script = [ok_payload()]
        assert client.poll_updates() == []
        assert fake_session.calls[0]["data"]["offset"] == 1

    def test_empty_result_does_not_touch_offset_file(self, fake_session, tmp_path):
        client = make_client(tmp_path)
        fake_session.script = [ok_payload()]
        assert client.poll_updates() == []
        assert not (tmp_path / "offset").exists()

    def test_update_without_text_advances_offset_silently(
        self, fake_session, tmp_path
    ):
        # e.g. a photo message, or an update with no message at all
        client = make_client(tmp_path)
        fake_session.script = [
            ok_payload(update(51), update(52, message=False))
        ]
        assert client.poll_updates() == []
        assert (tmp_path / "offset").read_text() == "52"

    def test_network_error_returns_empty_and_backs_off(
        self, fake_session, tmp_path, sleeps
    ):
        client = make_client(tmp_path)
        fake_session.script = [requests.ConnectionError("api unreachable")]
        assert client.poll_updates() == []
        assert sleeps == [5]
        assert not (tmp_path / "offset").exists()

    def test_bad_json_returns_empty_and_backs_off(
        self, fake_session, tmp_path, sleeps
    ):
        client = make_client(tmp_path)
        fake_session.script = [
            FakeResponse(200, json_exc=ValueError("no json could be decoded"))
        ]
        assert client.poll_updates() == []
        assert sleeps == [5]

    def test_api_not_ok_returns_empty_and_backs_off(
        self, fake_session, tmp_path, sleeps
    ):
        client = make_client(tmp_path)
        fake_session.script = [
            FakeResponse(200, {"ok": False, "description": "Unauthorized"})
        ]
        assert client.poll_updates() == []
        assert sleeps == [5]

    def test_offset_write_failure_does_not_lose_messages(
        self, fake_session, tmp_path
    ):
        # offset path is a directory: write_text raises OSError, which must be
        # swallowed and the polled texts still returned
        offset_dir = tmp_path / "offset"
        offset_dir.mkdir()
        client = make_client(tmp_path)
        fake_session.script = [ok_payload(update(61, text="sync"))]
        assert client.poll_updates() == ["sync"]


# ---------------------------------------------------------------------------
# TelegramClient.send
# ---------------------------------------------------------------------------


class TestSend:
    def test_success(self, fake_session, tmp_path):
        client = make_client(tmp_path)
        fake_session.script = [FakeResponse(200, {"ok": True})]
        assert client.send("hello") is True
        call = fake_session.calls[0]
        assert call["url"] == f"{BASE_URL}/sendMessage"
        assert call["data"]["chat_id"] == CHAT_ID
        assert call["data"]["text"] == "hello"
        assert call["data"]["disable_notification"] == "false"
        # plain text: no parse_mode, so underscores/brackets cannot be dropped
        assert "parse_mode" not in call["data"]

    def test_silent_flag(self, fake_session, tmp_path):
        client = make_client(tmp_path)
        fake_session.script = [FakeResponse(200, {"ok": True})]
        assert client.send("psst", silent=True) is True
        assert fake_session.calls[0]["data"]["disable_notification"] == "true"

    def test_http_error_returns_false(self, fake_session, tmp_path):
        client = make_client(tmp_path)
        fake_session.script = [FakeResponse(502, {"ok": False})]
        assert client.send("hello") is False

    def test_api_not_ok_returns_false(self, fake_session, tmp_path):
        client = make_client(tmp_path)
        fake_session.script = [FakeResponse(200, {"ok": False})]
        assert client.send("hello") is False

    def test_network_error_returns_false_without_raising(
        self, fake_session, tmp_path
    ):
        client = make_client(tmp_path)
        fake_session.script = [requests.ConnectionError("boom")]
        assert client.send("hello") is False

    def test_bad_json_returns_false_without_raising(self, fake_session, tmp_path):
        client = make_client(tmp_path)
        fake_session.script = [FakeResponse(200, json_exc=ValueError("not json"))]
        assert client.send("hello") is False


# ---------------------------------------------------------------------------
# TelegramListener
# ---------------------------------------------------------------------------


def test_listener_queues_parsed_commands_and_stops():
    batches = [["boris sync", "utter junk", "123456"]]
    commands: "queue.Queue[Command]" = queue.Queue()
    listener_box = {}

    class FakeClient:
        def poll_updates(self, timeout=50):
            if batches:
                return batches.pop(0)
            listener_box["listener"].stop()
            return []

    listener = TelegramListener(FakeClient(), commands, aliases=("boris",))
    listener_box["listener"] = listener
    listener.start()
    listener.join(timeout=10)
    assert not listener.is_alive()

    received = []
    while True:
        try:
            received.append(commands.get_nowait())
        except queue.Empty:
            break
    assert received == [Command("sync"), Command("code", "123456")]
