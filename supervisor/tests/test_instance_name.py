"""Instance-name feature: tagged notifications + prefixed command routing.

Multiple containers sharing one Telegram chat need (a) to say which config
each message belongs to and (b) to only answer commands addressed to them
("a auth" vs "b auth" — the legacy container's <user>-prefix convention).
"""

from __future__ import annotations

import queue
from pathlib import Path

from icloudpd_supervisor.config import Config, load_config
from icloudpd_supervisor.scheduler import Supervisor
from icloudpd_supervisor.telegram import parse_command

APPLE_ID = "user@example.com"


# ---------------------------------------------------------------------------
# parse_command with require_prefix (multi-instance routing)
# ---------------------------------------------------------------------------


def test_prefixed_commands_accepted():
    assert parse_command("a sync", ("a",), require_prefix=True).kind == "sync"
    assert parse_command("A AUTH", ("a",), require_prefix=True).kind == "reauth"
    code = parse_command("a 123456", ("a",), require_prefix=True)
    assert code.kind == "code" and code.value == "123456"


def test_bare_commands_ignored_when_prefix_required():
    # Another instance's traffic — or ambiguous bare commands — are ignored.
    assert parse_command("sync", ("a",), require_prefix=True) is None
    assert parse_command("123456", ("a",), require_prefix=True) is None
    assert parse_command("b sync", ("a",), require_prefix=True) is None
    assert parse_command("b 123456", ("a",), require_prefix=True) is None


def test_bare_name_alone_means_sync():
    # Legacy convention: messaging just "<user>" triggered a sync.
    assert parse_command("a", ("a",), require_prefix=True).kind == "sync"


def test_bare_commands_still_work_without_required_prefix():
    assert parse_command("sync", ("user",), require_prefix=False).kind == "sync"
    assert parse_command("123456", ("user",), require_prefix=False).kind == "code"


# ---------------------------------------------------------------------------
# Config: name sources and legacy `user` fallback
# ---------------------------------------------------------------------------


def _env(tmp_path: Path, **overrides: str) -> dict[str, str]:
    env = {"config_dir": str(tmp_path), "apple_id": APPLE_ID}
    env.update(overrides)
    return env


def test_name_from_env(tmp_path: Path):
    assert load_config(_env(tmp_path, name="a")).name == "a"


def test_name_from_legacy_conf(tmp_path: Path):
    (tmp_path / "icloudpd.conf").write_text("name=b\n")
    assert load_config(_env(tmp_path)).name == "b"


def test_name_falls_back_to_legacy_user_key(tmp_path: Path):
    # Migrated volumes carry the old Telegram prefix in `user=`.
    (tmp_path / "icloudpd.conf").write_text("user=a\n")
    assert load_config(_env(tmp_path)).name == "a"


def test_env_name_beats_legacy_user(tmp_path: Path):
    (tmp_path / "icloudpd.conf").write_text("user=a\nname=b\n")
    assert load_config(_env(tmp_path)).name == "b"
    assert load_config(_env(tmp_path, name="c")).name == "c"


def test_shell_USER_env_var_never_becomes_name(tmp_path: Path):
    # get() accepts UPPERCASE env names, but the legacy-user fallback must
    # only read the conf file — $USER from the shell must not leak in.
    env = _env(tmp_path)
    env["USER"] = "root"
    assert load_config(env).name == ""


# ---------------------------------------------------------------------------
# Notification tagging
# ---------------------------------------------------------------------------


class FakeTelegram:
    def __init__(self) -> None:
        self.messages: list[str] = []

    def send(self, text: str, silent: bool = False) -> bool:
        self.messages.append(text)
        return True


def _make_supervisor(tmp_path: Path, name: str) -> tuple[Supervisor, FakeTelegram]:
    config = Config(
        apple_id=APPLE_ID,
        name=name,
        config_dir=str(tmp_path),
        download_path=str(tmp_path),
        status_file=str(tmp_path / "status.json"),
        state_file=str(tmp_path / "state.json"),
    )
    telegram = FakeTelegram()
    sup = Supervisor(config, telegram, queue.Queue())
    return sup, telegram


def test_notifications_tagged_with_instance_name(tmp_path: Path):
    sup, telegram = _make_supervisor(tmp_path, name="a")
    sup.notify("MFA cookie expires in 3 day(s).")
    assert telegram.messages == ["[a] MFA cookie expires in 3 day(s)."]


def test_notifications_untagged_without_name(tmp_path: Path):
    sup, telegram = _make_supervisor(tmp_path, name="")
    sup.notify("hello")
    assert telegram.messages == ["hello"]


def test_help_mentions_prefix_for_named_instance(tmp_path: Path):
    sup, telegram = _make_supervisor(tmp_path, name="a")
    sup._send_help()
    text = telegram.messages[0]
    assert "a sync" in text
    assert "only answers to 'a'" in text
