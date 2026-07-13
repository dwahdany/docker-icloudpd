"""Tests for icloudpd_supervisor.config.

Hermetic: every load_config() call is given an explicit `environ` dict with
config_dir pointed at tmp_path, so neither the real process environment nor
a real /config volume is ever consulted.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from icloudpd_supervisor.config import (
    LEGACY_CONF_NAME,
    Config,
    ConfigError,
    _parse_bool,
    _read_legacy_conf,
    load_config,
)

APPLE_ID = "user@example.com"


def make_env(tmp_path: Path, **overrides: str) -> dict[str, str]:
    """Baseline environ: isolated config_dir + a valid apple_id."""
    env = {"config_dir": str(tmp_path), "apple_id": APPLE_ID}
    env.update(overrides)
    return env


def write_conf(tmp_path: Path, text: str) -> Path:
    path = tmp_path / LEGACY_CONF_NAME
    path.write_text(textwrap.dedent(text), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# _parse_bool
# ---------------------------------------------------------------------------


def test_parse_bool_none_returns_default() -> None:
    assert _parse_bool(None) is False
    assert _parse_bool(None, default=True) is True


def test_parse_bool_bool_passthrough() -> None:
    assert _parse_bool(True) is True
    assert _parse_bool(False, default=True) is False


@pytest.mark.parametrize(
    "value", ["true", "True", "TRUE", " true ", "1", "yes", "YES", "on", "On", "\ton\n"]
)
def test_parse_bool_truthy_strings(value: str) -> None:
    assert _parse_bool(value) is True


@pytest.mark.parametrize(
    "value", ["false", "False", "0", "no", "off", "2", "enabled", "truthy", "", "  "]
)
def test_parse_bool_falsy_strings(value: str) -> None:
    assert _parse_bool(value) is False


def test_parse_bool_empty_string_uses_default() -> None:
    assert _parse_bool("", default=True) is True


# ---------------------------------------------------------------------------
# Precedence: environment > legacy file > default
# ---------------------------------------------------------------------------


def test_env_overrides_legacy(tmp_path: Path) -> None:
    write_conf(
        tmp_path,
        """\
        apple_id=legacy@example.com
        download_path=/legacy
        """,
    )
    cfg = load_config(make_env(tmp_path, download_path="/env"))
    assert cfg.apple_id == APPLE_ID
    assert cfg.download_path == "/env"


def test_legacy_used_when_env_missing(tmp_path: Path) -> None:
    write_conf(
        tmp_path,
        """\
        apple_id=legacy@example.com
        download_interval=7200
        photo_size=medium
        """,
    )
    cfg = load_config({"config_dir": str(tmp_path)})
    assert cfg.apple_id == "legacy@example.com"
    assert cfg.download_interval == 7200
    assert cfg.photo_size == "medium"


def test_defaults_when_neither_env_nor_legacy(tmp_path: Path) -> None:
    cfg = load_config(make_env(tmp_path))
    assert cfg.download_path == "/icloud"
    assert cfg.folder_structure == "{:%Y/%m/%d}"
    assert cfg.download_interval == 86400
    assert cfg.libraries == ["personal"]
    assert cfg.photo_size == "original"
    assert cfg.skip_videos is False
    assert cfg.extra_args == []
    assert cfg.telegram_enabled is False


def test_uppercase_env_names_accepted(tmp_path: Path) -> None:
    env = {
        "config_dir": str(tmp_path),
        "APPLE_ID": "upper@example.com",
        "DOWNLOAD_INTERVAL": "7200",
        "SKIP_VIDEOS": "true",
    }
    cfg = load_config(env)
    assert cfg.apple_id == "upper@example.com"
    assert cfg.download_interval == 7200
    assert cfg.skip_videos is True


def test_uppercase_env_beats_legacy(tmp_path: Path) -> None:
    write_conf(tmp_path, "download_path=/legacy\n")
    env = make_env(tmp_path, DOWNLOAD_PATH="/data/")
    cfg = load_config(env)
    assert cfg.download_path == "/data"


def test_lowercase_env_beats_uppercase_env(tmp_path: Path) -> None:
    env = {
        "config_dir": str(tmp_path),
        "apple_id": "lower@example.com",
        "APPLE_ID": "upper@example.com",
    }
    cfg = load_config(env)
    assert cfg.apple_id == "lower@example.com"


def test_empty_env_value_falls_back_to_legacy(tmp_path: Path) -> None:
    # An env var explicitly set to "" behaves like "unset" (shell semantics).
    write_conf(tmp_path, "photo_size=medium\n")
    cfg = load_config(make_env(tmp_path, photo_size=""))
    assert cfg.photo_size == "medium"


def test_uppercase_config_dir_env_honoured(tmp_path: Path) -> None:
    write_conf(tmp_path, f"apple_id={APPLE_ID}\n")
    cfg = load_config({"CONFIG_DIR": str(tmp_path)})
    assert cfg.config_dir == str(tmp_path)
    assert cfg.apple_id == APPLE_ID


# ---------------------------------------------------------------------------
# Legacy icloudpd.conf parsing
# ---------------------------------------------------------------------------


def test_read_legacy_conf_missing_file(tmp_path: Path) -> None:
    assert _read_legacy_conf(tmp_path / LEGACY_CONF_NAME) == {}


def test_read_legacy_conf_comments_blanks_and_garbage(tmp_path: Path) -> None:
    path = write_conf(
        tmp_path,
        """\
        # This is a comment
           # indented comment

        this line has no equals sign
        apple_id=legacy@example.com
        """,
    )
    assert _read_legacy_conf(path) == {"apple_id": "legacy@example.com"}


def test_read_legacy_conf_strips_double_quotes(tmp_path: Path) -> None:
    path = write_conf(
        tmp_path,
        """\
        apple_id="legacy@example.com"
        folder_structure="{:%Y/%m}"
        """,
    )
    values = _read_legacy_conf(path)
    assert values["apple_id"] == "legacy@example.com"
    assert values["folder_structure"] == "{:%Y/%m}"


def test_read_legacy_conf_spaces_around_equals(tmp_path: Path) -> None:
    path = write_conf(tmp_path, "download_path = /photos/\n")
    assert _read_legacy_conf(path) == {"download_path": "/photos/"}


def test_read_legacy_conf_unknown_keys_ignored(tmp_path: Path) -> None:
    path = write_conf(
        tmp_path,
        """\
        apple_id=legacy@example.com
        synchronisation_interval=60
        authentication_type=2FA
        icloud_china=false
        totally_made_up_key=value
        """,
    )
    assert _read_legacy_conf(path) == {"apple_id": "legacy@example.com"}


def test_read_legacy_conf_empty_values_skipped(tmp_path: Path) -> None:
    path = write_conf(
        tmp_path,
        """\
        photo_size=
        folder_structure=""
        apple_id=legacy@example.com
        """,
    )
    assert _read_legacy_conf(path) == {"apple_id": "legacy@example.com"}


def test_read_legacy_conf_photo_library_maps_to_libraries(tmp_path: Path) -> None:
    path = write_conf(tmp_path, "photo_library=SharedSync-ABC-123\n")
    assert _read_legacy_conf(path) == {"libraries": "SharedSync-ABC-123"}


def test_load_config_legacy_photo_library_becomes_libraries_list(tmp_path: Path) -> None:
    write_conf(
        tmp_path,
        f"""\
        apple_id={APPLE_ID}
        photo_library=Ye Olde Library
        """,
    )
    cfg = load_config({"config_dir": str(tmp_path)})
    assert cfg.libraries == ["Ye Olde Library"]


def test_env_libraries_beats_legacy_photo_library(tmp_path: Path) -> None:
    write_conf(tmp_path, "photo_library=OldLib\n")
    cfg = load_config(make_env(tmp_path, libraries="personal,shared"))
    assert cfg.libraries == ["personal", "shared"]


def test_load_config_full_legacy_file(tmp_path: Path) -> None:
    write_conf(
        tmp_path,
        """\
        # docker-icloudpd legacy config
        apple_id="legacy@example.com"
        download_path="/photos/user/"
        folder_structure={:%Y}
        download_interval=43200
        notification_days=14
        telegram_token="123:abc"
        telegram_chat_id="-100999"
        photo_size=medium
        skip_videos=true
        skip_live_photos=yes
        auth_china=false
        debug_logging=on
        user_id=1234
        group_id=4321
        """,
    )
    cfg = load_config({"config_dir": str(tmp_path)})
    assert cfg.apple_id == "legacy@example.com"
    assert cfg.download_path == "/photos/user"  # trailing slash stripped
    assert cfg.folder_structure == "{:%Y}"
    assert cfg.download_interval == 43200
    assert cfg.notification_days == 14
    assert cfg.telegram_token == "123:abc"
    assert cfg.telegram_chat_id == "-100999"
    assert cfg.telegram_enabled is True
    assert cfg.photo_size == "medium"
    assert cfg.skip_videos is True
    assert cfg.skip_live_photos is True
    assert cfg.auth_china is False
    assert cfg.debug_logging is True
    assert cfg.user_id == 1234
    assert cfg.group_id == 4321


# ---------------------------------------------------------------------------
# Integer coercion
# ---------------------------------------------------------------------------


def test_integer_fields_coerced_from_env(tmp_path: Path) -> None:
    cfg = load_config(
        make_env(
            tmp_path,
            download_interval="7200",
            notification_days="3",
            max_auth_per_day="5",
            mfa_timeout="600",
            user_id="500",
            group_id="501",
        )
    )
    assert cfg.download_interval == 7200
    assert cfg.notification_days == 3
    assert cfg.max_auth_per_day == 5
    assert cfg.mfa_timeout == 600
    assert cfg.user_id == 500
    assert cfg.group_id == 501


@pytest.mark.parametrize("bad", ["abc", "12h", "3600.5", "1e4"])
def test_non_integer_download_interval_raises(tmp_path: Path, bad: str) -> None:
    with pytest.raises(ConfigError, match="download_interval must be an integer"):
        load_config(make_env(tmp_path, download_interval=bad))


def test_non_integer_from_legacy_conf_raises(tmp_path: Path) -> None:
    write_conf(
        tmp_path,
        f"""\
        apple_id={APPLE_ID}
        notification_days=seven
        """,
    )
    with pytest.raises(ConfigError, match="notification_days must be an integer"):
        load_config({"config_dir": str(tmp_path)})


# ---------------------------------------------------------------------------
# validate()
# ---------------------------------------------------------------------------


def test_missing_apple_id_raises(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="apple_id is not set"):
        load_config({"config_dir": str(tmp_path)})


def test_interval_below_minimum_raises(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="at least 3600"):
        load_config(make_env(tmp_path, download_interval="3599"))


def test_interval_exactly_minimum_ok(tmp_path: Path) -> None:
    cfg = load_config(make_env(tmp_path, download_interval="3600"))
    assert cfg.download_interval == 3600


def test_partial_telegram_token_only_raises(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="partially configured"):
        load_config(make_env(tmp_path, telegram_token="123:abc"))


def test_partial_telegram_chat_id_only_raises(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="partially configured"):
        load_config(make_env(tmp_path, telegram_chat_id="-100999"))


def test_full_telegram_config_ok(tmp_path: Path) -> None:
    cfg = load_config(
        make_env(tmp_path, telegram_token="123:abc", telegram_chat_id="-100999")
    )
    assert cfg.telegram_enabled is True


def test_libraries_reduced_to_empty_raises(tmp_path: Path) -> None:
    # A libraries value of only commas/whitespace parses to an empty list.
    with pytest.raises(ConfigError, match="libraries must not be empty"):
        load_config(make_env(tmp_path, libraries=" , ,"))


def test_validate_direct_empty_libraries() -> None:
    cfg = Config(apple_id=APPLE_ID, libraries=[])
    with pytest.raises(ConfigError, match="libraries must not be empty"):
        cfg.validate()


# ---------------------------------------------------------------------------
# extra_icloudpd_args
# ---------------------------------------------------------------------------


def test_extra_args_shlex_split(tmp_path: Path) -> None:
    cfg = load_config(
        make_env(
            tmp_path,
            extra_icloudpd_args='--until-found 10 --skip-path "My Folder/Sub" -a org',
        )
    )
    assert cfg.extra_args == [
        "--until-found",
        "10",
        "--skip-path",
        "My Folder/Sub",
        "-a",
        "org",
    ]


def test_extra_args_single_quotes_and_escapes(tmp_path: Path) -> None:
    cfg = load_config(make_env(tmp_path, extra_icloudpd_args="--match 'a b' c\\ d"))
    assert cfg.extra_args == ["--match", "a b", "c d"]


def test_extra_args_default_empty(tmp_path: Path) -> None:
    cfg = load_config(make_env(tmp_path))
    assert cfg.extra_args == []


# ---------------------------------------------------------------------------
# download_path normalisation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("/icloud/", "/icloud"),
        ("/icloud", "/icloud"),
        ("/photos/user///", "/photos/user"),
        ("/", "/"),
        ("///", "/"),
    ],
)
def test_download_path_trailing_slash_normalisation(
    tmp_path: Path, raw: str, expected: str
) -> None:
    cfg = load_config(make_env(tmp_path, download_path=raw))
    assert cfg.download_path == expected


# ---------------------------------------------------------------------------
# Misc: libraries splitting, state_file default
# ---------------------------------------------------------------------------


def test_libraries_comma_split_with_whitespace(tmp_path: Path) -> None:
    cfg = load_config(make_env(tmp_path, libraries=" personal, shared ,My Library,"))
    assert cfg.libraries == ["personal", "shared", "My Library"]


def test_state_file_defaults_under_config_dir(tmp_path: Path) -> None:
    cfg = load_config(make_env(tmp_path))
    assert cfg.state_file == str(tmp_path / "supervisor_state.json")


def test_state_file_env_override(tmp_path: Path) -> None:
    cfg = load_config(make_env(tmp_path, state_file="/tmp/other-state.json"))
    assert cfg.state_file == "/tmp/other-state.json"


def test_auth_domain_property(tmp_path: Path) -> None:
    assert load_config(make_env(tmp_path)).auth_domain == "com"
    assert load_config(make_env(tmp_path, auth_china="true")).auth_domain == "cn"
