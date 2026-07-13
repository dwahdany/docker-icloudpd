"""Configuration: environment variables first, legacy /config/icloudpd.conf as fallback.

Precedence: environment variable > legacy config file > default.

Legacy compatibility: the old container wrote a flat key=value file at
/config/icloudpd.conf. We read the keys we still support from it so an
existing volume keeps working without changes.
"""

from __future__ import annotations

import os
import shlex
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_CONFIG_DIR = "/config"
LEGACY_CONF_NAME = "icloudpd.conf"

# Keys we read from the legacy config file (legacy name -> our name).
# Anything not listed here is intentionally unsupported by the rewrite.
_LEGACY_KEYS = {
    "name": "name",
    # The legacy container's Telegram command prefix was the local username;
    # it doubles as the instance-name fallback so migrated multi-account
    # volumes keep their "a auth" / "b auth" routing.
    "user": "legacy_user",
    "apple_id": "apple_id",
    "download_path": "download_path",
    "folder_structure": "folder_structure",
    "download_interval": "download_interval",
    "notification_days": "notification_days",
    "telegram_token": "telegram_token",
    "telegram_chat_id": "telegram_chat_id",
    "telegram_server": "telegram_server",
    "telegram_http": "telegram_http",
    "photo_size": "photo_size",
    "skip_videos": "skip_videos",
    "skip_live_photos": "skip_live_photos",
    "photo_library": "libraries",  # single legacy library -> libraries list
    "auth_china": "auth_china",
    "debug_logging": "debug_logging",
    "user_id": "user_id",
    "group_id": "group_id",
}

_TRUTHY = {"true", "1", "yes", "on"}


def _parse_bool(value: str | bool | None, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None or not value.strip():
        return default
    return value.strip().lower() in _TRUTHY


class ConfigError(Exception):
    """Fatal configuration problem. Message is user-facing."""


@dataclass
class Config:
    apple_id: str = ""
    # Instance name: prefixes every Telegram notification ("[a] ...") and
    # namespaces commands ("a sync", "a 123456", bare "a" = sync now). When
    # set, UNprefixed commands are ignored — required when several
    # containers share one chat, otherwise all of them would react to a
    # bare "sync" or 2FA code. Falls back to the legacy conf's `user` key.
    name: str = ""
    config_dir: str = DEFAULT_CONFIG_DIR
    download_path: str = "/icloud"
    folder_structure: str = "{:%Y/%m/%d}"
    download_interval: int = 86400
    # "personal" (PrimarySync), "shared" (auto-resolved SharedSync-*),
    # or an explicit library name as printed by --list-libraries.
    libraries: list[str] = field(default_factory=lambda: ["personal"])
    photo_size: str = "original"
    skip_videos: bool = False
    skip_live_photos: bool = False
    # Escape hatch: extra args appended verbatim to every sync invocation.
    extra_args: list[str] = field(default_factory=list)

    telegram_token: str = ""
    telegram_chat_id: str = ""
    # Optional: only accept commands from this Telegram user id (group chats
    # share the chat_id, so chat filtering alone is not a sender check).
    telegram_sender_id: str = ""
    telegram_server: str = ""  # optional self-hosted bot API server (host[:port])
    telegram_http: bool = False  # plain http for self-hosted server
    # Seconds between getUpdates short polls (drops to ~3s while a 2FA
    # prompt is waiting). Short polling is deliberate: it lets several
    # instances share one bot token, which long polling cannot.
    telegram_poll_interval: int = 20

    notification_days: int = 7
    auth_china: bool = False
    debug_logging: bool = False

    # Lockout protection: max full password authentications per rolling 24h.
    max_auth_per_day: int = 3
    # How long to wait for the user to supply an MFA code before aborting a run.
    mfa_timeout: int = 1800
    # NOTE: icloudpd 1.32.3 hardcodes its webui on port 8080 (waitress.serve
    # with no arguments) — the port is intentionally not configurable here.

    # Privilege drop target when the container starts as root.
    user_id: int = 1000
    group_id: int = 1000

    icloudpd_bin: str = "/opt/icloudpd/bin/icloudpd"
    icloud_bin: str = "/opt/icloudpd/bin/icloud"
    status_file: str = "/tmp/icloudpd/status.json"
    state_file: str = ""  # persisted supervisor state; defaults under config_dir

    @property
    def auth_domain(self) -> str:
        return "cn" if self.auth_china else "com"

    @property
    def telegram_base_url(self) -> str:
        scheme = "http" if self.telegram_http else "https"
        server = self.telegram_server or "api.telegram.org"
        return f"{scheme}://{server}/bot{self.telegram_token}"

    @property
    def telegram_enabled(self) -> bool:
        return bool(self.telegram_token and self.telegram_chat_id)

    def validate(self) -> None:
        if not self.apple_id:
            raise ConfigError(
                "apple_id is not set. Set the apple_id environment variable "
                f"or add apple_id=... to {Path(self.config_dir) / LEGACY_CONF_NAME}"
            )
        if self.download_interval < 3600:
            raise ConfigError("download_interval must be at least 3600 seconds")
        if not self.libraries:
            raise ConfigError("libraries must not be empty")
        if not self.telegram_enabled and (self.telegram_token or self.telegram_chat_id):
            raise ConfigError(
                "Telegram is partially configured: both telegram_token and "
                "telegram_chat_id are required"
            )


def _read_legacy_conf(path: Path) -> dict[str, str]:
    """Read key=value pairs from the legacy config file, ignoring comments."""
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"')
        if key in _LEGACY_KEYS and value:
            values[_LEGACY_KEYS[key]] = value
    return values


def load_config(environ: dict[str, str] | None = None) -> Config:
    """Build a Config from the environment plus the legacy config file."""
    env = dict(environ if environ is not None else os.environ)
    config_dir = env.get("config_dir") or env.get("CONFIG_DIR") or DEFAULT_CONFIG_DIR
    legacy = _read_legacy_conf(Path(config_dir) / LEGACY_CONF_NAME)

    def get(key: str, default: str = "") -> str:
        # Environment beats legacy file; accept both lower and upper case env names.
        return env.get(key) or env.get(key.upper()) or legacy.get(key, default)

    cfg = Config(config_dir=config_dir)
    cfg.apple_id = get("apple_id").strip()
    # NB: the legacy-user fallback reads only the conf FILE, never the
    # process environment — $USER from the shell must not become a name.
    cfg.name = (get("name") or legacy.get("legacy_user", "")).strip()
    cfg.download_path = get("download_path", cfg.download_path).rstrip("/") or "/"
    cfg.folder_structure = get("folder_structure", cfg.folder_structure)
    cfg.photo_size = get("photo_size", cfg.photo_size)
    cfg.skip_videos = _parse_bool(get("skip_videos"), cfg.skip_videos)
    cfg.skip_live_photos = _parse_bool(get("skip_live_photos"), cfg.skip_live_photos)
    cfg.telegram_token = get("telegram_token")
    cfg.telegram_chat_id = get("telegram_chat_id")
    cfg.telegram_sender_id = get("telegram_sender_id")
    cfg.telegram_server = get("telegram_server")
    cfg.telegram_http = _parse_bool(get("telegram_http"), cfg.telegram_http)
    cfg.auth_china = _parse_bool(get("auth_china"), cfg.auth_china)
    cfg.debug_logging = _parse_bool(get("debug_logging"), cfg.debug_logging)

    libraries = get("libraries")
    if libraries:
        cfg.libraries = [part.strip() for part in libraries.split(",") if part.strip()]

    extra = get("extra_icloudpd_args")
    if extra:
        cfg.extra_args = shlex.split(extra)

    for int_key in (
        "download_interval",
        "notification_days",
        "max_auth_per_day",
        "mfa_timeout",
        "telegram_poll_interval",
        "user_id",
        "group_id",
    ):
        raw = get(int_key)
        if raw:
            try:
                setattr(cfg, int_key, int(raw))
            except ValueError as exc:
                raise ConfigError(f"{int_key} must be an integer, got: {raw!r}") from exc

    cfg.icloudpd_bin = get("icloudpd_bin", cfg.icloudpd_bin)
    cfg.icloud_bin = get("icloud_bin", cfg.icloud_bin)
    cfg.status_file = get("status_file", cfg.status_file)
    cfg.state_file = get("state_file") or str(Path(config_dir) / "supervisor_state.json")

    cfg.validate()
    return cfg
