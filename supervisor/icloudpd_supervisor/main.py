"""Entrypoint.

Subcommands:
  (none)      run the supervisor (container CMD)
  init        interactively store the iCloud password in the keyring and
              perform the first authentication (docker exec -it ... init)
  healthcheck exit 0 if the supervisor loop is alive (Docker HEALTHCHECK)
"""

from __future__ import annotations

import logging
import os
import queue
import signal
import subprocess
import sys
from pathlib import Path

from .config import Config, ConfigError, load_config
from .cookies import read_cookie_status
from .runner import IcloudpdRunner
from .scheduler import Supervisor
from .telegram import Command, TelegramClient, TelegramListener

logger = logging.getLogger(__name__)


def _setup_logging(debug: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if debug else logging.INFO,
        format="%(asctime)s %(levelname)-8s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stdout,
    )


def _drop_privileges(config: Config) -> None:
    """If running as root, become the configured user for everything we do.

    The whole process drops — there is no root helper left behind. File
    ownership of /config and the download path is the operator's concern
    (documented), which removes the old container's 200 lines of recursive
    chown/chmod at every start.
    """
    if os.getuid() != 0:
        return
    uid, gid = config.user_id, config.group_id
    if uid == 0 or gid == 0:
        logger.warning("user_id/group_id 0 requested; staying root")
        return
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)
    logger.info("Dropped privileges to %d:%d", uid, gid)


def _setup_process_env(config: Config) -> None:
    """Force a coherent environment for us and every icloudpd subprocess.

    Must be UNCONDITIONAL: the container starts as root with HOME=/root, and
    after the privilege drop the inherited HOME makes the keyring library
    stat ~/.config/python_keyring/keyringrc.cfg inside /root — a
    PermissionError for the download user (the legacy container avoided
    this only because `su` reset HOME). A setdefault is not enough.
    """
    os.environ["XDG_DATA_HOME"] = config.config_dir  # keyring_pass.cfg location
    os.environ["HOME"] = "/tmp"
    os.environ["XDG_CONFIG_HOME"] = "/tmp/.config"  # keyringrc.cfg lookup, readable


def _preflight(config: Config) -> None:
    problems = []
    if not Path(config.download_path).is_dir():
        problems.append(f"download path does not exist: {config.download_path}")
    elif not os.access(config.download_path, os.W_OK):
        problems.append(f"download path is not writable: {config.download_path}")
    if not os.access(config.config_dir, os.W_OK):
        problems.append(f"config dir is not writable: {config.config_dir}")
    if not Path(config.icloudpd_bin).is_file():
        problems.append(f"icloudpd not found at {config.icloudpd_bin}")
    if problems:
        for problem in problems:
            logger.error("Preflight: %s", problem)
        raise ConfigError("; ".join(problems))


def run_supervisor(config: Config) -> int:
    import threading

    _preflight(config)
    commands: "queue.Queue[Command]" = queue.Queue()
    poll_urgency = threading.Event()
    telegram = None
    if config.telegram_enabled:
        telegram = TelegramClient(
            base_url=config.telegram_base_url,
            chat_id=config.telegram_chat_id,
            offset_file=str(Path(config.config_dir) / "telegram_update_id.num"),
            sender_id=config.telegram_sender_id,
        )
        if config.name:
            # Named instance: commands must be prefixed ("a sync"), so
            # several containers can share one chat (and one bot token —
            # hence short polling in the client) without all of them
            # reacting to a bare "sync" or 2FA code.
            listener = TelegramListener(
                telegram,
                commands,
                aliases=(config.name,),
                require_prefix=True,
                interval=config.telegram_poll_interval,
                urgent=poll_urgency,
            )
        else:
            listener = TelegramListener(
                telegram,
                commands,
                aliases=("user", "icloudpd"),
                interval=config.telegram_poll_interval,
                urgent=poll_urgency,
            )
        listener.start()
    else:
        logger.warning(
            "Telegram is not configured: remote 2FA will not be available. "
            "Set telegram_token and telegram_chat_id."
        )

    supervisor = Supervisor(config, telegram, commands, poll_urgency=poll_urgency)

    def handle_term(_signum: int, _frame: object) -> None:
        logger.info("Received SIGTERM, shutting down")
        supervisor.stop()

    signal.signal(signal.SIGTERM, handle_term)
    signal.signal(signal.SIGINT, handle_term)
    supervisor.run_forever()
    return 0


def run_init(config: Config) -> int:
    """Interactive first-time setup: store password, then authenticate."""
    print(f"Storing iCloud password for {config.apple_id} in the keyring.")
    result = subprocess.run(
        [config.icloud_bin, "--username", config.apple_id, "--domain", config.auth_domain]
    )
    if result.returncode != 0:
        print("Password storage failed.", file=sys.stderr)
        return result.returncode
    print("Password stored. Performing initial authentication (console prompts).")
    result = subprocess.run(
        [
            config.icloudpd_bin,
            "--username", config.apple_id,
            "--cookie-directory", config.config_dir,
            "--domain", config.auth_domain,
            "--auth-only",
            "--password-provider", "keyring",
            "--mfa-provider", "console",
        ]
    )
    if result.returncode == 0:
        cookie = read_cookie_status(config.config_dir, config.apple_id)
        days = cookie.days_remaining
        print(f"Authenticated. Cookie valid for ~{days} day(s)." if days else "Authenticated.")
    return result.returncode


def run_healthcheck(config: Config) -> int:
    import json
    import time

    try:
        payload = json.loads(Path(config.status_file).read_text())
    except (OSError, ValueError):
        print("status file missing/unreadable")
        return 1
    age = time.time() - float(payload.get("updated_at", 0))
    # The main loop writes at least every ~10s; syncs tick every second but
    # the status file is refreshed by state transitions. Allow generous slack.
    if age > 900:
        print(f"supervisor loop stale ({int(age)}s)")
        return 1
    print(f"ok: {payload.get('state')} (updated {int(age)}s ago)")
    return 0


def main() -> None:
    command = sys.argv[1] if len(sys.argv) > 1 else ""
    try:
        config = load_config()
    except ConfigError as exc:
        # Healthcheck must not fail the container for a config error at
        # startup; the supervisor itself reports it.
        print(f"Configuration error: {exc}", file=sys.stderr)
        sys.exit(0 if command == "healthcheck" else 2)

    _setup_logging(config.debug_logging)

    if command == "healthcheck":
        sys.exit(run_healthcheck(config))

    _drop_privileges(config)
    _setup_process_env(config)
    Path(config.status_file).parent.mkdir(parents=True, exist_ok=True)

    if command == "init":
        sys.exit(run_init(config))
    elif command == "":
        try:
            sys.exit(run_supervisor(config))
        except ConfigError:
            # Do NOT exit: a restart policy would loop the container without
            # fixing anything. Stay alive so the operator can inspect.
            logger.error("Fatal preflight problem; sleeping. Fix the config and restart.")
            signal.pause()
    else:
        print(f"Unknown command: {command}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
