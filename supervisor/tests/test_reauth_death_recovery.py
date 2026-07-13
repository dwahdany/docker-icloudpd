"""Container death mid-reauth must not strand the account cookieless.

run_reauth (scheduler.py:334-336) copies cookie+session to *.reauth-backup and
then unlinks the originals BEFORE running icloudpd, which can then block up to
mfa_timeout+300s (~35 min by default) waiting for the user's MFA code.
Restore (scheduler.py:353) and discard (scheduler.py:345) live only inside
that call frame. If the process is SIGKILLed in that window (docker stop's
grace period expiring — SIGTERM only sets Supervisor._stop, which
_tick_during_run never checks — OOM kill, host reboot), the restarted
supervisor finds no cookie/session, immediately schedules a sync that performs
a full password sign-in + MFA prompt, and the possibly-still-valid backed-up
trust cookie sits on disk as *.reauth-backup forever: no startup code
references ".reauth-backup" (grep: only cookies.py:89 creates the name).

Hermetic: fake icloudpd (a sleeping shell script), fork+SIGKILL, temp dirs.
"""

from __future__ import annotations

import http.cookiejar
import os
import queue
import signal
import time
from pathlib import Path

import pytest

from icloudpd_supervisor.config import Config
from icloudpd_supervisor.cookies import cookie_path, read_cookie_status, session_path
from icloudpd_supervisor.scheduler import Supervisor

APPLE_ID = "user@example.com"


def _make_config(base: Path) -> Config:
    fake = base / "icloudpd"
    if not fake.exists():
        # Hangs like a real auth-only run waiting for the user's MFA code.
        fake.write_text("#!/bin/sh\nsleep 3600\n")
        fake.chmod(0o755)
    return Config(
        apple_id=APPLE_ID,
        config_dir=str(base / "config"),
        download_path=str(base / "photos"),
        icloudpd_bin=str(fake),
        icloud_bin=str(fake),
        status_file=str(base / "status.json"),
        state_file=str(base / "state.json"),
        mfa_timeout=1800,
    )


def _seed_valid_auth_files(config_dir: Path) -> None:
    jar = http.cookiejar.LWPCookieJar(
        filename=str(cookie_path(str(config_dir), APPLE_ID))
    )
    jar.set_cookie(
        http.cookiejar.Cookie(
            0, "X-APPLE-WEBAUTH-USER", "v", None, False, "idmsa.apple.com",
            True, False, "/", True, True, int(time.time()) + 20 * 86400,
            False, None, None, {},
        )
    )
    jar.save(ignore_discard=True, ignore_expires=True)
    session_path(str(config_dir), APPLE_ID).write_text('{"session_token": "tok"}')
    keyring_dir = config_dir / "python_keyring"
    keyring_dir.mkdir()
    (keyring_dir / "keyring_pass.cfg").write_text("[x]\npw = y\n")


def test_restart_after_death_mid_reauth_recovers_backed_up_cookie(tmp_path):
    config = _make_config(tmp_path)
    config_dir = Path(config.config_dir)
    config_dir.mkdir()
    Path(config.download_path).mkdir()
    _seed_valid_auth_files(config_dir)
    assert read_cookie_status(config.config_dir, APPLE_ID).valid

    # A child process runs run_reauth for real: it backs up + unlinks the
    # auth files, then blocks in runner.run on the hanging fake icloudpd.
    pid = os.fork()
    if pid == 0:  # child
        try:
            sup = Supervisor(config, telegram=None, commands=queue.Queue())
            sup.run_reauth()
        finally:
            os._exit(0)

    try:
        # Wait for run_reauth to pass line 336 (originals unlinked).
        deadline = time.time() + 15
        while time.time() < deadline and cookie_path(
            config.config_dir, APPLE_ID
        ).exists():
            time.sleep(0.05)
        assert not cookie_path(config.config_dir, APPLE_ID).exists(), (
            "run_reauth never reached the unlink step"
        )
        time.sleep(0.3)
    finally:
        os.kill(pid, signal.SIGKILL)  # container dies: OOM / reboot / SIGKILL
        os.waitpid(pid, 0)

    # Backups exist; originals do not — the on-disk state after death.
    assert list(config_dir.glob("*.reauth-backup"))
    assert not cookie_path(config.config_dir, APPLE_ID).exists()

    # "Container restart": a fresh Supervisor should recover the backed-up,
    # still-valid trust cookie (or at minimum clean up the stale backups)
    # instead of leaving the account facing a full password sign-in.
    Supervisor(config, telegram=None, commands=queue.Queue())
    restored = read_cookie_status(config.config_dir, APPLE_ID)
    assert restored.valid, (
        "restart left the account cookieless although a valid trust cookie "
        "sits in *.reauth-backup"
    )
    assert list(config_dir.glob("*.reauth-backup")) == []
