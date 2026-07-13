"""The supervisor's main loop and state machine.

Fixes the two structural failures of the old container:

1. The Telegram listener runs in every state, so remote reauthentication is
   available exactly when it is needed (the old container only polled
   Telegram after a successful sync — an expired cookie made reauth
   unreachable and restart-looped the container).

2. Apple is never contacted in an unattended retry loop. Full password
   authentications are counted against a persisted daily budget; when the
   budget is spent, the supervisor waits for a human instead of retrying.
"""

from __future__ import annotations

import logging
import queue
import time

from .config import Config
from .cookies import (
    backup_auth_files,
    discard_backups,
    read_cookie_status,
    recover_stale_backups,
    restore_auth_files,
)
from .runner import IcloudpdRunner, RunResult
from .state import PersistedState, StatusFile, SupervisorState
from .telegram import Command, TelegramClient
from .webui import WebUIBridge, WebUIState

logger = logging.getLogger(__name__)

PERSONAL_LIBRARY = "PrimarySync"


class Supervisor:
    def __init__(
        self,
        config: Config,
        telegram: TelegramClient | None,
        commands: "queue.Queue[Command]",
        runner: IcloudpdRunner | None = None,
        webui: WebUIBridge | None = None,
    ) -> None:
        self.config = config
        self.telegram = telegram
        self.commands = commands
        self.runner = runner or IcloudpdRunner(config)
        self.webui = webui or WebUIBridge()
        self.state = SupervisorState.STARTING
        self.status_file = StatusFile(config.status_file)
        self.persisted = PersistedState.load(config.state_file)
        # Schedule from persisted history: a container restart must NOT
        # trigger an immediate sync, or restart loops turn into Apple
        # hammering — the exact failure mode of the old container.
        if self.persisted.last_sync_time:
            self.next_sync_time = max(
                time.time(), self.persisted.last_sync_time + config.download_interval
            )
        else:
            self.next_sync_time = time.time()
        self._stop = False
        # Recover from a container death mid-reauth at construction time, so
        # every entry point (not just run_forever) sees consistent cookies.
        self._recovered_backups = recover_stale_backups(config.config_dir, config.apple_id)
        self._resolved_libraries: list[str] | None = None
        # MFA round-trip state (only meaningful while a run is in flight).
        # Deadlines use wall-clock time: an NTP step can shorten/extend one
        # MFA window, which is recoverable (send 'sync' again) — accepted.
        self._mfa_prompted_at: float | None = None
        self._mfa_deadline: float | None = None
        self._mfa_submitted_at: float | None = None
        self._mfa_prompt_delivered = False
        self._mfa_prompt_last_try = 0.0
        self._pending_code: str | None = None
        self._auth_recorded_this_run = False
        self._last_webui_poll = 0.0
        self._last_tick_status_write = 0.0
        self._last_loop_error_notify = 0.0

    # --- messaging helpers -------------------------------------------------

    def notify(self, text: str, silent: bool = False) -> bool:
        logger.info("Notify: %s", text)
        if self.telegram:
            return self.telegram.send(text, silent=silent)
        return True  # nothing to deliver counts as delivered

    def _set_state(self, state: SupervisorState) -> None:
        if state != self.state:
            logger.info("State: %s -> %s", self.state.value, state.value)
            self.state = state
        self._write_status()

    def _write_status(self) -> None:
        cookie = read_cookie_status(self.config.config_dir, self.config.apple_id)
        self.status_file.write(
            self.state,
            last_sync_time=self.persisted.last_sync_time,
            last_sync_ok=self.persisted.last_sync_ok,
            cookie_days_remaining=cookie.days_remaining,
            next_sync_time=self.next_sync_time,
            auth_attempts_last_day=self.persisted.auth_attempts_last_day(),
        )

    # --- auth budget --------------------------------------------------------

    def _auth_budget_remaining(self) -> int:
        return max(
            0, self.config.max_auth_per_day - self.persisted.auth_attempts_last_day()
        )

    def _record_auth_attempt(self) -> None:
        self.persisted.record_auth_attempt()
        self.persisted.save(self.config.state_file)
        logger.info(
            "Password authentication recorded (%d/%d in last 24h)",
            self.persisted.auth_attempts_last_day(),
            self.config.max_auth_per_day,
        )

    def _bridged_run(
        self, args: list[str], timeout: float, collect_output: bool = False
    ) -> tuple[RunResult, bool]:
        """Run icloudpd with webui<->Telegram bridging and budget accounting.

        Returns (result, mfa_was_pending). Budget entries for MFA-observed
        runs are written the moment the prompt appears (see tick) so a kill
        or restart mid-wait cannot lose them; a session-token rotation
        without an observed prompt is recorded here after the run.
        """
        self._reset_mfa_flow()
        self._auth_recorded_this_run = False
        result = self.runner.run(
            args,
            tick=self._tick_during_run,
            timeout=timeout,
            collect_output=collect_output,
        )
        if result.performed_password_auth and not self._auth_recorded_this_run:
            self._record_auth_attempt()
        mfa_was_pending = self._mfa_prompted_at is not None
        self._reset_mfa_flow()
        return result, mfa_was_pending

    # --- MFA bridging during a run -------------------------------------------

    def _reset_mfa_flow(self) -> None:
        self._mfa_prompted_at = None
        self._mfa_deadline = None
        self._mfa_submitted_at = None
        self._mfa_prompt_delivered = False
        self._mfa_prompt_last_try = 0.0
        self._pending_code = None

    def _tick_during_run(self) -> bool:
        """Called ~once/second while icloudpd runs.

        Bridges webui <-> Telegram. Returns False to abort the run (MFA wait
        expired with no code from the user).
        """
        now = time.time()

        # A stop request (SIGTERM) aborts the run for a prompt shutdown;
        # otherwise Docker's stop timeout expires and the container is
        # SIGKILLed mid-download.
        if self._stop:
            logger.info("Stop requested — aborting current run")
            return False

        # Keep the healthcheck's liveness beacon fresh during long downloads:
        # the main loop is blocked while a run is in flight.
        if now - self._last_tick_status_write > 60:
            self._last_tick_status_write = now
            self._write_status()

        # Drain Telegram commands that make sense mid-run.
        while True:
            try:
                command = self.commands.get_nowait()
            except queue.Empty:
                break
            if command.kind == "code":
                self._handle_code_mid_run(command.value)
            elif command.kind == "status":
                self._send_status_report()
            elif command.kind == "help":
                self._send_help()
            else:
                self.notify(
                    f"A run is already in progress — '{command.kind}' was ignored. "
                    "Send it again once the current run finishes.",
                    silent=True,
                )

        # Poll the webui at most every 2 seconds.
        if now - self._last_webui_poll < 2:
            return True
        self._last_webui_poll = now
        status = self.webui.status()

        if status.state == WebUIState.CHECKING:
            # A submitted code is being verified — neither success nor
            # rejection yet. (Classifying this as success loses Apple's
            # rejection feedback; icloudpd returns to NEED_MFA on a bad code.)
            return True
        if status.state == WebUIState.NEED_MFA:
            if self._mfa_submitted_at and status.error:
                # Our submitted code came back rejected.
                self.notify(
                    f"❌ Apple rejected the code: {status.error}\n"
                    "Reply with a fresh 6-digit code to try again."
                )
                self._mfa_submitted_at = None
            if self._mfa_prompted_at is None:
                self._mfa_prompted_at = now
                self._mfa_deadline = now + self.config.mfa_timeout
                self._set_state(SupervisorState.WAITING_FOR_MFA)
                if not self._auth_recorded_this_run:
                    # Record the budget entry immediately: a kill/restart
                    # during the (up to 30-minute) MFA wait must not lose it.
                    self._record_auth_attempt()
                    self._auth_recorded_this_run = True
                self._mfa_prompt_delivered = self.notify(
                    "🔐 iCloud needs a new two-factor code. A push notification "
                    "has been sent to your Apple devices.\n"
                    f"Reply with the 6-digit code within {self.config.mfa_timeout // 60} "
                    "minutes to continue."
                )
                self._mfa_prompt_last_try = now
                if self._pending_code:
                    # The user sent a code before we noticed the prompt
                    # (e.g. straight after the Apple push) — use it.
                    code, self._pending_code = self._pending_code, None
                    self._handle_code_mid_run(code)
            elif self._mfa_deadline is not None and now > self._mfa_deadline:
                self.notify(
                    "⏰ No two-factor code received in time — pausing until the "
                    "next scheduled sync. Send 'sync' to try again."
                )
                # Do NOT reset the flow here: _bridged_run must still see
                # mfa_was_pending=True so it suppresses the redundant
                # "sync failed (exit -15)" message for the run we ourselves
                # are terminating. It resets the flow after the run.
                return False
            elif not self._mfa_prompt_delivered and now - self._mfa_prompt_last_try > 60:
                # Telegram was unreachable when the prompt was first sent;
                # keep retrying while the MFA wait lasts.
                self._mfa_prompt_delivered = self.notify(
                    "🔐 (retry) iCloud needs a two-factor code — reply with the "
                    "6-digit code."
                )
                self._mfa_prompt_last_try = now
        elif status.state in (WebUIState.IDLE, WebUIState.UNREACHABLE):
            if self._mfa_submitted_at is not None:
                # Left NEED_MFA after our submission: authenticated.
                self.notify("✅ Two-factor authentication successful.")
                self._reset_mfa_flow()
                self._set_state(SupervisorState.SYNCING)
        elif status.state == WebUIState.NEED_PASSWORD:
            # We only use the keyring password provider, so this should not
            # happen; never relay passwords through Telegram.
            logger.error("icloudpd is asking for a password via webui; aborting run")
            self.notify(
                "❌ iCloud is asking for your password, which cannot be supplied "
                "remotely. Run: docker exec -it <container> icloudpd-supervisor init"
            )
            return False
        return True

    def _handle_code_mid_run(self, code: str) -> None:
        if self._mfa_prompted_at is None:
            # Possibly ahead of us: the user saw Apple's push before our poll
            # noticed NEED_MFA. Buffer the code; the tick submits it when the
            # prompt appears (cleared at run end).
            self._pending_code = code
            self.notify(
                "No code has been requested yet — I'll use this one if a "
                "2FA prompt appears during the current run.",
                silent=True,
            )
            return
        if self.webui.submit_code(code):
            self._mfa_submitted_at = time.time()
            self.notify("Code received — verifying with Apple…", silent=True)
        else:
            self.notify("❌ Could not deliver the code to icloudpd. Try again.")

    # --- sync cycle ----------------------------------------------------------

    def _resolve_libraries(self) -> list[str]:
        """Map configured library aliases to real names, caching the result.

        The lookup runs through the same bridged run() path as syncs so that
        an auth-needed state during --list-libraries still reaches Telegram
        (and its password sign-in counts against the budget).
        """
        if self._resolved_libraries is not None:
            return self._resolved_libraries
        aliases = self.config.libraries
        needs_lookup = any(a.lower() == "shared" for a in aliases)
        available: list[str] = []
        if needs_lookup:
            result, _mfa = self._bridged_run(
                self.runner.list_libraries_args(),
                timeout=self.config.mfa_timeout + 600,
                collect_output=True,
            )
            if result.exit_code != 0:
                logger.error("--list-libraries failed (exit %d)", result.exit_code)
            available = self.runner.parse_library_names(result.output_lines)
            logger.info("Available libraries: %s", available)
        resolved: list[str] = []
        for alias in aliases:
            low = alias.lower()
            if low == "personal":
                resolved.append(PERSONAL_LIBRARY)
            elif low == "shared":
                shared = [name for name in available if name.startswith("SharedSync")]
                if shared:
                    resolved.extend(shared)
                else:
                    self.notify(
                        "⚠️ No shared library found on this account; skipping it."
                    )
            else:
                resolved.append(alias)
        # Preserve order, drop duplicates.
        seen: set[str] = set()
        resolved = [x for x in resolved if not (x in seen or seen.add(x))]
        if resolved:
            self._resolved_libraries = resolved
        return resolved

    def run_sync_cycle(self, manual: bool = False) -> None:
        if not self._keyring_ready():
            # Re-check periodically, NOT on every ~1s loop iteration —
            # _keyring_ready notifies, and a 1s cadence floods the chat.
            self.next_sync_time = time.time() + 300
            return
        if self._auth_budget_remaining() == 0:
            cookie = read_cookie_status(self.config.config_dir, self.config.apple_id)
            if not cookie.valid:
                # A sync now would trigger yet another password sign-in.
                self._set_state(SupervisorState.AUTH_RATE_LIMITED)
                if manual:
                    self.notify(
                        "🛑 Authentication budget exhausted "
                        f"({self.config.max_auth_per_day} password sign-ins in 24h). "
                        "Refusing to contact Apple again today to protect the "
                        "account from being locked. The budget resets as attempts "
                        "age out."
                    )
                logger.warning("Skipping sync: auth budget exhausted and cookie invalid")
                # Earliest possible retry is when the oldest attempt ages out.
                oldest = min(self.persisted.auth_attempts, default=time.time())
                self.next_sync_time = max(time.time() + 300, oldest + 86400)
                return

        self._set_state(SupervisorState.SYNCING)
        self._reset_mfa_flow()
        libraries = self._resolve_libraries()
        if not libraries:
            self.notify("❌ Could not resolve any photo library to download.")
            self._finish_cycle(ok=False)
            return

        total_downloaded = 0
        ok = True
        for library in libraries:
            logger.info("Syncing library: %s", library)
            result, mfa_was_pending = self._bridged_run(
                self.runner.sync_args(library), timeout=86400
            )
            if result.exit_code != 0:
                ok = False
                detail = "\n".join(result.tail[-5:])
                if not result.timed_out and not mfa_was_pending:
                    self.notify(
                        f"❌ Sync of {library} failed (exit {result.exit_code}).\n"
                        f"Last output:\n{detail}"
                    )
                # An auth problem affects every library: stop the cycle.
                break
            total_downloaded += result.downloaded

        if ok and total_downloaded > 0:
            self.notify(f"📷 Downloaded {total_downloaded} new item(s) from iCloud.")
        self._finish_cycle(ok=ok)

    def _finish_cycle(self, ok: bool) -> None:
        self.persisted.last_sync_time = time.time()
        self.persisted.last_sync_ok = ok
        self.persisted.save(self.config.state_file)
        self.next_sync_time = time.time() + self.config.download_interval
        self._set_state(SupervisorState.IDLE)
        logger.info(
            "Next sync at %s",
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.next_sync_time)),
        )

    def _keyring_ready(self) -> bool:
        from pathlib import Path

        keyring_file = Path(self.config.config_dir) / "python_keyring" / "keyring_pass.cfg"
        if keyring_file.is_file() and keyring_file.stat().st_size > 0:
            return True
        self._set_state(SupervisorState.PASSWORD_NEEDED)
        if time.time() - getattr(self, "_last_keyring_notify", 0.0) > 3600:
            self._last_keyring_notify = time.time()
            self.notify(
                "🔑 No iCloud password is stored yet. Run:\n"
                "docker exec -it <container> icloudpd-supervisor init",
                silent=True,
            )
        return False

    # --- reauth ---------------------------------------------------------------

    def run_reauth(self) -> None:
        """Explicit re-authentication: obtain a fresh MFA trust cookie.

        The old cookies are backed up and restored on failure — the old
        container deleted them up front, so a failed reauth stranded the
        account with no cookie at all.
        """
        if not self._keyring_ready():
            return
        if self._auth_budget_remaining() == 0:
            self.notify(
                "🛑 Authentication budget exhausted "
                f"({self.config.max_auth_per_day} password sign-ins in 24h). "
                "Try again later; the budget frees up as attempts age out."
            )
            return
        self.notify("Starting iCloud re-authentication…", silent=True)
        self._set_state(SupervisorState.SYNCING)
        backups = backup_auth_files(self.config.config_dir, self.config.apple_id)
        for original, _backup in backups:
            original.unlink()  # force a full sign-in so a fresh trust cookie is issued
        result, _mfa = self._bridged_run(
            self.runner.auth_only_args(), timeout=self.config.mfa_timeout + 300
        )
        if result.exit_code == 0:
            discard_backups(backups)
            cookie = read_cookie_status(self.config.config_dir, self.config.apple_id)
            days = cookie.days_remaining
            self.notify(
                "✅ Re-authentication complete."
                + (f" The new cookie is valid for about {days} days." if days else "")
            )
        else:
            restore_auth_files(backups)
            detail = "\n".join(result.tail[-5:])
            self.notify(
                "❌ Re-authentication failed — your previous cookies were restored.\n"
                f"Last output:\n{detail}"
            )
        self._set_state(SupervisorState.IDLE)

    # --- reports ---------------------------------------------------------------

    def _send_status_report(self) -> None:
        cookie = read_cookie_status(self.config.config_dir, self.config.apple_id)
        if cookie.days_remaining is not None:
            cookie_line = f"MFA cookie valid for ~{cookie.days_remaining} day(s)"
        elif cookie.exists:
            cookie_line = "MFA cookie present but not readable/valid"
        else:
            cookie_line = "No MFA cookie — send 'reauth' to authenticate"
        last = self.persisted.last_sync_time
        last_line = (
            time.strftime("%Y-%m-%d %H:%M", time.localtime(last)) if last else "never"
        )
        next_line = time.strftime(
            "%Y-%m-%d %H:%M", time.localtime(self.next_sync_time)
        )
        ok = self.persisted.last_sync_ok
        ok_line = "ok" if ok else ("failed" if ok is not None else "n/a")
        self.notify(
            f"ℹ️ State: {self.state.value}\n"
            f"{cookie_line}\n"
            f"Last sync: {last_line} ({ok_line})\n"
            f"Next sync: {next_line}\n"
            f"Auth budget used: {self.persisted.auth_attempts_last_day()}"
            f"/{self.config.max_auth_per_day} (24h)",
            silent=True,
        )

    def _send_help(self) -> None:
        self.notify(
            "Commands:\n"
            "sync — start a sync now\n"
            "reauth — get a fresh 2FA cookie\n"
            "status — show current state\n"
            "<6-digit code> — answer a 2FA prompt",
            silent=True,
        )

    def _check_cookie_expiry(self) -> None:
        cookie = read_cookie_status(self.config.config_dir, self.config.apple_id)
        days = cookie.days_remaining
        if days is None or days > self.config.notification_days:
            return
        if time.time() - self.persisted.last_expiry_warning < 86400:
            return
        self.persisted.last_expiry_warning = time.time()
        self.persisted.save(self.config.state_file)
        if days < 1:
            self.notify(
                "🚨 Your iCloud 2FA cookie has expired. Send 'reauth' to "
                "re-authenticate via Telegram."
            )
        else:
            self.notify(
                f"⚠️ Your iCloud 2FA cookie expires in {days} day(s). "
                "Send 'reauth' to renew it now."
            )

    # --- main loop ----------------------------------------------------------------

    def stop(self) -> None:
        self._stop = True

    def run_forever(self) -> None:
        if self._recovered_backups:
            self.notify(
                "♻️ Restored cookies from an interrupted re-authentication.",
                silent=True,
            )
        cookie = read_cookie_status(self.config.config_dir, self.config.apple_id)
        days = cookie.days_remaining
        self.notify(
            "▶️ icloudpd-supervisor started."
            + (f" MFA cookie valid ~{days} day(s)." if days is not None else "")
            + " Send 'help' for commands.",
            silent=True,
        )
        self._set_state(SupervisorState.IDLE)
        last_status_write = 0.0
        while not self._stop:
            try:
                try:
                    command = self.commands.get(timeout=1)
                except queue.Empty:
                    command = None
                if command:
                    if command.kind == "sync":
                        self.notify("Starting sync…", silent=True)
                        self.run_sync_cycle(manual=True)
                    elif command.kind == "reauth":
                        self.run_reauth()
                    elif command.kind == "status":
                        self._send_status_report()
                    elif command.kind == "help":
                        self._send_help()
                    elif command.kind == "code":
                        self.notify(
                            "No two-factor code is being requested right now.", silent=True
                        )
                if time.time() >= self.next_sync_time:
                    self.run_sync_cycle()
                self._check_cookie_expiry()
                if time.time() - last_status_write > 10:
                    self._write_status()
                    last_status_write = time.time()
            except Exception:
                # The supervisor must never crash-loop: an unexpected error
                # is logged and the loop continues. (Exiting would hand
                # control to Docker's restart policy — the old container's
                # account-locking failure mode.)
                logger.exception("Unexpected error in supervisor loop; continuing")
                if time.time() - self._last_loop_error_notify > 3600:
                    self._last_loop_error_notify = time.time()
                    self.notify(
                        "⚠️ Internal error (see container log). "
                        "The supervisor is still running.",
                        silent=True,
                    )
                time.sleep(5)
        logger.info("Supervisor stopped")
