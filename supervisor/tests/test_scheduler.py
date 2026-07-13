"""Tests for icloudpd_supervisor.scheduler and icloudpd_supervisor.state.

Hermetic by construction: the icloudpd runner, the webui bridge and the
Telegram client are replaced with in-process fakes injected through the
Supervisor constructor, ``time.time`` is monkeypatched, and every file lives
under ``tmp_path``. No subprocess is spawned and no network I/O happens.

Tests marked ``xfail`` document real implementation bugs (see the reason
strings); they must not be "fixed" by weakening the assertions.
"""

from __future__ import annotations

import http.cookiejar
import json
import pathlib
import queue
import time
from types import SimpleNamespace

import pytest

from icloudpd_supervisor.config import Config
from icloudpd_supervisor.cookies import (
    MFA_COOKIE_NAME,
    cookie_path,
    read_cookie_status,
    session_path,
)
from icloudpd_supervisor.runner import IcloudpdRunner, RunResult
from icloudpd_supervisor.scheduler import PERSONAL_LIBRARY, Supervisor
from icloudpd_supervisor.state import PersistedState, StatusFile, SupervisorState
from icloudpd_supervisor.telegram import Command
from icloudpd_supervisor.webui import WebUIState, WebUIStatus

APPLE_ID = "user@example.com"
BASE_TIME = 1_750_000_000.0  # 2025-06-15-ish; any stable epoch works

# Stable substrings of the supervisor's user-facing messages.
PROMPT_MSG = "needs a new two-factor code"
VERIFYING_MSG = "verifying with Apple"
SUCCESS_MSG = "Two-factor authentication successful"
REJECTED_MSG = "rejected the code"
TIMEOUT_MSG = "No two-factor code received in time"
BUDGET_MSG = "Authentication budget exhausted"
NO_CODE_MSG = "No two-factor code is being requested right now"
NO_PASSWORD_MSG = "No iCloud password is stored yet"


# --------------------------------------------------------------------------
# Fakes
# --------------------------------------------------------------------------


class FakeClock:
    def __init__(self, start: float = BASE_TIME) -> None:
        self.now = float(start)

    def time(self) -> float:
        return self.now

    def advance(self, seconds: float) -> float:
        self.now += seconds
        return self.now

    def set(self, value: float) -> None:
        self.now = float(value)


class FakeTelegram:
    def __init__(self) -> None:
        self.messages: list[tuple[str, bool]] = []  # (text, silent)

    def send(self, text: str, silent: bool = False) -> bool:
        self.messages.append((text, silent))
        return True

    def texts(self) -> list[str]:
        return [t for t, _ in self.messages]

    def count(self, needle: str) -> int:
        return sum(needle in t for t in self.texts())

    def index(self, needle: str) -> int:
        for i, t in enumerate(self.texts()):
            if needle in t:
                return i
        raise AssertionError(f"no message containing {needle!r} in {self.texts()!r}")


class FakeWebUI:
    """Stands in for WebUIBridge; state is set directly by the test."""

    def __init__(self) -> None:
        self._status = WebUIStatus(WebUIState.UNREACHABLE)
        self.submitted: list[str] = []
        self.submit_result = True
        self.status_calls = 0

    def set(self, state: WebUIState, error: str | None = None) -> None:
        self._status = WebUIStatus(state, error)

    def status(self) -> WebUIStatus:
        self.status_calls += 1
        return self._status

    def submit_code(self, code: str) -> bool:
        self.submitted.append(code)
        if self.submit_result:
            # Mirror icloudpd's StatusExchange.set_payload(): accepting a
            # code clears the previous error.
            self._status = WebUIStatus(self._status.state, None)
        return self.submit_result

    def cancel(self) -> None:  # pragma: no cover - never exercised
        pass


class FakeRunner:
    """Stands in for IcloudpdRunner: canned results, no subprocess."""

    def __init__(self, libraries: list[str] | None = None) -> None:
        self.libraries = list(libraries or [])
        self.results: list[RunResult] = []
        self.run_hook = None  # callable(args, tick) -> RunResult | None
        self.run_calls: list[list[str]] = []
        self.list_libraries_calls = 0

    def sync_args(self, library: str | None) -> list[str]:
        args = ["fake-icloudpd", "--sync"]
        if library:
            args += ["--library", library]
        return args

    def auth_only_args(self) -> list[str]:
        return ["fake-icloudpd", "--auth-only"]

    def list_libraries_args(self) -> list[str]:
        return ["fake-icloudpd", "--list-libraries"]

    parse_library_names = staticmethod(IcloudpdRunner.parse_library_names)

    def run(
        self, args, tick=None, timeout=None, tail_lines=40, collect_output=False
    ) -> RunResult:
        self.run_calls.append(list(args))
        if "--list-libraries" in args:
            self.list_libraries_calls += 1
            return RunResult(
                exit_code=0, duration=0.1, output_lines=list(self.libraries)
            )
        if self.run_hook is not None:
            result = self.run_hook(args, tick)
            if result is not None:
                return result
        if self.results:
            return self.results.pop(0)
        return RunResult(exit_code=0, duration=0.1)


class AutoStopQueue:
    """Command queue whose get() reports empty immediately and stops the
    supervisor after a fixed number of main-loop iterations."""

    def __init__(self, iterations: int) -> None:
        self.remaining = iterations
        self.sup: Supervisor | None = None

    def get(self, timeout=None):
        self.remaining -= 1
        if self.remaining <= 0 and self.sup is not None:
            self.sup.stop()
        raise queue.Empty

    def get_nowait(self):
        raise queue.Empty


# --------------------------------------------------------------------------
# Helpers / fixtures
# --------------------------------------------------------------------------


@pytest.fixture
def clock(monkeypatch) -> FakeClock:
    c = FakeClock()
    monkeypatch.setattr(time, "time", c.time)
    return c


def write_mfa_cookie(config_dir, expires_at: float) -> pathlib.Path:
    """Write a real LWP cookiejar the way pyicloud_ipd does."""
    path = cookie_path(str(config_dir), APPLE_ID)
    jar = http.cookiejar.LWPCookieJar(str(path))
    jar.set_cookie(
        http.cookiejar.Cookie(
            version=0,
            name=MFA_COOKIE_NAME,
            value="token",
            port=None,
            port_specified=False,
            domain=".icloud.com",
            domain_specified=True,
            domain_initial_dot=True,
            path="/",
            path_specified=True,
            secure=True,
            expires=int(expires_at),
            discard=False,
            comment=None,
            comment_url=None,
            rest={},
        )
    )
    jar.save(ignore_discard=True, ignore_expires=True)
    return pathlib.Path(path)


def make_env(
    tmp_path,
    *,
    libraries=("personal",),
    shared_available=None,
    max_auth_per_day=3,
    mfa_timeout=1800,
    keyring=True,
    commands=None,
) -> SimpleNamespace:
    config_dir = tmp_path / "config"
    config_dir.mkdir(parents=True, exist_ok=True)
    if keyring:
        keyring_dir = config_dir / "python_keyring"
        keyring_dir.mkdir(exist_ok=True)
        (keyring_dir / "keyring_pass.cfg").write_text("[icloudpd]\nuser = secret\n")
    cfg = Config(
        apple_id=APPLE_ID,
        config_dir=str(config_dir),
        download_path=str(tmp_path / "icloud"),
        libraries=list(libraries),
        max_auth_per_day=max_auth_per_day,
        mfa_timeout=mfa_timeout,
        status_file=str(tmp_path / "run" / "status.json"),
        state_file=str(config_dir / "supervisor_state.json"),
    )
    telegram = FakeTelegram()
    webui = FakeWebUI()
    runner = FakeRunner(libraries=shared_available)
    if commands is None:
        commands = queue.Queue()
    sup = Supervisor(cfg, telegram, commands, runner=runner, webui=webui)
    return SimpleNamespace(
        sup=sup,
        cfg=cfg,
        telegram=telegram,
        webui=webui,
        runner=runner,
        commands=commands,
        config_dir=config_dir,
    )


# --------------------------------------------------------------------------
# 1. MFA round-trip via _tick_during_run
# --------------------------------------------------------------------------


class TestMfaRoundTrip:
    def test_need_mfa_prompts_exactly_once(self, tmp_path, clock):
        env = make_env(tmp_path)
        env.webui.set(WebUIState.NEED_MFA)

        assert env.sup._tick_during_run() is True
        assert env.sup.state is SupervisorState.WAITING_FOR_MFA
        clock.advance(3)
        assert env.sup._tick_during_run() is True
        clock.advance(3)
        assert env.sup._tick_during_run() is True

        assert env.telegram.count(PROMPT_MSG) == 1
        # The prompt must be a loud (non-silent) notification.
        prompt_idx = env.telegram.index(PROMPT_MSG)
        assert env.telegram.messages[prompt_idx][1] is False
        # Prompt mentions the timeout in minutes.
        assert "30" in env.telegram.texts()[prompt_idx]

    def test_webui_poll_throttled_to_two_seconds(self, tmp_path, clock):
        env = make_env(tmp_path)
        env.webui.set(WebUIState.NEED_MFA)

        env.sup._tick_during_run()
        assert env.webui.status_calls == 1
        clock.advance(1)
        env.sup._tick_during_run()  # < 2s since last poll: skipped
        assert env.webui.status_calls == 1
        clock.advance(1.5)
        env.sup._tick_during_run()
        assert env.webui.status_calls == 2

    def test_code_command_mid_run_submits_code(self, tmp_path, clock):
        env = make_env(tmp_path)
        env.webui.set(WebUIState.NEED_MFA)
        env.sup._tick_during_run()  # prompt

        env.commands.put(Command("code", "123456"))
        clock.advance(1)  # poll throttled: code must still be handled
        assert env.sup._tick_during_run() is True

        assert env.webui.submitted == ["123456"]
        idx = env.telegram.index(VERIFYING_MSG)
        assert env.telegram.messages[idx][1] is True  # silent ack

    def test_code_without_active_prompt_is_buffered(self, tmp_path, clock):
        # The user may see Apple's push before our 2s-throttled poll notices
        # NEED_MFA; an early code is buffered and submitted once the prompt
        # appears instead of being refused.
        env = make_env(tmp_path)
        env.webui.set(WebUIState.IDLE)
        env.commands.put(Command("code", "123456"))

        assert env.sup._tick_during_run() is True
        assert env.webui.submitted == []
        assert env.sup._pending_code == "123456"
        assert env.telegram.count("I'll use this one") == 1

        # Prompt appears on a later tick: the buffered code is submitted.
        env.webui.set(WebUIState.NEED_MFA)
        clock.advance(3)
        assert env.sup._tick_during_run() is True
        assert env.webui.submitted == ["123456"]
        assert env.sup._pending_code is None

    def test_idle_after_submit_notifies_success(self, tmp_path, clock):
        env = make_env(tmp_path)
        env.webui.set(WebUIState.NEED_MFA)
        env.sup._tick_during_run()  # prompt
        env.commands.put(Command("code", "123456"))
        clock.advance(3)
        env.sup._tick_during_run()  # submit

        env.webui.set(WebUIState.IDLE)
        clock.advance(3)
        assert env.sup._tick_during_run() is True

        assert env.telegram.count(SUCCESS_MSG) == 1
        assert env.sup.state is SupervisorState.SYNCING
        # Flow is reset: staying IDLE must not repeat the notification.
        clock.advance(3)
        env.sup._tick_during_run()
        assert env.telegram.count(SUCCESS_MSG) == 1

    def test_undeliverable_code_notifies_and_is_not_treated_as_submitted(
        self, tmp_path, clock
    ):
        env = make_env(tmp_path)
        env.webui.set(WebUIState.NEED_MFA)
        env.sup._tick_during_run()  # prompt
        env.webui.submit_result = False
        env.commands.put(Command("code", "123456"))
        clock.advance(3)
        assert env.sup._tick_during_run() is True

        assert env.webui.submitted == ["123456"]
        assert env.telegram.count("Could not deliver the code") == 1
        # Nothing was submitted, so a later IDLE poll must not claim success.
        env.webui.set(WebUIState.IDLE)
        clock.advance(3)
        env.sup._tick_during_run()
        assert env.telegram.count(SUCCESS_MSG) == 0

    def test_rejected_code_notifies_and_rewaits(self, tmp_path, clock):
        env = make_env(tmp_path)
        env.webui.set(WebUIState.NEED_MFA)
        env.sup._tick_during_run()  # prompt
        env.commands.put(Command("code", "111111"))
        clock.advance(3)
        env.sup._tick_during_run()  # submit

        # Apple rejects: icloudpd goes back to NEED_MFA with an error text.
        env.webui.set(WebUIState.NEED_MFA, error="Incorrect verification code")
        clock.advance(3)
        assert env.sup._tick_during_run() is True

        assert env.telegram.count(REJECTED_MSG) == 1
        rejected = env.telegram.texts()[env.telegram.index(REJECTED_MSG)]
        assert "Incorrect verification code" in rejected
        # Still exactly one prompt: we re-wait, not re-prompt.
        assert env.telegram.count(PROMPT_MSG) == 1

        # A fresh code can be submitted for the same prompt.
        env.commands.put(Command("code", "222222"))
        clock.advance(3)
        assert env.sup._tick_during_run() is True
        assert env.webui.submitted == ["111111", "222222"]

    def test_mfa_deadline_exceeded_aborts_run(self, tmp_path, clock):
        env = make_env(tmp_path, mfa_timeout=600)
        env.webui.set(WebUIState.NEED_MFA)
        assert env.sup._tick_during_run() is True  # prompt, deadline = now+600

        clock.advance(601)
        assert env.sup._tick_during_run() is False
        assert env.telegram.count(TIMEOUT_MSG) == 1

    def test_need_password_aborts_run(self, tmp_path, clock):
        env = make_env(tmp_path)
        env.webui.set(WebUIState.NEED_PASSWORD)
        assert env.sup._tick_during_run() is False
        assert env.telegram.count("asking for your password") == 1

    def test_status_and_help_handled_mid_run_sync_deferred(self, tmp_path, clock):
        env = make_env(tmp_path)
        env.webui.set(WebUIState.IDLE)
        env.commands.put(Command("status"))
        env.commands.put(Command("help"))
        env.commands.put(Command("sync"))  # not started mid-run, but acknowledged

        assert env.sup._tick_during_run() is True
        assert env.telegram.count("State:") == 1
        assert env.telegram.count("Commands:") == 1
        # 'sync' mid-run is not silently swallowed: the user gets feedback.
        assert env.telegram.count("already in progress") == 1
        assert len(env.telegram.messages) == 3
        assert env.runner.run_calls == []

    def test_full_mfa_roundtrip_via_run_sync_cycle(self, tmp_path, clock):
        env = make_env(tmp_path)

        def hook(args, tick):
            env.webui.set(WebUIState.NEED_MFA)
            clock.advance(3)
            assert tick() is True
            assert env.sup.state is SupervisorState.WAITING_FOR_MFA
            env.commands.put(Command("code", "123456"))
            clock.advance(3)
            assert tick() is True
            assert env.webui.submitted == ["123456"]
            env.webui.set(WebUIState.IDLE)
            clock.advance(3)
            assert tick() is True
            return RunResult(
                exit_code=0,
                duration=9.0,
                performed_password_auth=True,
                downloaded=4,
            )

        env.runner.run_hook = hook
        env.sup.run_sync_cycle()

        tel = env.telegram
        assert tel.count(PROMPT_MSG) == 1
        assert tel.count(SUCCESS_MSG) == 1
        assert tel.count("Downloaded 4 new item(s)") == 1
        assert (
            tel.index(PROMPT_MSG)
            < tel.index(VERIFYING_MSG)
            < tel.index(SUCCESS_MSG)
            < tel.index("Downloaded 4 new item(s)")
        )
        assert env.sup.state is SupervisorState.IDLE
        assert env.sup.persisted.last_sync_ok is True
        # The password sign-in was counted and persisted.
        assert env.sup.persisted.auth_attempts_last_day() == 1
        assert PersistedState.load(env.cfg.state_file).auth_attempts_last_day() == 1

    def test_checking_window_does_not_fake_success_and_relays_rejection(
        self, tmp_path, clock
    ):
        env = make_env(tmp_path)
        env.webui.set(WebUIState.NEED_MFA)
        env.sup._tick_during_run()  # prompt
        env.commands.put(Command("code", "111111"))
        clock.advance(3)
        env.sup._tick_during_run()  # submit

        # icloudpd picked the code up and is checking it with Apple: /status
        # now renders status.html, which the (fixed) bridge reports as
        # CHECKING — the supervisor must keep waiting, not declare success.
        env.webui.set(WebUIState.CHECKING)
        clock.advance(3)
        env.sup._tick_during_run()

        # Apple rejects the code.
        env.webui.set(WebUIState.NEED_MFA, error="Incorrect verification code")
        clock.advance(3)
        env.sup._tick_during_run()

        assert env.telegram.count(SUCCESS_MSG) == 0
        assert env.telegram.count(REJECTED_MSG) == 1

    def test_mfa_timeout_sends_single_notification(self, tmp_path, clock):
        env = make_env(tmp_path, mfa_timeout=600)

        def hook(args, tick):
            env.webui.set(WebUIState.NEED_MFA)
            clock.advance(3)
            assert tick() is True
            clock.advance(601)
            assert tick() is False
            # Real runner terminates the process on tick() False.
            return RunResult(
                exit_code=-15, duration=1.0, tail=["Terminated by supervisor"]
            )

        env.runner.run_hook = hook
        env.sup.run_sync_cycle()

        assert env.telegram.count(TIMEOUT_MSG) == 1
        assert env.telegram.count("failed (exit") == 0


# --------------------------------------------------------------------------
# 2. Auth budget
# --------------------------------------------------------------------------


class TestAuthBudget:
    def test_auth_attempts_prune_across_24h_window(self, clock):
        t0 = clock.now
        st = PersistedState()
        st.record_auth_attempt()  # t0
        clock.advance(2 * 3600)
        st.record_auth_attempt()  # t0 + 2h
        clock.advance(2 * 3600)
        st.record_auth_attempt()  # t0 + 4h
        assert st.auth_attempts_last_day() == 3

        clock.set(t0 + 86400 + 1)
        assert st.auth_attempts_last_day() == 2
        clock.set(t0 + 2 * 3600 + 86400 + 1)
        assert st.auth_attempts_last_day() == 1
        clock.set(t0 + 4 * 3600 + 86400 + 1)
        assert st.auth_attempts_last_day() == 0
        # Aged-out budget can be spent again.
        st.record_auth_attempt()
        assert st.auth_attempts_last_day() == 1

    @pytest.mark.parametrize("cookie", ["missing", "expired"])
    def test_sync_skipped_when_budget_exhausted_and_cookie_invalid(
        self, tmp_path, clock, cookie
    ):
        env = make_env(tmp_path, max_auth_per_day=2)
        env.sup.persisted.auth_attempts = [clock.now - 100, clock.now - 50]
        if cookie == "expired":
            write_mfa_cookie(env.config_dir, clock.now - 5)

        env.sup.run_sync_cycle(manual=False)
        assert env.runner.run_calls == []
        assert env.sup.state is SupervisorState.AUTH_RATE_LIMITED
        # Scheduled (non-manual) skips are silent.
        assert env.telegram.count(BUDGET_MSG) == 0

        env.sup.run_sync_cycle(manual=True)
        assert env.runner.run_calls == []
        assert env.telegram.count(BUDGET_MSG) == 1

    def test_sync_proceeds_when_budget_exhausted_but_cookie_valid(
        self, tmp_path, clock
    ):
        env = make_env(tmp_path, max_auth_per_day=1)
        env.sup.persisted.auth_attempts = [clock.now - 10]
        write_mfa_cookie(env.config_dir, clock.now + 30 * 86400)
        env.runner.results = [RunResult(exit_code=0, duration=1.0, downloaded=2)]

        env.sup.run_sync_cycle()

        assert len(env.runner.run_calls) == 1
        assert env.runner.run_calls[0][-2:] == ["--library", PERSONAL_LIBRARY]
        assert env.telegram.count("Downloaded 2 new item(s)") == 1
        assert env.sup.state is SupervisorState.IDLE
        assert env.sup.persisted.last_sync_ok is True
        assert env.sup.next_sync_time == clock.now + env.cfg.download_interval

    def test_sync_proceeds_when_budget_available_and_cookie_invalid(
        self, tmp_path, clock
    ):
        env = make_env(tmp_path, max_auth_per_day=3)
        env.sup.persisted.auth_attempts = [clock.now - 10]  # 1 of 3 used
        env.sup.run_sync_cycle()
        assert len(env.runner.run_calls) == 1
        assert env.sup.state is SupervisorState.IDLE

    def test_password_auth_recorded_and_persisted(self, tmp_path, clock):
        env = make_env(tmp_path)
        env.runner.results = [
            RunResult(exit_code=0, duration=1.0, performed_password_auth=True)
        ]
        env.sup.run_sync_cycle()
        assert env.sup.persisted.auth_attempts_last_day() == 1
        assert PersistedState.load(env.cfg.state_file).auth_attempts == [clock.now]

    def test_sync_failure_notifies_with_tail_and_stops_cycle(self, tmp_path, clock):
        env = make_env(tmp_path, libraries=["personal", "OtherLib"])
        env.runner.results = [
            RunResult(exit_code=1, duration=1.0, tail=["line1", "boom"])
        ]
        env.sup.run_sync_cycle()

        assert len(env.runner.run_calls) == 1  # second library never attempted
        idx = env.telegram.index("failed (exit 1)")
        text = env.telegram.texts()[idx]
        assert PERSONAL_LIBRARY in text and "boom" in text
        assert env.sup.persisted.last_sync_ok is False
        assert env.telegram.count("Downloaded") == 0
        assert env.sup.state is SupervisorState.IDLE


# --------------------------------------------------------------------------
# 3. run_reauth
# --------------------------------------------------------------------------


class TestReauth:
    def _seed_auth_files(self, env, clock) -> tuple[pathlib.Path, bytes, pathlib.Path, bytes]:
        cookie = write_mfa_cookie(env.config_dir, clock.now + 5 * 86400)
        cookie_bytes = cookie.read_bytes()
        session = session_path(str(env.config_dir), APPLE_ID)
        session.write_text('{"session_token": "abc"}')
        return cookie, cookie_bytes, session, session.read_bytes()

    def test_reauth_failure_restores_cookie_and_session(self, tmp_path, clock):
        env = make_env(tmp_path)
        cookie, cookie_bytes, session, session_bytes = self._seed_auth_files(env, clock)
        observed = {}

        def hook(args, tick):
            observed["cookie_deleted"] = not cookie.exists()
            observed["session_deleted"] = not session.exists()
            observed["cookie_backup"] = cookie.with_name(
                cookie.name + ".reauth-backup"
            ).exists()
            observed["session_backup"] = session.with_name(
                session.name + ".reauth-backup"
            ).exists()
            return RunResult(exit_code=1, duration=1.0, tail=["auth exploded"])

        env.runner.run_hook = hook
        env.sup.run_reauth()

        # Originals were deleted (to force a full sign-in) but backed up first.
        assert observed == {
            "cookie_deleted": True,
            "session_deleted": True,
            "cookie_backup": True,
            "session_backup": True,
        }
        assert "--auth-only" in env.runner.run_calls[0]
        # Failure: originals restored byte-for-byte, backups cleaned up.
        assert cookie.read_bytes() == cookie_bytes
        assert session.read_bytes() == session_bytes
        assert list(env.config_dir.glob("*.reauth-backup")) == []
        failed = env.telegram.texts()[env.telegram.index("Re-authentication failed")]
        assert "auth exploded" in failed
        assert env.telegram.count("previous cookies were restored") == 1
        assert env.sup.state is SupervisorState.IDLE

    def test_reauth_success_discards_backups(self, tmp_path, clock):
        env = make_env(tmp_path)
        cookie, _, _session, _ = self._seed_auth_files(env, clock)

        def hook(args, tick):
            # icloudpd writes a fresh trust cookie on success.
            write_mfa_cookie(env.config_dir, clock.now + 90 * 86400 + 60)
            return RunResult(
                exit_code=0, duration=1.0, performed_password_auth=True
            )

        env.runner.run_hook = hook
        env.sup.run_reauth()

        assert list(env.config_dir.glob("*.reauth-backup")) == []
        done = env.telegram.texts()[env.telegram.index("Re-authentication complete")]
        assert "90 days" in done
        status = read_cookie_status(str(env.config_dir), APPLE_ID)
        assert status.days_remaining == 90
        # The password sign-in was charged to the budget.
        assert env.sup.persisted.auth_attempts_last_day() == 1
        assert env.sup.state is SupervisorState.IDLE

    def test_reauth_refused_when_budget_exhausted(self, tmp_path, clock):
        env = make_env(tmp_path, max_auth_per_day=1)
        env.sup.persisted.auth_attempts = [clock.now - 60]
        cookie, cookie_bytes, session, session_bytes = self._seed_auth_files(env, clock)

        env.sup.run_reauth()

        assert env.runner.run_calls == []
        assert env.telegram.count(BUDGET_MSG) == 1
        # Cookies were never touched.
        assert cookie.read_bytes() == cookie_bytes
        assert session.read_bytes() == session_bytes
        assert list(env.config_dir.glob("*.reauth-backup")) == []


# --------------------------------------------------------------------------
# 4. _resolve_libraries
# --------------------------------------------------------------------------


class TestResolveLibraries:
    def test_personal_maps_to_primarysync_without_lookup(self, tmp_path, clock):
        env = make_env(tmp_path, libraries=["personal"])
        assert env.sup._resolve_libraries() == [PERSONAL_LIBRARY]
        assert env.runner.list_libraries_calls == 0

    def test_shared_resolves_all_sharedsync_libraries(self, tmp_path, clock):
        env = make_env(
            tmp_path,
            libraries=["shared"],
            shared_available=[
                "PrimarySync",
                "SharedSync-ABC-123",
                "SharedSync-DEF-456",
            ],
        )
        assert env.sup._resolve_libraries() == [
            "SharedSync-ABC-123",
            "SharedSync-DEF-456",
        ]
        assert env.runner.list_libraries_calls == 1

    def test_explicit_names_pass_through_case_insensitive_aliases_dedup(
        self, tmp_path, clock
    ):
        env = make_env(
            tmp_path,
            libraries=["Personal", "SHARED", "CustomLib", "PrimarySync", "CustomLib"],
            shared_available=["PrimarySync", "SharedSync-1111"],
        )
        assert env.sup._resolve_libraries() == [
            PERSONAL_LIBRARY,
            "SharedSync-1111",
            "CustomLib",
        ]

    def test_resolution_cached_after_success(self, tmp_path, clock):
        env = make_env(
            tmp_path,
            libraries=["shared"],
            shared_available=["SharedSync-1111"],
        )
        first = env.sup._resolve_libraries()
        second = env.sup._resolve_libraries()
        assert first == second == ["SharedSync-1111"]
        assert env.runner.list_libraries_calls == 1

    def test_no_shared_found_notifies_and_retries_next_time(self, tmp_path, clock):
        env = make_env(tmp_path, libraries=["shared"], shared_available=["PrimarySync"])
        assert env.sup._resolve_libraries() == []
        assert env.telegram.count("No shared library found") == 1
        # An empty resolution is not cached: the lookup is retried.
        env.sup._resolve_libraries()
        assert env.runner.list_libraries_calls == 2

    def test_sync_cycle_with_unresolvable_libraries_fails_cleanly(
        self, tmp_path, clock
    ):
        env = make_env(tmp_path, libraries=["shared"], shared_available=[])
        env.sup.run_sync_cycle()
        # The library lookup itself runs through run() (bridged); what must
        # NOT happen is any actual sync run.
        assert [c for c in env.runner.run_calls if "--sync" in c] == []
        assert env.telegram.count("Could not resolve any photo library") == 1
        assert env.sup.persisted.last_sync_ok is False
        assert env.sup.state is SupervisorState.IDLE
        assert env.sup.next_sync_time == clock.now + env.cfg.download_interval


# --------------------------------------------------------------------------
# 5. StatusFile + PersistedState
# --------------------------------------------------------------------------


class TestStatusFile:
    def test_write_produces_json_and_leaves_no_tmp(self, tmp_path, clock):
        path = tmp_path / "run" / "status.json"
        sf = StatusFile(str(path))
        sf.write(SupervisorState.IDLE, next_sync_time=123.0)

        data = json.loads(path.read_text())
        assert data["state"] == "idle"
        assert data["updated_at"] == clock.now
        assert data["next_sync_time"] == 123.0
        assert not path.with_suffix(".tmp").exists()

    def test_failed_write_preserves_previous_content(self, tmp_path, monkeypatch):
        path = tmp_path / "status.json"
        sf = StatusFile(str(path))
        sf.write(SupervisorState.IDLE, marker=1)
        before = path.read_text()

        def boom(self, *args, **kwargs):
            raise OSError("disk full")

        monkeypatch.setattr(pathlib.Path, "write_text", boom)
        sf.write(SupervisorState.SYNCING, marker=2)  # must not raise

        assert path.read_text() == before  # target never truncated in place

    def test_supervisor_write_status_reports_all_fields(self, tmp_path, clock):
        env = make_env(tmp_path)
        env.sup.persisted.auth_attempts = [clock.now - 100]
        env.sup.persisted.last_sync_time = clock.now - 500
        env.sup.persisted.last_sync_ok = True
        write_mfa_cookie(env.config_dir, clock.now + 10 * 86400 + 30)

        env.sup._write_status()

        data = json.loads(pathlib.Path(env.cfg.status_file).read_text())
        assert data["state"] == "starting"
        assert data["updated_at"] == clock.now
        assert data["last_sync_time"] == clock.now - 500
        assert data["last_sync_ok"] is True
        assert data["cookie_days_remaining"] == 10
        assert data["next_sync_time"] == env.sup.next_sync_time
        assert data["auth_attempts_last_day"] == 1


class TestPersistedState:
    def test_save_load_roundtrip(self, tmp_path, clock):
        path = tmp_path / "state.json"
        st = PersistedState(
            auth_attempts=[clock.now - 10.0, clock.now - 5.0],
            last_sync_time=clock.now - 100.0,
            last_sync_ok=False,
            last_expiry_warning=clock.now - 1000.0,
        )
        st.save(str(path))
        assert not path.with_suffix(".tmp").exists()
        assert PersistedState.load(str(path)) == st

    def test_load_missing_file_returns_default(self, tmp_path):
        assert PersistedState.load(str(tmp_path / "missing.json")) == PersistedState()

    @pytest.mark.parametrize(
        "content",
        ["", "{not json", '{"auth_attempts": ["abc"]}'],
        ids=["empty", "truncated", "non-numeric-attempts"],
    )
    def test_load_corrupt_file_returns_default(self, tmp_path, content):
        path = tmp_path / "state.json"
        path.write_text(content)
        assert PersistedState.load(str(path)) == PersistedState()

    @pytest.mark.parametrize("content", ["null", "[1, 2, 3]"])
    def test_load_non_dict_json_returns_default(self, tmp_path, content):
        path = tmp_path / "state.json"
        path.write_text(content)
        assert PersistedState.load(str(path)) == PersistedState()

    def test_save_to_unwritable_path_does_not_raise(self, tmp_path):
        PersistedState().save(str(tmp_path / "no_such_dir" / "state.json"))


# --------------------------------------------------------------------------
# run_forever regression: keyring-missing notification flood
# --------------------------------------------------------------------------


def test_run_forever_without_keyring_does_not_flood_telegram(tmp_path, clock):
    commands = AutoStopQueue(iterations=4)
    env = make_env(tmp_path, keyring=False, commands=commands)
    commands.sup = env.sup

    env.sup.run_forever()

    assert env.sup.state is SupervisorState.PASSWORD_NEEDED
    assert env.telegram.count(NO_PASSWORD_MSG) <= 1
