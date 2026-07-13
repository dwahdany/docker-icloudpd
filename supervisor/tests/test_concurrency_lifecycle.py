"""Concurrency & lifecycle tests for the supervisor / runner / telegram trio.

Hermetic: fake icloudpd executables are tiny python scripts under tmp_path;
the webui and Telegram are in-process fakes; no network I/O, no real
icloudpd, no Apple.

Tests marked ``xfail`` document real implementation bugs (see the reason
strings); they must not be "fixed" by weakening the assertions.
"""

from __future__ import annotations

import os
import queue
import signal
import sys
import textwrap
import threading
import time
from types import SimpleNamespace

import pytest

from icloudpd_supervisor.config import Config
from icloudpd_supervisor.runner import IcloudpdRunner, RunResult
from icloudpd_supervisor.scheduler import Supervisor
from icloudpd_supervisor.telegram import Command, TelegramListener
from icloudpd_supervisor.webui import WebUIState, WebUIStatus

APPLE_ID = "user@example.com"


# --------------------------------------------------------------------------
# Fakes / helpers
# --------------------------------------------------------------------------


class FakeTelegram:
    def __init__(self) -> None:
        self.messages: list[tuple[str, bool]] = []

    def send(self, text: str, silent: bool = False) -> bool:
        self.messages.append((text, silent))
        return True

    def texts(self) -> list[str]:
        return [t for t, _ in self.messages]

    def count(self, needle: str) -> int:
        return sum(needle in t for t in self.texts())


class FakeWebUI:
    def __init__(self) -> None:
        self._status = WebUIStatus(WebUIState.UNREACHABLE)
        self.submitted: list[str] = []

    def set(self, state: WebUIState, error: str | None = None) -> None:
        self._status = WebUIStatus(state, error)

    def status(self) -> WebUIStatus:
        return self._status

    def submit_code(self, code: str) -> bool:
        self.submitted.append(code)
        return True

    def cancel(self) -> None:  # pragma: no cover
        pass


def make_fake_icloudpd(tmp_path, body: str, name: str = "fake-icloudpd") -> str:
    script = tmp_path / name
    script.write_text(f"#!{sys.executable}\n" + textwrap.dedent(body))
    script.chmod(0o755)
    return str(script)


def make_config(tmp_path, icloudpd_bin: str = "/nonexistent/icloudpd", **overrides) -> Config:
    config_dir = tmp_path / "config"
    config_dir.mkdir(parents=True, exist_ok=True)
    keyring_dir = config_dir / "python_keyring"
    keyring_dir.mkdir(exist_ok=True)
    (keyring_dir / "keyring_pass.cfg").write_text("[icloudpd]\nuser = secret\n")
    (tmp_path / "icloud").mkdir(exist_ok=True)
    return Config(
        apple_id=APPLE_ID,
        config_dir=str(config_dir),
        download_path=str(tmp_path / "icloud"),
        icloudpd_bin=icloudpd_bin,
        status_file=str(tmp_path / "run" / "status.json"),
        state_file=str(config_dir / "supervisor_state.json"),
        **overrides,
    )


def make_supervisor(tmp_path, *, runner=None, icloudpd_bin: str = "/nonexistent/icloudpd"):
    cfg = make_config(tmp_path, icloudpd_bin=icloudpd_bin)
    telegram = FakeTelegram()
    webui = FakeWebUI()
    commands: "queue.Queue[Command]" = queue.Queue()
    runner = runner or IcloudpdRunner(cfg)
    sup = Supervisor(cfg, telegram, commands, runner=runner, webui=webui)
    return SimpleNamespace(
        sup=sup, cfg=cfg, telegram=telegram, webui=webui, commands=commands, runner=runner
    )


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


# --------------------------------------------------------------------------
# 1. stop()/SIGTERM during a run does not abort the run
# --------------------------------------------------------------------------


def test_stop_during_run_aborts_promptly(tmp_path):
    # icloudpd stand-in that runs for 8 seconds unless terminated.
    script = make_fake_icloudpd(
        tmp_path,
        """
        import time
        print("session token is valid", flush=True)
        time.sleep(8)
        """,
    )
    env = make_supervisor(tmp_path, icloudpd_bin=script)

    # Simulate SIGTERM arriving 0.5s into the run (main.handle_term calls stop()).
    threading.Timer(0.5, env.sup.stop).start()

    start = time.monotonic()
    env.sup.run_sync_cycle()
    elapsed = time.monotonic() - start

    # A graceful shutdown should abort the in-flight run within a few
    # seconds of stop(); today the run continues for its full duration.
    assert elapsed < 4.0, f"run continued {elapsed:.1f}s after stop()"


# --------------------------------------------------------------------------
# 2. sync/reauth commands received during a run are swallowed silently
# --------------------------------------------------------------------------


class TickingRunner:
    """Runner stand-in that invokes tick a few times, like a live run."""

    def __init__(self, cfg, ticks: int = 3) -> None:
        self._real = IcloudpdRunner(cfg)
        self.ticks = ticks
        self.run_args: list[list[str]] = []

    def sync_args(self, library):
        return self._real.sync_args(library)

    def auth_only_args(self):
        return self._real.auth_only_args()

    def list_libraries_args(self):
        return self._real.list_libraries_args()

    parse_library_names = staticmethod(IcloudpdRunner.parse_library_names)

    def run(
        self, args, tick=None, timeout=None, tail_lines=40, collect_output=False
    ) -> RunResult:
        self.run_args.append(list(args))
        for _ in range(self.ticks):
            if tick is not None and tick() is False:
                break
        return RunResult(exit_code=0, duration=0.1)


def test_reauth_command_during_run_is_not_silently_dropped(tmp_path):
    cfg = make_config(tmp_path)
    runner = TickingRunner(cfg)
    telegram = FakeTelegram()
    webui = FakeWebUI()
    commands: "queue.Queue[Command]" = queue.Queue()
    sup = Supervisor(cfg, telegram, commands, runner=runner, webui=webui)

    # The user sends 'reauth' while the sync run is in flight.
    commands.put(Command("reauth"))
    sup.run_sync_cycle()

    auth_runs = [a for a in runner.run_args if "--auth-only" in a]
    still_queued = not commands.empty()
    user_was_told = any(
        "reauth" in t.lower() or "later" in t.lower() or "progress" in t.lower()
        for t in telegram.texts()
    )
    # The command must not simply evaporate: it should be deferred/requeued,
    # executed after the run, or at minimum acknowledged to the user.
    assert auth_runs or still_queued or user_was_told, (
        f"'reauth' was consumed mid-run with no effect and no user feedback; "
        f"telegram={telegram.texts()!r}"
    )


# --------------------------------------------------------------------------
# 3. a code arriving in the same tick as NEED_MFA detection is discarded
# --------------------------------------------------------------------------


def test_code_arriving_before_first_need_mfa_poll_is_submitted(tmp_path):
    env = make_supervisor(tmp_path)
    # icloudpd already entered NEED_MFA (push notification already sent to
    # the user's devices), but the supervisor has not polled the webui yet.
    env.webui.set(WebUIState.NEED_MFA)
    env.commands.put(Command("code", "123456"))

    assert env.sup._tick_during_run() is True

    # The webui is in NEED_MFA: the user's code should reach it.
    assert env.webui.submitted == ["123456"], (
        f"code was dropped; telegram={env.telegram.texts()!r}"
    )


# --------------------------------------------------------------------------
# 4. an exception from tick() leaks the running icloudpd process
# --------------------------------------------------------------------------


def test_tick_exception_terminates_subprocess(tmp_path):
    pidfile = tmp_path / "child.pid"
    script = make_fake_icloudpd(
        tmp_path,
        f"""
        import os, time
        open({str(pidfile)!r}, "w").write(str(os.getpid()))
        time.sleep(30)
        """,
    )
    cfg = make_config(tmp_path, icloudpd_bin=script)
    runner = IcloudpdRunner(cfg)

    def exploding_tick():
        raise RuntimeError("tick blew up (e.g. UnicodeDecodeError in cookie read)")

    with pytest.raises(RuntimeError):
        runner.run([script], tick=exploding_tick)

    deadline = time.monotonic() + 5
    while not pidfile.is_file() and time.monotonic() < deadline:
        time.sleep(0.05)
    pid = int(pidfile.read_text())

    time.sleep(0.5)  # give any cleanup a moment
    leaked = _alive(pid)
    if leaked:  # do not leave the 30s sleeper behind
        os.kill(pid, signal.SIGKILL)
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass
    assert not leaked, "icloudpd subprocess left running after tick() raised"


# --------------------------------------------------------------------------
# 5. RunResult is still mutated by the reader thread after run() returns
# --------------------------------------------------------------------------


# performed_password_auth is now computed synchronously from the session
# file after the reader join, so it is final when run() returns. (The
# leaked reader can still append to tail/output_lines late: cosmetic.)
def test_runresult_is_final_when_run_returns(tmp_path):
    # Parent exits immediately, but a grandchild inherits stdout and prints
    # the password-auth marker after run()'s 10s reader join has expired.
    script = make_fake_icloudpd(
        tmp_path,
        """
        import subprocess, sys
        subprocess.Popen(
            [sys.executable, "-c",
             "import time; time.sleep(11.5); print('Authenticating as user', flush=True)"],
        )
        """,
    )
    cfg = make_config(tmp_path, icloudpd_bin=script)
    runner = IcloudpdRunner(cfg)

    result = runner.run([script])
    auth_at_return = result.performed_password_auth

    # Wait for the grandchild's late output to land.
    time.sleep(3.5)

    assert result.performed_password_auth == auth_at_return, (
        "RunResult mutated after run() returned: performed_password_auth "
        f"changed {auth_at_return} -> {result.performed_password_auth}; "
        "_record_auth already made its budget decision on the stale value"
    )


# --------------------------------------------------------------------------
# 6. listener stop() cannot interrupt an in-flight long poll
# --------------------------------------------------------------------------


def test_listener_stop_does_not_interrupt_long_poll(tmp_path):
    """Documents (non-xfail: latent, daemon flag masks it) that
    TelegramListener.stop() is only observed between polls; a real
    poll_updates blocks up to ~65s. Nothing in main.py ever calls stop()."""

    release = threading.Event()

    class SlowClient:
        def poll_updates(self, timeout: int = 50) -> list[str]:
            release.wait(10)  # stands in for the 50s Telegram long poll
            return []

    commands: "queue.Queue[Command]" = queue.Queue()
    listener = TelegramListener(SlowClient(), commands)
    listener.start()
    time.sleep(0.2)
    listener.stop()
    listener.join(timeout=1.0)
    blocked = listener.is_alive()
    release.set()
    listener.join(timeout=2.0)
    assert blocked, "expected stop() to be unable to interrupt an in-flight poll"
    assert not listener.is_alive()
