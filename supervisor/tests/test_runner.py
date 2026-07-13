"""Tests for icloudpd_supervisor.runner.

Hermetic: a fake icloudpd executable -- a tiny Python script written into
tmp_path with a shebang pointing at the current interpreter -- stands in for
the real binary.  It prints controlled log lines (formats copied from
icloudpd 1.32.3 / pyicloud_ipd) and exits with a chosen code.  No network,
no real icloudpd.
"""

from __future__ import annotations

import json
import signal
import sys
import textwrap

from icloudpd_supervisor.config import Config
from icloudpd_supervisor.runner import IcloudpdRunner

USER = "user@example.com"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_fake_icloudpd(tmp_path, body: str) -> str:
    """Write an executable python script that plays the role of icloudpd."""
    script = tmp_path / "fake-icloudpd"
    script.write_text(f"#!{sys.executable}\n" + textwrap.dedent(body))
    script.chmod(0o755)
    return str(script)


def make_runner(tmp_path, bin_path: str = "/nonexistent/icloudpd", **overrides):
    config = Config(
        apple_id=USER,
        config_dir=str(tmp_path),
        download_path=str(tmp_path / "icloud"),
        icloudpd_bin=bin_path,
        **overrides,
    )
    return IcloudpdRunner(config)


def script_printing(lines: list[str], exit_code: int = 0) -> str:
    return (
        "import sys\n"
        f"for line in {lines!r}:\n"
        "    print(line, flush=True)\n"
        f"sys.exit({exit_code})\n"
    )


# ---------------------------------------------------------------------------
# run(): RunResult fields
# ---------------------------------------------------------------------------


def test_run_counts_downloads_and_tail(tmp_path):
    # Line shapes copied from icloudpd/base.py ("Downloading %s...",
    # "%s already exists", "Downloading %s %s %s to %s ...").
    lines = [
        "Downloading 42 original photos and videos to /icloud ...",  # summary: no path
        "2026-07-13 10:00:01 DEBUG    Downloading /icloud/2026/07/13/IMG_0001.HEIC...",
        "2026-07-13 10:00:02 DEBUG    /icloud/2026/07/13/IMG_0002.HEIC already exists",
        "2026-07-13 10:00:03 DEBUG    Downloading /icloud/2026/07/13/IMG_0003.HEIC...",
        "2026-07-13 10:00:04 DEBUG    Downloading /icloud/2026/07/IMG_0004.HEIC skipped: already exists",
        "2026-07-13 10:00:05 INFO     All photos have been downloaded",
        "",  # blank lines must be dropped from the tail
    ]
    script = make_fake_icloudpd(tmp_path, script_printing(lines, exit_code=3))
    result = make_runner(tmp_path, script).run([script])

    assert result.exit_code == 3
    assert result.downloaded == 2  # IMG_0001 + IMG_0003 only
    assert result.timed_out is False
    assert result.duration >= 0
    assert result.tail == [line for line in lines if line]


def test_run_detects_password_auth_via_session_token_rotation(tmp_path):
    # A full idmsa password sign-in mints a new X-Apple-Session-Token, which
    # pyicloud persists into <cookie>.session (pyicloud_ipd/session.py).
    # Log markers are unreliable (pyicloud's logger stays at root WARNING),
    # so the runner compares the token before/after the run.
    session_file = tmp_path / "userexamplecom.session"
    session_file.write_text(json.dumps({"session_token": "old-token"}))
    script = make_fake_icloudpd(
        tmp_path,
        f"""
        import json, sys
        with open({str(session_file)!r}, "w") as f:
            json.dump({{"session_token": "new-token"}}, f)
        sys.exit(0)
        """,
    )
    result = make_runner(tmp_path, script).run([script])
    assert result.performed_password_auth is True


def test_run_first_ever_signin_counts_as_password_auth(tmp_path):
    # No session file before the run; one appears with a token -> sign-in.
    session_file = tmp_path / "userexamplecom.session"
    script = make_fake_icloudpd(
        tmp_path,
        f"""
        import json, sys
        with open({str(session_file)!r}, "w") as f:
            json.dump({{"session_token": "fresh"}}, f)
        sys.exit(0)
        """,
    )
    result = make_runner(tmp_path, script).run([script])
    assert result.performed_password_auth is True


def test_run_unchanged_session_token_is_not_password_auth(tmp_path):
    session_file = tmp_path / "userexamplecom.session"
    session_file.write_text(json.dumps({"session_token": "stable"}))
    script = make_fake_icloudpd(tmp_path, script_printing(["ok"]))
    result = make_runner(tmp_path, script).run([script])
    assert result.performed_password_auth is False


def test_run_session_reuse_is_not_password_auth(tmp_path):
    # Session-token reuse logs "Checking session token validity" instead
    # (pyicloud_ipd/base.py authenticate()); must not count against budget.
    lines = [
        "2026-07-13 10:00:00 DEBUG    Checking session token validity",
        "2026-07-13 10:00:01 INFO     All photos have been downloaded",
    ]
    script = make_fake_icloudpd(tmp_path, script_printing(lines))
    result = make_runner(tmp_path, script).run([script])

    assert result.exit_code == 0
    assert result.performed_password_auth is False
    assert result.downloaded == 0


def test_run_tail_keeps_only_last_lines(tmp_path):
    lines = [f"line-{i:03d}" for i in range(25)]
    script = make_fake_icloudpd(tmp_path, script_printing(lines))
    result = make_runner(tmp_path, script).run([script], tail_lines=10)

    assert result.tail == lines[-10:]
    assert result.exit_code == 0


# ---------------------------------------------------------------------------
# run(): tick abort and timeout kill
# ---------------------------------------------------------------------------


def test_tick_false_terminates_process(tmp_path):
    script = make_fake_icloudpd(
        tmp_path,
        """
        import time
        print("started", flush=True)
        time.sleep(60)
        print("never printed", flush=True)
        """,
    )
    ticks = []

    def tick():
        ticks.append(1)
        return False

    result = make_runner(tmp_path, script).run([script], tick=tick)

    assert len(ticks) == 1
    assert result.exit_code == -signal.SIGTERM
    assert result.timed_out is False
    assert result.duration < 30  # nowhere near the child's 60s sleep
    assert "started" in result.tail
    assert "never printed" not in result.tail


def test_tick_true_lets_process_finish(tmp_path):
    script = make_fake_icloudpd(
        tmp_path,
        """
        import time
        print("working", flush=True)
        time.sleep(2.2)
        print("done", flush=True)
        """,
    )
    ticks = []

    def tick():
        ticks.append(1)
        return True

    result = make_runner(tmp_path, script).run([script], tick=tick)

    assert result.exit_code == 0
    assert result.timed_out is False
    assert len(ticks) >= 1  # called roughly once per second while running
    assert "done" in result.tail


def test_timeout_kills_process_and_sets_flag(tmp_path):
    script = make_fake_icloudpd(
        tmp_path,
        """
        import time
        print("hanging", flush=True)
        time.sleep(60)
        """,
    )
    result = make_runner(tmp_path, script).run([script], timeout=1.5)

    assert result.timed_out is True
    assert result.exit_code == -signal.SIGTERM
    assert result.duration < 20  # terminated shortly after the 1.5s budget
    assert "hanging" in result.tail


# ---------------------------------------------------------------------------
# list_libraries()
# ---------------------------------------------------------------------------


def test_list_libraries_keeps_bare_names_drops_log_lines(tmp_path, monkeypatch):
    argv_dump = tmp_path / "argv.json"
    monkeypatch.setenv("ARGV_DUMP", str(argv_dump))
    script = make_fake_icloudpd(
        tmp_path,
        """
        import json, os, sys
        with open(os.environ["ARGV_DUMP"], "w") as f:
            json.dump(sys.argv[1:], f)
        print("2026-07-13 10:00:00 DEBUG    Authenticating as user@example.com")
        print("2026-07-13 10:00:01 INFO     Libraries:")
        print("PrimarySync")
        print("  SharedSync-217B600A-4949-4C4C-8747-8471195641FA  ")
        print("")
        print("not a library name")
        sys.exit(0)
        """,
    )
    runner = make_runner(tmp_path, script)
    result = runner.run(runner.list_libraries_args(), collect_output=True)
    names = runner.parse_library_names(result.output_lines)

    assert names == [
        "PrimarySync",
        "SharedSync-217B600A-4949-4C4C-8747-8471195641FA",
    ]
    argv = json.loads(argv_dump.read_text())
    assert "--list-libraries" in argv
    assert argv[argv.index("--username") + 1] == USER


def test_list_libraries_failure_reports_exit_code(tmp_path):
    # The runner no longer swallows failures behind an empty list (the old
    # standalone list_libraries() could also raise TimeoutExpired and crash
    # the supervisor). It runs through run(), which never raises: partial
    # output stays available and the caller decides based on exit_code.
    script = make_fake_icloudpd(
        tmp_path,
        """
        import sys
        print("PrimarySync")
        print("boom: keyring has no password", file=sys.stderr)
        sys.exit(1)
        """,
    )
    runner = make_runner(tmp_path, script)
    result = runner.run(runner.list_libraries_args(), collect_output=True)
    assert result.exit_code == 1
    assert runner.parse_library_names(result.output_lines) == ["PrimarySync"]


# ---------------------------------------------------------------------------
# Command construction (Config built directly, no load_config)
# ---------------------------------------------------------------------------


def _flag_value(args: list[str], flag: str) -> str:
    return args[args.index(flag) + 1]


def test_sync_args_full(tmp_path):
    runner = make_runner(
        tmp_path,
        "/opt/icloudpd/bin/icloudpd",
        skip_videos=True,
        skip_live_photos=True,
        extra_args=["--until-found", "10"],
        auth_china=True,
    )
    args = runner.sync_args("SharedSync-ABC")

    assert args[0] == "/opt/icloudpd/bin/icloudpd"
    assert _flag_value(args, "--username") == USER
    assert _flag_value(args, "--cookie-directory") == str(tmp_path)
    assert _flag_value(args, "--directory") == str(tmp_path / "icloud")
    assert _flag_value(args, "--domain") == "cn"  # auth_china=True
    assert _flag_value(args, "--library") == "SharedSync-ABC"
    assert _flag_value(args, "--password-provider") == "keyring"
    assert _flag_value(args, "--mfa-provider") == "webui"
    assert _flag_value(args, "--log-level") == "debug"  # needed for auth marker
    assert "--skip-videos" in args
    assert "--skip-live-photos" in args
    assert args[-2:] == ["--until-found", "10"]  # extra args appended verbatim


def test_sync_args_defaults_omit_optional_flags(tmp_path):
    args = make_runner(tmp_path).sync_args(None)

    assert "--library" not in args
    assert "--skip-videos" not in args
    assert "--skip-live-photos" not in args
    assert _flag_value(args, "--domain") == "com"


def test_auth_only_args(tmp_path):
    args = make_runner(tmp_path).auth_only_args()

    assert "--auth-only" in args
    assert "--directory" not in args  # auth run must not download
    assert _flag_value(args, "--password-provider") == "keyring"
    assert _flag_value(args, "--mfa-provider") == "webui"
    assert _flag_value(args, "--log-level") == "debug"
