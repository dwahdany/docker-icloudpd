"""Adversarial protocol-fidelity tests: supervisor assumptions vs the real
icloudpd 1.32.3 behaviour.

Hermetic: fake icloudpd executables (python scripts) reproduce icloudpd's
*exact* logging configuration (icloudpd/base.py create_logger) and
pyicloud_ipd's *exact* log calls (pyicloud_ipd/base.py authenticate), so no
network and no real icloudpd binary are involved.
"""

from __future__ import annotations

import sys
import textwrap

import pytest

from icloudpd_supervisor.config import Config
from icloudpd_supervisor.runner import IcloudpdRunner

USER = "user@example.com"


def make_fake_icloudpd(tmp_path, body: str) -> str:
    script = tmp_path / "fake-icloudpd"
    script.write_text(f"#!{sys.executable}\n" + textwrap.dedent(body))
    script.chmod(0o755)
    return str(script)


def make_runner(tmp_path, bin_path: str) -> IcloudpdRunner:
    config = Config(
        apple_id=USER,
        config_dir=str(tmp_path),
        download_path=str(tmp_path / "icloud"),
        icloudpd_bin=bin_path,
    )
    return IcloudpdRunner(config)


# Replicates icloudpd 1.32.3 logging byte-for-byte:
#  - icloudpd/base.py create_logger(): basicConfig(format=..., stream=stdout)
#    with NO level argument, then setLevel(DEBUG) on the "icloudpd" logger
#    only (this is what `--log-level debug` does).
#  - pyicloud_ipd/base.py:315 logs the password sign-in marker with
#    LOGGER.debug(f"Authenticating as {apple_id}") on the
#    "pyicloud_ipd.base" logger, whose effective level stays at the root
#    default (WARNING) because create_logger never touches it.
_REAL_ICLOUDPD_LOGGING = """
    import logging, sys
    logging.basicConfig(
        format="%(asctime)s %(levelname)-8s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stdout,
    )
    icloudpd_logger = logging.getLogger("icloudpd")
    icloudpd_logger.setLevel(logging.DEBUG)  # --log-level debug
    pyicloud_logger = logging.getLogger("pyicloud_ipd.base")

    # pyicloud_ipd/base.py authenticate(): full password sign-in path
    pyicloud_logger.debug("Authenticating as user@example.com")
    # icloudpd/authentication.py authenticator():
    icloudpd_logger.info("Two-factor authentication is required (2fa)")
    sys.exit(0)
"""


def test_real_icloudpd_logging_signin_detected_via_session_rotation(tmp_path):
    # icloudpd 1.32.3 never emits pyicloud's "Authenticating as" DEBUG line
    # (create_logger only raises the "icloudpd" logger; pyicloud_ipd stays at
    # the root WARNING). The runner therefore does not scan logs: it detects
    # a sign-in by the session-token rotation that pyicloud_ipd/session.py
    # persists on every idmsa response. The fake reproduces both: the real
    # logging config (marker suppressed) and the session-file write.
    session_file = tmp_path / "userexamplecom.session"
    session_file.write_text('{"session_token": "stale"}')
    body = _REAL_ICLOUDPD_LOGGING.replace(
        "sys.exit(0)",
        f'''
    import json
    with open({str(session_file)!r}, "w") as f:
        json.dump({{"session_token": "rotated-by-signin"}}, f)
    sys.exit(0)
''',
    )
    bin_path = make_fake_icloudpd(tmp_path, body)
    runner = make_runner(tmp_path, bin_path)
    result = runner.run([bin_path])
    assert result.exit_code == 0
    # A full password sign-in genuinely happened inside icloudpd; the
    # supervisor must count it against the daily auth budget.
    assert result.performed_password_auth is True


def test_log_lines_alone_do_not_count_as_password_auth(tmp_path):
    """Log output must not influence budget accounting.

    Even a line that looks exactly like pyicloud's sign-in marker (e.g. a
    filename echoed into the log) must not burn a budget entry: only the
    session-token rotation counts.
    """
    body = """
    import sys
    print("2026-07-13 00:00:00 DEBUG    Authenticating as user@example.com", flush=True)
    sys.exit(0)
    """
    bin_path = make_fake_icloudpd(tmp_path, body)
    runner = make_runner(tmp_path, bin_path)
    result = runner.run([bin_path])
    assert result.performed_password_auth is False


def test_list_libraries_reports_password_auth(tmp_path):
    # --list-libraries authenticates exactly like a sync; it now runs through
    # run() (the scheduler bridges its MFA and books its sign-in), so the
    # session rotation must surface on the RunResult.
    session_file = tmp_path / "userexamplecom.session"
    body = f'''
    import json, sys
    print("PrimarySync", flush=True)
    print("SharedSync-ABC-123", flush=True)
    with open({str(session_file)!r}, "w") as f:
        json.dump({{"session_token": "fresh"}}, f)
    sys.exit(0)
'''
    bin_path = make_fake_icloudpd(tmp_path, body)
    runner = make_runner(tmp_path, bin_path)
    result = runner.run(runner.list_libraries_args(), collect_output=True)
    assert "SharedSync-ABC-123" in runner.parse_library_names(result.output_lines)
    assert result.performed_password_auth is True
