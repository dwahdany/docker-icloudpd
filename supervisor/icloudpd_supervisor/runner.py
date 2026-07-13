"""Run icloudpd as a subprocess and observe what it does.

The runner never restarts icloudpd on its own: retry policy belongs to the
scheduler, which enforces the daily authentication budget. (The old container
let Docker's restart policy drive retries, which hammered Apple's auth
endpoint until the account was locked.)
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
import threading
import time
from dataclasses import dataclass, field

from .config import Config
from .cookies import session_path

logger = logging.getLogger(__name__)

# Password sign-in detection: log markers are NOT reliable here — pyicloud's
# "Authenticating as" line is DEBUG on a logger that icloudpd never raises
# above the root WARNING level (icloudpd/base.py create_logger only adjusts
# the "icloudpd" named logger). Instead we watch the .session file: every
# response persists X-Apple-Session-Token into it (pyicloud_ipd/session.py),
# and only a fresh idmsa password sign-in mints a NEW token — plain session
# reuse keeps the existing one. A changed/newly-appeared token therefore
# means a password authentication happened and must count against the budget.
_DOWNLOAD_MARKER = re.compile(r"Downloading (?P<path>/\S.*)")
_ALREADY_DOWNLOADED = re.compile(r"already exists", re.IGNORECASE)


@dataclass
class RunResult:
    exit_code: int
    duration: float
    performed_password_auth: bool = False
    downloaded: int = 0
    timed_out: bool = False
    tail: list[str] = field(default_factory=list)  # last output lines, for error reports
    output_lines: list[str] = field(default_factory=list)  # full output when collected


class IcloudpdRunner:
    def __init__(self, config: Config) -> None:
        self._config = config

    # --- command construction -------------------------------------------

    def sync_args(self, library: str | None) -> list[str]:
        cfg = self._config
        args = [
            cfg.icloudpd_bin,
            "--username", cfg.apple_id,
            "--cookie-directory", cfg.config_dir,
            "--directory", cfg.download_path,
            "--domain", cfg.auth_domain,
            "--folder-structure", cfg.folder_structure,
            "--size", cfg.photo_size,
            "--no-progress-bar",
            "--log-level", "debug",
            "--password-provider", "keyring",
            "--mfa-provider", "webui",
        ]
        if library:
            args += ["--library", library]
        if cfg.skip_videos:
            args.append("--skip-videos")
        if cfg.skip_live_photos:
            args.append("--skip-live-photos")
        args += cfg.extra_args
        return args

    def auth_only_args(self) -> list[str]:
        cfg = self._config
        return [
            cfg.icloudpd_bin,
            "--username", cfg.apple_id,
            "--cookie-directory", cfg.config_dir,
            "--domain", cfg.auth_domain,
            "--auth-only",
            "--log-level", "debug",
            "--password-provider", "keyring",
            "--mfa-provider", "webui",
        ]

    def list_libraries_args(self) -> list[str]:
        cfg = self._config
        return [
            cfg.icloudpd_bin,
            "--username", cfg.apple_id,
            "--cookie-directory", cfg.config_dir,
            "--domain", cfg.auth_domain,
            "--list-libraries",
            "--password-provider", "keyring",
            "--mfa-provider", "webui",
        ]

    # --- execution -------------------------------------------------------

    def _session_token(self) -> str | None:
        try:
            data = json.loads(
                session_path(self._config.config_dir, self._config.apple_id).read_text()
            )
            return data.get("session_token")
        except (OSError, ValueError):
            return None

    def run(
        self,
        args: list[str],
        tick: "callable | None" = None,
        timeout: float | None = None,
        tail_lines: int = 40,
        collect_output: bool = False,
    ) -> RunResult:
        """Run icloudpd, streaming output to the log.

        `tick` is called roughly once per second while the process runs; the
        scheduler uses it to bridge the webui and Telegram. If `tick` returns
        False the process is terminated (used for MFA timeout aborts).
        """
        start = time.monotonic()
        logger.info("Running: %s", " ".join(args))
        result = RunResult(exit_code=-1, duration=0.0)
        tail: list[str] = []
        token_before = self._session_token()

        process = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            bufsize=1,
        )

        def consume() -> None:
            assert process.stdout is not None
            for line in process.stdout:
                line = line.rstrip("\n")
                if line:
                    logger.debug("[icloudpd] %s", line)
                    tail.append(line)
                    del tail[:-tail_lines]
                    if collect_output:
                        result.output_lines.append(line)
                    if _DOWNLOAD_MARKER.search(line) and not _ALREADY_DOWNLOADED.search(line):
                        result.downloaded += 1

        reader = threading.Thread(target=consume, name="icloudpd-output", daemon=True)
        reader.start()

        aborted = False
        try:
            while True:
                try:
                    process.wait(timeout=1)
                    break
                except subprocess.TimeoutExpired:
                    pass
                elapsed = time.monotonic() - start
                if timeout is not None and elapsed > timeout:
                    logger.error("icloudpd run exceeded %ss, terminating", timeout)
                    result.timed_out = True
                    aborted = True
                if tick is not None and tick() is False:
                    logger.warning("Run aborted by supervisor")
                    aborted = True
                if aborted:
                    process.terminate()
                    try:
                        process.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
                    break
        finally:
            # A tick() exception must not abandon a live icloudpd process.
            if process.poll() is None:
                process.kill()
                process.wait()

        reader.join(timeout=10)
        result.exit_code = process.returncode if process.returncode is not None else -1
        result.duration = time.monotonic() - start
        result.tail = tail
        token_after = self._session_token()
        result.performed_password_auth = (
            token_after is not None and token_after != token_before
        )
        return result

    @staticmethod
    def parse_library_names(lines: list[str]) -> list[str]:
        """Extract library names from --list-libraries output.

        The output mixes log lines (timestamped, contain spaces) with bare
        library names printed one per line; keep only plausible names.
        """
        names = []
        for line in lines:
            line = line.strip()
            if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", line):
                names.append(line)
        return names
