#!/usr/bin/env python3
"""Verify every assumption the supervisor makes about icloudpd internals.

The webui bridge, cookie handling and auth-budget accounting depend on
specific icloudpd implementation details. The hermetic test suite uses
COPIES of those markers, so it cannot detect upstream drift — this script
checks them against the real source of a given icloudpd version and must
pass before an automated version bump is released.

Usage: check_icloudpd_assumptions.py <version> [--source-dir DIR]
"""

from __future__ import annotations

import argparse
import io
import re
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

FAILED = []


def check(name: str, ok: bool, detail: str = "") -> None:
    marker = "ok " if ok else "FAIL"
    print(f"[{marker}] {name}" + (f" — {detail}" if detail and not ok else ""))
    if not ok:
        FAILED.append(name)


def fetch_source(version: str) -> Path:
    url = (
        "https://github.com/icloud-photos-downloader/icloud_photos_downloader"
        f"/archive/refs/tags/v{version}.tar.gz"
    )
    print(f"Fetching {url}")
    data = urllib.request.urlopen(url, timeout=60).read()
    target = Path(tempfile.mkdtemp(prefix="icloudpd-src-"))
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        tar.extractall(target, filter="data")
    (extracted,) = target.iterdir()
    return extracted


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("version")
    parser.add_argument("--source-dir", help="use a local source tree instead of downloading")
    args = parser.parse_args()

    root = Path(args.source_dir) if args.source_dir else fetch_source(args.version)
    src = root / "src"

    def read(rel: str) -> str:
        path = src / rel
        if not path.is_file():
            check(f"file exists: {rel}", False, f"missing: {path}")
            return ""
        return path.read_text(encoding="utf-8", errors="replace")

    # --- webui bridge markers (icloudpd_supervisor/webui.py) ---------------
    code_html = read("icloudpd/server/templates/code.html")
    check("code.html has name=\"code\" input (NEED_MFA marker)", 'name="code"' in code_html)

    password_html = read("icloudpd/server/templates/password.html")
    check(
        "password.html has name=\"password\" input (NEED_PASSWORD marker)",
        'name="password"' in password_html,
    )

    status_html = read("icloudpd/server/templates/status.html")
    check(
        "status.html renders 'Status: {{ status }}' (CHECKING marker)",
        re.search(r"Status:\s*{{\s*status\s*}}", status_html) is not None,
    )

    code_or_password_error = re.search(r'class="fw-bold">\s*{{\s*error\s*}}', code_html)
    check("code.html renders error in fw-bold div (rejection relay)", code_or_password_error is not None)

    status_py = read("icloudpd/status.py")
    for state in ("NEED_MFA", "SUPPLIED_MFA", "CHECKING_MFA", "NO_INPUT_NEEDED"):
        check(f"Status enum has {state}", state in status_py)
    check(
        "Status.__str__ returns the enum NAME (status.html marker casing)",
        re.search(r"def __str__.*\n\s+return self\.name", status_py) is not None,
    )
    check(
        "set_error returns state to NEED_MFA after failed check (retryable rejection)",
        re.search(r"def set_error[\s\S]{0,700}else Status\.NEED_MFA", status_py) is not None
        or re.search(r"def set_error[\s\S]{0,700}Status\.NEED_MFA", status_py) is not None,
    )

    server_py = read("icloudpd/server/__init__.py")
    check("server has POST /code route", '"/code"' in server_py)
    check("server has GET /status route", '"/status"' in server_py)
    check(
        "waitress.serve called without host/port overrides (default 0.0.0.0:8080)",
        re.search(r"waitress\.serve\(app\)", server_py) is not None,
    )

    # --- auth flow (scheduler MFA round-trip) -------------------------------
    auth_py = read("icloudpd/authentication.py")
    check("request_2fa_web exists (webui MFA flow)", "def request_2fa_web" in auth_py)
    check(
        "webui flow triggers Apple push before waiting (2026+ auth)",
        "trigger_push_notification" in auth_py,
    )

    # --- CLI flags the runner passes ----------------------------------------
    cli_or_base = read("icloudpd/cli.py") + read("icloudpd/base.py")
    for flag in (
        "--auth-only",
        "--mfa-provider",
        "--password-provider",
        "--cookie-directory",
        "--library",
        "--list-libraries",
        "--folder-structure",
        "--no-progress-bar",
        "--log-level",
    ):
        check(f"CLI flag {flag}", flag in cli_or_base)

    mfa_provider_py = read("icloudpd/mfa_provider.py")
    check("MFAProvider has WEBUI", "WEBUI" in mfa_provider_py)
    password_provider_py = read("icloudpd/password_provider.py")
    check("PasswordProvider has KEYRING", "KEYRING" in password_provider_py)

    # --- cookie/session handling (cookies.py, runner.py) ---------------------
    pyicloud_base = read("pyicloud_ipd/base.py")
    check(
        "cookiejar named by keeping \\w chars of apple_id (cookie_filename rule)",
        re.search(r"match\(\s*r\"\\+w\",\s*c\s*\)", pyicloud_base) is not None
        or 'match(r"\\w", c)' in pyicloud_base,
    )
    check(
        "session file is cookiejar path + .session",
        re.search(r'\+\s*"\.session"', pyicloud_base) is not None,
    )

    session_py = read("pyicloud_ipd/session.py")
    check(
        "X-Apple-Session-Token persisted to session file (auth-budget signal)",
        "X-Apple-Session-Token" in session_py and "session_path" in session_py,
    )

    utils_py = read("pyicloud_ipd/utils.py")
    check("password read via python keyring library", "keyring.get_password" in utils_py)

    print()
    if FAILED:
        print(f"{len(FAILED)} assumption(s) BROKEN by icloudpd {args.version}:")
        for name in FAILED:
            print(f"  - {name}")
        print("Do NOT auto-release: the supervisor bridge likely needs code changes.")
        return 1
    print(f"All supervisor assumptions hold for icloudpd {args.version}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
