"""Cookie inspection.

icloudpd (pyicloud_ipd) stores its cookies as an LWPCookieJar in the cookie
directory, named by stripping every non-[A-Za-z0-9_] character from the
apple_id exactly as passed on the command line (pyicloud_ipd/base.py,
cookiejar_path). The old shell scripts re-derived this name three different,
mutually inconsistent ways; we derive it once, the same way icloudpd does.

The MFA trust lifetime is carried by the X-APPLE-WEBAUTH-USER cookie's expiry.
"""

from __future__ import annotations

import http.cookiejar
import re
import time
from dataclasses import dataclass
from pathlib import Path

MFA_COOKIE_NAME = "X-APPLE-WEBAUTH-USER"


def cookie_filename(apple_id: str) -> str:
    """Replicates pyicloud_ipd's cookiejar naming exactly.

    pyicloud_ipd keeps every character matching re.match(r"\\w", c), which is
    Unicode-aware — an ASCII-only [A-Za-z0-9_] rule would diverge for
    internationalized Apple IDs (e.g. "jörg@example.com").
    """
    return "".join(c for c in apple_id if re.match(r"\w", c))


def cookie_path(config_dir: str, apple_id: str) -> Path:
    return Path(config_dir) / cookie_filename(apple_id)


def session_path(config_dir: str, apple_id: str) -> Path:
    return Path(config_dir) / (cookie_filename(apple_id) + ".session")


@dataclass
class CookieStatus:
    exists: bool
    mfa_expires_at: float | None = None  # epoch seconds

    @property
    def days_remaining(self) -> int | None:
        if self.mfa_expires_at is None:
            return None
        return int((self.mfa_expires_at - time.time()) // 86400)

    @property
    def valid(self) -> bool:
        return self.mfa_expires_at is not None and self.mfa_expires_at > time.time()


def read_cookie_status(config_dir: str, apple_id: str) -> CookieStatus:
    """Load the cookiejar and report the MFA trust cookie's expiry.

    Never raises on malformed/missing files: a cookie we cannot read is a
    cookie that does not authenticate us, and is reported as such.
    """
    path = cookie_path(config_dir, apple_id)
    if not path.is_file():
        return CookieStatus(exists=False)

    jar = http.cookiejar.LWPCookieJar(filename=str(path))
    try:
        jar.load(ignore_discard=True, ignore_expires=True)
    except (OSError, ValueError, http.cookiejar.LoadError):
        # ValueError covers UnicodeDecodeError from legacy pickled jars.
        return CookieStatus(exists=True)

    for cookie in jar:
        if cookie.name == MFA_COOKIE_NAME:
            return CookieStatus(exists=True, mfa_expires_at=cookie.expires)
    return CookieStatus(exists=True)


def backup_auth_files(config_dir: str, apple_id: str) -> list[tuple[Path, Path]]:
    """Copy cookie+session aside before a reauth attempt.

    Returns (original, backup) pairs for the files that existed, so a failed
    reauth can restore them. The old container deleted these before
    authenticating, which stranded the account when auth failed.
    """
    pairs: list[tuple[Path, Path]] = []
    for original in (cookie_path(config_dir, apple_id), session_path(config_dir, apple_id)):
        if original.is_file():
            backup = original.with_name(original.name + ".reauth-backup")
            backup.write_bytes(original.read_bytes())
            pairs.append((original, backup))
    return pairs


def restore_auth_files(pairs: list[tuple[Path, Path]]) -> None:
    for original, backup in pairs:
        if backup.is_file():
            original.write_bytes(backup.read_bytes())
            backup.unlink()


def discard_backups(pairs: list[tuple[Path, Path]]) -> None:
    for _original, backup in pairs:
        backup.unlink(missing_ok=True)


def recover_stale_backups(config_dir: str, apple_id: str) -> bool:
    """Recover from a container death mid-reauth.

    A reauth deletes the originals after backing them up; if the container
    dies before the reauth concludes, .reauth-backup files are left behind.
    On startup: restore a backup whose original is missing (the reauth never
    finished), and discard a backup whose original exists (the reauth
    finished but cleanup did not). Returns True if anything was restored.
    """
    restored = False
    for original in (cookie_path(config_dir, apple_id), session_path(config_dir, apple_id)):
        backup = original.with_name(original.name + ".reauth-backup")
        if not backup.is_file():
            continue
        if original.is_file():
            backup.unlink(missing_ok=True)
        else:
            original.write_bytes(backup.read_bytes())
            backup.unlink(missing_ok=True)
            restored = True
    return restored
