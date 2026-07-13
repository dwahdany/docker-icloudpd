"""Tests for icloudpd_supervisor.cookies.

Hermetic: everything runs against temp files; the "reference" for the cookie
filename is the exact per-character keep-\\w rule from pyicloud_ipd/base.py
(cookiejar_path), re-implemented locally.
"""

from __future__ import annotations

import http.cookiejar
import re
import time
from pathlib import Path

import pytest

from icloudpd_supervisor import cookies
from icloudpd_supervisor.cookies import (
    MFA_COOKIE_NAME,
    CookieStatus,
    backup_auth_files,
    cookie_filename,
    cookie_path,
    discard_backups,
    read_cookie_status,
    restore_auth_files,
    session_path,
)

DAY = 86400


def pyicloud_cookiejar_name(apple_id: str) -> str:
    """Verbatim naming rule from pyicloud_ipd/base.py cookiejar_path."""
    return "".join([c for c in apple_id if re.match(r"\w", c)])


def make_cookie(name: str, value: str, expires: int | None) -> http.cookiejar.Cookie:
    """Build a well-formed persistent Cookie the way a real jar would hold it."""
    return http.cookiejar.Cookie(
        version=0,
        name=name,
        value=value,
        port=None,
        port_specified=False,
        domain=".icloud.com",
        domain_specified=True,
        domain_initial_dot=True,
        path="/",
        path_specified=True,
        secure=True,
        expires=expires,
        discard=False,
        comment=None,
        comment_url=None,
        rest={"HTTPOnly": None},
        rfc2109=False,
    )


def write_jar(path: Path, *jar_cookies: http.cookiejar.Cookie) -> None:
    """Save an LWPCookieJar exactly like pyicloud_ipd does (LWP format)."""
    jar = http.cookiejar.LWPCookieJar(filename=str(path))
    for c in jar_cookies:
        jar.set_cookie(c)
    jar.save(ignore_discard=True, ignore_expires=True)


# ---------------------------------------------------------------------------
# cookie_filename / cookie_path / session_path
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "apple_id",
    [
        "user.name+x@example.com",
        "john@example.com",
        "John.Appleseed@ICLOUD.COM",  # uppercase must be preserved
        "user_name@ex-ample.com",  # underscore kept, hyphen dropped
        "  spaced id@example.com ",
        "1234567890@example.com",
        "!#$%&'*+/=?^_`{|}~@example.com",  # every RFC5321 atext special
        "",
    ],
)
def test_cookie_filename_matches_pyicloud_derivation(apple_id: str) -> None:
    assert cookie_filename(apple_id) == pyicloud_cookiejar_name(apple_id)


def test_cookie_filename_expected_literals() -> None:
    assert cookie_filename("user.name+x@example.com") == "usernamexexamplecom"
    # Case is preserved, never folded.
    assert cookie_filename("John.Appleseed@ICLOUD.COM") == "JohnAppleseedICLOUDCOM"
    assert cookie_filename("user_name@example.com") == "user_nameexamplecom"


def test_cookie_filename_matches_pyicloud_for_unicode_apple_id() -> None:
    apple_id = "jörg@example.com"
    assert cookie_filename(apple_id) == pyicloud_cookiejar_name(apple_id)


def test_cookie_and_session_paths(tmp_path: Path) -> None:
    apple_id = "user.name+x@example.com"
    assert cookie_path(str(tmp_path), apple_id) == tmp_path / "usernamexexamplecom"
    assert (
        session_path(str(tmp_path), apple_id)
        == tmp_path / "usernamexexamplecom.session"
    )


# ---------------------------------------------------------------------------
# read_cookie_status
# ---------------------------------------------------------------------------

APPLE_ID = "user.name+x@example.com"


def test_read_cookie_status_missing_file(tmp_path: Path) -> None:
    status = read_cookie_status(str(tmp_path), APPLE_ID)
    assert status.exists is False
    assert status.mfa_expires_at is None
    assert status.valid is False
    assert status.days_remaining is None


def test_read_cookie_status_directory_instead_of_file(tmp_path: Path) -> None:
    cookie_path(str(tmp_path), APPLE_ID).mkdir()
    status = read_cookie_status(str(tmp_path), APPLE_ID)
    assert status.exists is False
    assert status.valid is False


@pytest.mark.parametrize(
    "content",
    [
        b"this is definitely not an LWP cookie jar\n",
        b"",  # empty file: missing #LWP-Cookies magic
        b"#LWP-Cookies-2.0\nSet-Cookie3: total garbage after the magic\n",
    ],
)
def test_read_cookie_status_unparseable_file(tmp_path: Path, content: bytes) -> None:
    cookie_path(str(tmp_path), APPLE_ID).write_bytes(content)
    status = read_cookie_status(str(tmp_path), APPLE_ID)
    assert status.exists is True
    assert status.mfa_expires_at is None
    assert status.valid is False
    assert status.days_remaining is None


def test_read_cookie_status_binary_pickled_legacy_jar(tmp_path: Path) -> None:
    # Minimal stand-in for a protocol-4 pickled cookiejar: not valid UTF-8.
    cookie_path(str(tmp_path), APPLE_ID).write_bytes(b"\x80\x04\x95pickled-garbage")
    status = read_cookie_status(str(tmp_path), APPLE_ID)
    assert status.exists is True
    assert status.mfa_expires_at is None
    assert status.valid is False


def test_read_cookie_status_future_mfa_cookie(tmp_path: Path) -> None:
    expires = int(time.time()) + 30 * DAY
    write_jar(
        cookie_path(str(tmp_path), APPLE_ID),
        make_cookie("X-APPLE-WEBAUTH-HSA-TRUST", "trust-token", expires),
        make_cookie(MFA_COOKIE_NAME, '"v=1:s=0"', expires),
    )
    status = read_cookie_status(str(tmp_path), APPLE_ID)
    assert status.exists is True
    assert status.mfa_expires_at == expires
    assert status.valid is True
    # 30 days minus the instants spent in the test: floor is 29.
    assert status.days_remaining in (29, 30)


def test_read_cookie_status_past_mfa_cookie(tmp_path: Path) -> None:
    expires = int(time.time()) - 5 * DAY
    write_jar(
        cookie_path(str(tmp_path), APPLE_ID),
        make_cookie(MFA_COOKIE_NAME, '"v=1:s=0"', expires),
    )
    status = read_cookie_status(str(tmp_path), APPLE_ID)
    assert status.exists is True
    # Expired cookies must still be surfaced (loaded with ignore_expires) so
    # the caller can see *when* trust lapsed, but they are not valid.
    assert status.mfa_expires_at == expires
    assert status.valid is False
    assert status.days_remaining is not None and status.days_remaining < 0


def test_read_cookie_status_jar_without_mfa_cookie(tmp_path: Path) -> None:
    expires = int(time.time()) + 30 * DAY
    write_jar(
        cookie_path(str(tmp_path), APPLE_ID),
        make_cookie("X-APPLE-WEBAUTH-TOKEN", "tok", expires),
        make_cookie("X-APPLE-WEBAUTH-HSA-TRUST", "trust", expires),
    )
    status = read_cookie_status(str(tmp_path), APPLE_ID)
    assert status.exists is True
    assert status.mfa_expires_at is None
    assert status.valid is False


# ---------------------------------------------------------------------------
# CookieStatus.days_remaining / valid arithmetic (deterministic clock)
# ---------------------------------------------------------------------------

NOW = 1_800_000_000.0


@pytest.fixture
def frozen_clock(monkeypatch: pytest.MonkeyPatch) -> float:
    monkeypatch.setattr(cookies.time, "time", lambda: NOW)
    return NOW


@pytest.mark.parametrize(
    ("delta", "expected_days"),
    [
        (30 * DAY, 30),
        (30 * DAY - 1, 29),  # one second short of 30 days floors to 29
        (10 * DAY + 5, 10),
        (DAY, 1),
        (DAY - 1, 0),
        (1, 0),
        (0, 0),
        (-1, -1),  # just expired floors to -1, not 0
        (-DAY, -1),
        (-DAY - 1, -2),
        (-5 * DAY, -5),
    ],
)
def test_days_remaining_arithmetic(
    frozen_clock: float, delta: int, expected_days: int
) -> None:
    status = CookieStatus(exists=True, mfa_expires_at=NOW + delta)
    assert status.days_remaining == expected_days


@pytest.mark.parametrize(
    ("delta", "expected_valid"),
    [(30 * DAY, True), (1, True), (0, False), (-1, False)],
)
def test_valid_boundary(frozen_clock: float, delta: int, expected_valid: bool) -> None:
    status = CookieStatus(exists=True, mfa_expires_at=NOW + delta)
    assert status.valid is expected_valid


def test_days_remaining_none_without_expiry() -> None:
    assert CookieStatus(exists=True).days_remaining is None
    assert CookieStatus(exists=False).days_remaining is None


# ---------------------------------------------------------------------------
# backup / restore / discard
# ---------------------------------------------------------------------------


def _seed_auth_files(tmp_path: Path) -> tuple[Path, Path]:
    cookie = cookie_path(str(tmp_path), APPLE_ID)
    session = session_path(str(tmp_path), APPLE_ID)
    cookie.write_bytes(b"#LWP-Cookies-2.0\noriginal-cookie\n")
    session.write_bytes(b'{"session": "original"}')
    return cookie, session


def test_backup_copies_both_files_and_keeps_originals(tmp_path: Path) -> None:
    cookie, session = _seed_auth_files(tmp_path)
    pairs = backup_auth_files(str(tmp_path), APPLE_ID)

    assert [(o, b) for o, b in pairs] == [
        (cookie, cookie.with_name(cookie.name + ".reauth-backup")),
        (session, session.with_name(session.name + ".reauth-backup")),
    ]
    for original, backup in pairs:
        assert backup.is_file()
        assert backup.read_bytes() == original.read_bytes()
    # Originals are copied aside, not moved: icloudpd must still see them.
    assert cookie.read_bytes() == b"#LWP-Cookies-2.0\noriginal-cookie\n"
    assert session.read_bytes() == b'{"session": "original"}'


def test_backup_with_no_auth_files_returns_empty(tmp_path: Path) -> None:
    assert backup_auth_files(str(tmp_path), APPLE_ID) == []


def test_backup_with_only_cookie_file(tmp_path: Path) -> None:
    cookie = cookie_path(str(tmp_path), APPLE_ID)
    cookie.write_bytes(b"cookie-only")
    pairs = backup_auth_files(str(tmp_path), APPLE_ID)
    assert len(pairs) == 1
    assert pairs[0][0] == cookie


def test_restore_overwrites_mangled_originals_and_removes_backups(
    tmp_path: Path,
) -> None:
    cookie, session = _seed_auth_files(tmp_path)
    pairs = backup_auth_files(str(tmp_path), APPLE_ID)

    # Failed reauth scribbles over both files.
    cookie.write_bytes(b"clobbered")
    session.write_bytes(b"clobbered")

    restore_auth_files(pairs)

    assert cookie.read_bytes() == b"#LWP-Cookies-2.0\noriginal-cookie\n"
    assert session.read_bytes() == b'{"session": "original"}'
    for _original, backup in pairs:
        assert not backup.exists()


def test_restore_after_originals_deleted(tmp_path: Path) -> None:
    """A failed reauth may delete cookie+session; restore must recreate them."""
    cookie, session = _seed_auth_files(tmp_path)
    pairs = backup_auth_files(str(tmp_path), APPLE_ID)

    cookie.unlink()
    session.unlink()

    restore_auth_files(pairs)

    assert cookie.read_bytes() == b"#LWP-Cookies-2.0\noriginal-cookie\n"
    assert session.read_bytes() == b'{"session": "original"}'
    for _original, backup in pairs:
        assert not backup.exists()


def test_restore_with_missing_backup_is_a_noop(tmp_path: Path) -> None:
    cookie, _session = _seed_auth_files(tmp_path)
    pairs = backup_auth_files(str(tmp_path), APPLE_ID)
    for _original, backup in pairs:
        backup.unlink()
    cookie.write_bytes(b"post-reauth")

    restore_auth_files(pairs)  # must not raise

    assert cookie.read_bytes() == b"post-reauth"


def test_discard_backups_removes_backups_keeps_originals(tmp_path: Path) -> None:
    cookie, session = _seed_auth_files(tmp_path)
    pairs = backup_auth_files(str(tmp_path), APPLE_ID)

    discard_backups(pairs)

    for original, backup in pairs:
        assert not backup.exists()
        assert original.is_file()
    assert cookie.read_bytes() == b"#LWP-Cookies-2.0\noriginal-cookie\n"
    assert session.read_bytes() == b'{"session": "original"}'


def test_discard_backups_tolerates_already_missing_backups(tmp_path: Path) -> None:
    _seed_auth_files(tmp_path)
    pairs = backup_auth_files(str(tmp_path), APPLE_ID)
    discard_backups(pairs)
    discard_backups(pairs)  # second discard must not raise


def test_backup_restore_roundtrip_preserves_readable_mfa_status(
    tmp_path: Path,
) -> None:
    """End to end: back up a real jar, wreck it, restore, re-read the expiry."""
    expires = int(time.time()) + 60 * DAY
    write_jar(
        cookie_path(str(tmp_path), APPLE_ID),
        make_cookie(MFA_COOKIE_NAME, '"v=1:s=0"', expires),
    )
    session_path(str(tmp_path), APPLE_ID).write_text("{}")

    pairs = backup_auth_files(str(tmp_path), APPLE_ID)
    cookie_path(str(tmp_path), APPLE_ID).unlink()
    session_path(str(tmp_path), APPLE_ID).unlink()
    assert read_cookie_status(str(tmp_path), APPLE_ID).exists is False

    restore_auth_files(pairs)

    status = read_cookie_status(str(tmp_path), APPLE_ID)
    assert status.exists is True
    assert status.mfa_expires_at == expires
    assert status.valid is True
