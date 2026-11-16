"""Run icloudpd with the software security key standing in for a USB key.

    python -m icloudpd_supervisor.softkey_run <key-file> <icloudpd arguments...>

icloudpd (>= 1.33.0) confirms a security-key sign-in by asking python-fido2
for the USB keys that are plugged in. This replaces that list with the
software key, then hands over to icloudpd unchanged. Only icloudpd's console
MFA flow knows about security keys, so pass ``--mfa-provider console``.
"""

from __future__ import annotations

import sys


def install(key_file: str) -> None:
    from fido2.hid import CtapHidDevice

    from . import softkey

    def log(message: str) -> None:
        print(f"[softkey] {message}", flush=True)

    def list_devices(cls):  # noqa: ANN001, ANN202 - signature of the method it replaces
        return iter([softkey.make_ctap_device(key_file, log)])

    CtapHidDevice.list_devices = classmethod(list_devices)  # type: ignore[method-assign]


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        print(__doc__, file=sys.stderr)
        return 2
    install(args[0])
    sys.argv = ["icloudpd", *args[1:]]
    from icloudpd.cli import cli

    result = cli()
    return result if isinstance(result, int) else 0


if __name__ == "__main__":
    sys.exit(main())
