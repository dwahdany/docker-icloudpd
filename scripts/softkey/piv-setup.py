#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["yubikey-manager>=5.5,<6", "fido2==2.2.1", "cryptography"]
# ///
"""Create the software security key's private key INSIDE a YubiKey.

Generates a P-256 key in a free PIV slot of the YubiKey, set to sign without
touch and without PIN, and writes a key file that only points to it. The
private key is made by the YubiKey and can never be read out of it; the key
file holds nothing secret. Whoever has the YubiKey plugged in can confirm
sign-ins — pull it and nothing can.

    scripts/softkey/piv-setup.py --key ~/.config/icloudpd-softkey/softkey.json
    scripts/softkey/piv-setup.py --key ... --serial 12345678   # several YubiKeys plugged in

Nothing existing is overwritten: an occupied slot is never touched, and the
key file must not exist yet. Afterwards register the key with Apple through
the Pico bridge (bridge.py); the YubiKey is not needed for that step.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec



def die(message: str) -> None:
    sys.exit(f"error: {message}")


def main() -> None:
    from ykman.device import list_all_devices
    from yubikit.core.smartcard import ApduError, SmartCardConnection
    from yubikit.piv import (
        DEFAULT_MANAGEMENT_KEY,
        KEY_TYPE,
        PIN_POLICY,
        SLOT,
        TOUCH_POLICY,
        PivSession,
    )

    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--key", required=True, help="key file to create (must not exist)")
    parser.add_argument("--serial", type=int, help="serial number of the YubiKey to use")
    parser.add_argument("--slot", help="PIV slot in hex (default: the first free retired slot, 82-95)")
    parser.add_argument("--management-key", help="PIV management key in hex, if it is not the default")
    args = parser.parse_args()

    key_path = Path(args.key).expanduser()
    if key_path.exists():
        die(f"{key_path} already exists; move it away first (it may hold a registered key)")

    devices = [(d, i) for d, i in list_all_devices() if d.supports_connection(SmartCardConnection)]
    if args.serial:
        devices = [(d, i) for d, i in devices if i.serial == args.serial]
    if not devices:
        die("no YubiKey found" + (f" with serial {args.serial}" if args.serial else ""))
    if len(devices) > 1:
        listed = ", ".join(str(i.serial) for _d, i in devices)
        die(f"several YubiKeys are plugged in ({listed}); pass --serial")
    device, info = devices[0]
    if info.serial is None:
        die("this YubiKey does not report a serial number")
    print(f"YubiKey {info.serial}, firmware {info.version}")

    with device.open_connection(SmartCardConnection) as connection:
        session = PivSession(connection)

        def occupied(slot: SLOT) -> bool:
            try:
                session.get_slot_metadata(slot)
                return True
            except ApduError:
                return False

        if args.slot:
            slot = SLOT(int(args.slot, 16))
            if occupied(slot):
                die(f"slot {args.slot} already holds a key; it is left untouched")
        else:
            free = [s for s in SLOT if s.name.startswith("RETIRED") and not occupied(s)]
            if not free:
                die("no free retired PIV slot (82-95) on this YubiKey")
            slot = free[0]
        print(f"Using PIV slot {slot.value:02x} (free)")

        metadata = session.get_management_key_metadata()
        if args.management_key:
            management_key = bytes.fromhex(args.management_key)
        elif metadata.default_value:
            management_key = DEFAULT_MANAGEMENT_KEY
        else:
            die("this YubiKey's PIV management key was changed; pass it with --management-key")
        session.authenticate(metadata.key_type, management_key)

        public_key = session.generate_key(
            slot, KEY_TYPE.ECCP256, PIN_POLICY.NEVER, TOUCH_POLICY.NEVER
        )
        print("Generated a P-256 key in the YubiKey (no touch, no PIN, not exportable)")

        # Prove it signs unattended, with the same call the container makes.
        message = os.urandom(32)
        signature = session.sign(slot, KEY_TYPE.ECCP256, message, hashes.SHA256())
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        print("Test signature made without touch: ok")

    state = {
        "version": 1,
        "aaguid": os.urandom(16).hex(),
        "piv": {
            "serial": info.serial,
            "slot": f"{slot.value:02x}",
            "public_key": public_key.public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode(),
        },
        "credentials": [],
    }
    key_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)
    print(f"Wrote {key_path}")
    print()
    print("Next: unplug this YubiKey (and any other security key), plug in the Pico and run")
    print(f"  scripts/softkey/bridge.py --key {key_path}")
    print("then add the key under System Settings -> Apple Account -> Sign-In & Security.")
    if metadata.default_value:
        print()
        print("Note: this YubiKey's PIV management key is still the factory default. That")
        print("does not let anyone read the key, but anyone with USB access could delete it.")


if __name__ == "__main__":
    main()
