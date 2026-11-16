#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["segno>=1.6", "cryptography"]
# ///
"""Paper backup of a software security key, and restoring from it.

    scripts/softkey/backup.py --key softkey.json --out backup.html    # open, print, delete
    scripts/softkey/backup.py --restore softkey.json                  # paste the backup text

The page holds the key as text and as a QR code of the same text. It is a
second factor for the Apple ID in plain sight: print it on a printer you
trust, delete the HTML file, and store the paper like a spare key. Only a
key file that holds its private key can be backed up — one that points to a
YubiKey cannot (make the backup before piv-setup.py --import-key).
"""

from __future__ import annotations

import argparse
import base64
import html
import json
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def die(message: str) -> None:
    sys.exit(f"error: {message}")


def to_backup(state: dict) -> str:
    if len(state.get("credentials", [])) != 1 or "private_key" not in state["credentials"][0]:
        die("the key file must hold exactly one credential with its private key")
    credential = state["credentials"][0]
    key = serialization.load_pem_private_key(credential["private_key"].encode(), None)
    secret = key.private_numbers().private_value.to_bytes(32, "big")
    # Short enough to type by hand: the 32-byte private scalar and the ids.
    return json.dumps(
        {
            "softkey": 1,
            "rp": credential["rp_id"],
            "id": credential["id"],
            "user": credential["user_id"],
            "aaguid": state["aaguid"],
            "d": secret.hex(),
        },
        separators=(",", ":"),
    )


def from_backup(text: str) -> dict:
    data = json.loads(text)
    if data.get("softkey") != 1:
        die("this is not a software security key backup")
    scalar = int(data["d"], 16)
    if not 0 < scalar < P256_ORDER:
        die("the private key in the backup is not valid (typing error?)")
    key = ec.derive_private_key(scalar, ec.SECP256R1())
    base64.b64decode(data["id"], validate=True)
    return {
        "version": 1,
        "aaguid": data["aaguid"],
        "credentials": [
            {
                "id": data["id"],
                "rp_id": data["rp"],
                "user_id": data["user"],
                "user_name": "",
                "created": "restored from backup",
                "private_key": key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                ).decode(),
            }
        ],
    }


def page(backup: str, label: str) -> str:
    import segno

    qr = segno.make(backup, error="q").svg_inline(scale=5, border=2)
    lines = "\n".join(backup[i : i + 48] for i in range(0, len(backup), 48))
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Security key backup</title>
<style>
body {{ font: 12pt/1.5 system-ui, sans-serif; margin: 2cm; color: #000; }}
pre {{ font: 11pt/1.6 ui-monospace, Menlo, monospace; border: 1px solid #000; padding: .6cm; }}
p {{ max-width: 16cm; }}
</style></head><body>
<h1>Security key backup</h1>
<p><strong>{html.escape(label)}</strong></p>
<p>This sheet is a working security key for the Apple ID it was registered with.
Anyone who has it and the account password can sign in. Keep it locked away.</p>
{qr}
<p>The same content as text (one line, no spaces or line breaks when typed):</p>
<pre>{html.escape(lines)}</pre>
<p>To restore: run <code>scripts/softkey/backup.py --restore softkey.json</code> from
github.com/dwahdany/docker-icloudpd and paste the scanned or typed text. The
resulting file works with the container, with <code>verify.sh</code>, and through
<code>bridge.py</code> as a USB security key.</p>
</body></html>
"""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--key", help="key file to back up")
    parser.add_argument("--out", help="HTML page to write (print it, then delete it)")
    parser.add_argument("--label", default="Software security key", help="heading on the page, e.g. the key's name")
    parser.add_argument("--restore", metavar="FILE", help="write a key file from backup text read on stdin")
    args = parser.parse_args()

    if args.restore:
        target = Path(args.restore).expanduser()
        if target.exists():
            die(f"{target} already exists")
        text = "".join(sys.stdin.read().split())
        state = from_backup(text)
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
        print(f"Wrote {target}")
        return

    if not (args.key and args.out):
        parser.error("--key and --out are required (or --restore)")
    out = Path(args.out).expanduser()
    if out.exists():
        die(f"{out} already exists")
    backup = to_backup(json.loads(Path(args.key).expanduser().read_text()))
    # Round trip before anything is printed.
    restored = from_backup(backup)
    assert to_backup(restored) == backup
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(page(backup, args.label))
    print(f"Wrote {out} ({len(backup)} characters). Print it, then delete the file.")


if __name__ == "__main__":
    main()
