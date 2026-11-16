#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["pyserial>=3.5", "fido2==2.2.1", "cryptography"]
# ///
"""Serve the software security key through the Pico USB bridge.

While this runs, the computer the Pico is plugged into sees a USB security key
that needs no touch. Requests are answered from (and new credentials are
written to) the key file — keep that file secret; it is the second factor.

    scripts/softkey/bridge.py --key ./softkey.json
    scripts/softkey/bridge.py --key ./softkey.json --self-test   # no Apple involved
"""

from __future__ import annotations

import argparse
import sys
import threading
import time
from pathlib import Path

import serial
from serial.tools import list_ports

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "supervisor"))
from icloudpd_supervisor import softkey  # noqa: E402

VID, PID = 0x1209, 0x0001


def log(message: str) -> None:
    print(f"{time.strftime('%H:%M:%S')} {message}", flush=True)


def find_port() -> str:
    ports = [p.device for p in list_ports.comports() if (p.vid, p.pid) == (VID, PID)]
    if not ports:
        sys.exit("error: no Pico bridge found — is it plugged in and flashed with softkey_bridge.uf2?")
    if len(ports) > 1:
        sys.exit(f"error: several bridges found ({', '.join(ports)}); pass --port")
    return ports[0]


def serve(port: str, key: str, stop: threading.Event, touch_delay: float = 0.0) -> None:
    session = softkey.CtapHidSession(softkey.SoftAuthenticator(key, log), touch_delay)
    with serial.Serial(port, timeout=0.2) as link:  # opening raises DTR: the bridge resets its buffers
        link.reset_input_buffer()
        log(f"software key ready on {port} (key file: {key})")
        buffer = b""
        while not stop.is_set():
            buffer += link.read(softkey.HID_PACKET - len(buffer))
            if len(buffer) < softkey.HID_PACKET:
                continue
            packet, buffer = buffer, b""
            for reply in session.feed(packet):
                link.write(reply)
                link.flush()


def self_test() -> None:
    """Register and sign in against a local test server, through real USB HID."""
    from fido2.client import DefaultClientDataCollector, Fido2Client
    from fido2.hid import CtapHidDevice
    from fido2.server import Fido2Server
    from fido2.webauthn import PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity

    devices = [d for d in CtapHidDevice.list_devices() if (d.descriptor.vid, d.descriptor.pid) == (VID, PID)]
    if not devices:
        sys.exit("self-test: the operating system does not list the bridge as a security key")
    client = Fido2Client(devices[0], client_data_collector=DefaultClientDataCollector("https://softkey.test"))
    server = Fido2Server(PublicKeyCredentialRpEntity(id="softkey.test", name="self-test"), attestation="direct")
    options, state = server.register_begin(
        PublicKeyCredentialUserEntity(id=b"self-test", name="self-test"), user_verification="discouraged"
    )
    credential = server.register_complete(state, client.make_credential(options.public_key)).credential_data
    options, state = server.authenticate_begin([credential], user_verification="discouraged")
    server.authenticate_complete(state, [credential], client.get_assertion(options.public_key).get_response(0))
    log("self-test passed: registered and signed in over USB")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--key", required=True, help="key file to use (created at the first registration)")
    parser.add_argument("--port", help="serial port of the bridge (default: found by USB id)")
    parser.add_argument(
        "--touch-delay", type=float, default=2.0, metavar="SECONDS",
        help="pretend the touch takes this long (default: 2; Apple's dialog hangs on an instant answer)",
    )
    parser.add_argument("--self-test", action="store_true", help="check the whole USB path with a throwaway key, then exit")
    args = parser.parse_args()
    port = args.port or find_port()
    stop = threading.Event()

    if args.self_test:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            thread = threading.Thread(target=serve, args=(port, f"{tmp}/selftest.json", stop, args.touch_delay), daemon=True)
            thread.start()
            time.sleep(1)
            try:
                self_test()
            finally:
                stop.set()
                thread.join(2)
        return

    try:
        serve(port, args.key, stop, args.touch_delay)
    except KeyboardInterrupt:
        log("stopped")


if __name__ == "__main__":
    main()
