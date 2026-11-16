"""Keep the software security key's private key inside a YubiKey.

The YubiKey's FIDO function insists on a touch for every sign-in, so it cannot
confirm an unattended one. Its PIV (smart card) function is different: a key
in a PIV slot can never be read out, and can be set to sign without touch or
PIN. The software security key (softkey.py) then holds no secret at all — it
asks the YubiKey for each signature. Pull the YubiKey and no further sign-in
can be confirmed.

The YubiKey is reached through PC/SC where that exists (macOS, desktops, via
ykman) and otherwise directly over USB, which is what the container does: it
has no smart-card daemon, only access to the USB device.
"""

from __future__ import annotations

import struct
from typing import Any

from cryptography.hazmat.primitives import hashes

YUBICO_VENDOR_ID = 0x1050
_CCID_INTERFACE_CLASS = 0x0B


class PivError(Exception):
    """The YubiKey could not be asked (not plugged in, wrong one, no access)."""


def _usb_connection_class() -> Any:
    from yubikit.core import TRANSPORT
    from yubikit.core.smartcard import SmartCardConnection

    class UsbCcidConnection(SmartCardConnection):
        """APDUs to the YubiKey's smart-card interface, straight over USB (CCID)."""

        _POWER_ON, _POWER_OFF, _XFR_BLOCK = 0x62, 0x63, 0x6F
        _DATA_BLOCK, _SLOT_STATUS = 0x80, 0x81

        def __init__(self, device: Any) -> None:
            import usb.util

            self._device = device
            self._sequence = 0
            interface = None
            for candidate in device.get_active_configuration():
                if candidate.bInterfaceClass == _CCID_INTERFACE_CLASS:
                    interface = candidate
                    break
            if interface is None:
                raise PivError("this YubiKey has its smart-card (CCID) interface disabled")
            self._interface = interface.bInterfaceNumber
            try:
                if device.is_kernel_driver_active(self._interface):
                    device.detach_kernel_driver(self._interface)
            except (NotImplementedError, usb.core.USBError):
                pass
            usb.util.claim_interface(device, self._interface)

            def endpoint(direction: int) -> Any:
                return usb.util.find_descriptor(
                    interface,
                    custom_match=lambda e: usb.util.endpoint_direction(e.bEndpointAddress)
                    == direction
                    and usb.util.endpoint_type(e.bmAttributes) == usb.util.ENDPOINT_TYPE_BULK,
                )

            self._out = endpoint(usb.util.ENDPOINT_OUT)
            self._in = endpoint(usb.util.ENDPOINT_IN)
            self._exchange(self._POWER_ON, b"")

        @property
        def transport(self) -> Any:
            return TRANSPORT.USB

        def _exchange(self, message_type: int, data: bytes) -> bytes:
            sequence = self._sequence
            self._sequence = (self._sequence + 1) % 256
            header = struct.pack("<BIBB3x", message_type, len(data), 0, sequence)
            self._out.write(header + data, timeout=5000)
            while True:
                reply = bytes(self._in.read(65556, timeout=30000))
                while len(reply) < 10 or len(reply) < 10 + struct.unpack_from("<I", reply, 1)[0]:
                    reply += bytes(self._in.read(65556, timeout=30000))
                kind, length, _slot, reply_sequence, status, error = struct.unpack_from(
                    "<BIBBBB", reply
                )
                if reply_sequence != sequence:
                    continue  # stale answer to an earlier message
                if status & 0xC0 == 0x80:
                    continue  # time extension: the card is still working
                if status & 0xC0 or kind not in (self._DATA_BLOCK, self._SLOT_STATUS):
                    raise PivError(f"the YubiKey refused a CCID message (status {status:#x}, error {error:#x})")
                return reply[10 : 10 + length]

        def send_and_receive(self, apdu: bytes) -> tuple[bytes, int]:
            reply = self._exchange(self._XFR_BLOCK, apdu)
            if len(reply) < 2:
                raise PivError("short answer from the YubiKey")
            return reply[:-2], int.from_bytes(reply[-2:], "big")

        def close(self) -> None:
            import usb.util

            try:
                self._exchange(self._POWER_OFF, b"")
            except Exception:  # noqa: BLE001 - closing a device that may be gone
                pass
            usb.util.release_interface(self._device, self._interface)
            usb.util.dispose_resources(self._device)

    return UsbCcidConnection


def _serial_of(connection: Any) -> int | None:
    from yubikit.management import ManagementSession

    return ManagementSession(connection).read_device_info().serial


def _open_pcsc(serial: int | None) -> Any | None:
    """A PC/SC connection, or None when this machine has no PC/SC to ask."""
    try:
        from ykman.device import list_all_devices
        from yubikit.core.smartcard import SmartCardConnection
    except ImportError:
        return None
    try:
        devices = list_all_devices()
    except Exception:  # noqa: BLE001 - no PC/SC service running
        return None
    for device, info in devices:
        if serial in (None, info.serial) and device.supports_connection(SmartCardConnection):
            return device.open_connection(SmartCardConnection)
    return None


def usb_backend() -> Any | None:
    """libusb for pyusb, or None when it cannot start.

    libusb refuses to initialise when there is no USB bus to look at, which is
    the case in a container that /dev/bus/usb was not passed to.
    """
    import usb.backend.libusb1

    return usb.backend.libusb1.get_backend()


def _open_usb(serial: int | None) -> Any | None:
    try:
        import usb.core
    except ImportError:
        return None
    backend = usb_backend()
    if backend is None:
        raise PivError(
            "no USB access: pass /dev/bus/usb through to the container "
            "(or libusb is not installed)"
        )
    connection_class = _usb_connection_class()
    last_error: Exception | None = None
    for device in usb.core.find(find_all=True, idVendor=YUBICO_VENDOR_ID, backend=backend):
        try:
            connection = connection_class(device)
        except (PivError, usb.core.USBError) as error:
            last_error = error
            continue
        if serial is None or _serial_of(connection) == serial:
            return connection
        connection.close()
    if last_error is not None:
        raise PivError(f"a YubiKey is plugged in but cannot be used: {last_error}")
    return None


def open_connection(serial: int | None = None) -> Any:
    connection = _open_pcsc(serial) or _open_usb(serial)
    if connection is None:
        which = f"YubiKey {serial}" if serial else "a YubiKey"
        raise PivError(f"{which} is not plugged in (or not passed through to this container)")
    return connection


def slot_of(piv: dict[str, Any]) -> Any:
    from yubikit.piv import SLOT

    return SLOT(int(str(piv["slot"]), 16))


def sign(piv: dict[str, Any], message: bytes) -> bytes:
    """ECDSA P-256 / SHA-256 signature (DER) by the key in the configured slot."""
    from yubikit.piv import KEY_TYPE, PivSession

    with open_connection(piv.get("serial")) as connection:
        return PivSession(connection).sign(
            slot_of(piv), KEY_TYPE.ECCP256, message, hashes.SHA256()
        )


def usb_device_nodes() -> list[str]:
    """Device nodes of the YubiKeys that are plugged in (Linux)."""
    from pathlib import Path

    nodes = []
    for device in Path("/sys/bus/usb/devices").glob("*"):
        try:
            if int((device / "idVendor").read_text(), 16) != YUBICO_VENDOR_ID:
                continue
            bus = int((device / "busnum").read_text())
            number = int((device / "devnum").read_text())
        except (OSError, ValueError):
            continue
        nodes.append(f"/dev/bus/usb/{bus:03d}/{number:03d}")
    return nodes
