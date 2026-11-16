"""The raw-USB (CCID) path to the YubiKey, against a scripted device."""

import struct
import sys
import types

import pytest

pytest.importorskip("yubikit")

from icloudpd_supervisor import piv  # noqa: E402


class _Endpoint:
    def __init__(self, device, direction):
        self.device, self.direction = device, direction
        self.bEndpointAddress = 0x82 if direction == "in" else 0x02
        self.bmAttributes = 2  # bulk

    def write(self, data, timeout=None):
        self.device.handle(bytes(data))

    def read(self, size, timeout=None):
        return self.device.replies.pop(0)


class _Interface:
    bInterfaceClass = 0x0B
    bInterfaceNumber = 2


class _Device:
    """Answers CCID messages; APDUs are answered by `card`."""

    def __init__(self, card, extensions=0):
        self.card, self.extensions = card, extensions
        self.replies, self.powered, self.claimed = [], False, False
        self.interface = _Interface()
        self.endpoints = {"in": _Endpoint(self, "in"), "out": _Endpoint(self, "out")}

    def get_active_configuration(self):
        return [types.SimpleNamespace(bInterfaceClass=3, bInterfaceNumber=0), self.interface]

    def is_kernel_driver_active(self, _interface):
        return False

    def handle(self, message):
        kind, length, _slot, sequence = struct.unpack_from("<BIBB", message)
        data = message[10 : 10 + length]

        def reply(kind, payload=b"", status=0):
            self.replies.append(struct.pack("<BIBBBBB", kind, len(payload), 0, sequence, status, 0, 0) + payload)

        if kind == 0x62:
            self.powered = True
            reply(0x80, b"\x3b\xfd")
        elif kind == 0x63:
            self.powered = False
            reply(0x81)
        elif kind == 0x6F:
            for _ in range(self.extensions):
                reply(0x80, status=0x80)  # "still working"
            answer = self.card(data)
            # split across two USB reads, as a long answer would be
            whole = struct.pack("<BIBBBBB", 0x80, len(answer), 0, sequence, 0, 0, 0) + answer
            self.replies += [whole[:7], whole[7:]]


@pytest.fixture
def fake_usb(monkeypatch):
    """A stand-in for pyusb's usb.util, so the test needs no USB at all."""
    util = types.ModuleType("usb.util")
    util.ENDPOINT_OUT, util.ENDPOINT_IN, util.ENDPOINT_TYPE_BULK = "out", "in", 2
    util.claim_interface = lambda device, _n: setattr(device, "claimed", True)
    util.release_interface = lambda device, _n: setattr(device, "claimed", False)
    util.dispose_resources = lambda device: None
    util.endpoint_direction = lambda address: "in" if address & 0x80 else "out"
    util.endpoint_type = lambda attributes: attributes & 3
    util.find_descriptor = lambda interface, custom_match: next(
        e for e in interface.device.endpoints.values() if custom_match(e)
    )
    core = types.ModuleType("usb.core")
    core.USBError = type("USBError", (Exception,), {})
    usb = types.ModuleType("usb")
    usb.util, usb.core = util, core
    monkeypatch.setitem(sys.modules, "usb", usb)
    monkeypatch.setitem(sys.modules, "usb.util", util)
    monkeypatch.setitem(sys.modules, "usb.core", core)


def _connect(device):
    device.interface.device = device
    return piv._usb_connection_class()(device)


def test_apdu_round_trip_with_time_extension_and_split_reads(fake_usb):
    seen = []

    def card(apdu):
        seen.append(apdu)
        return b"answer" + b"\x90\x00"

    device = _Device(card, extensions=2)
    connection = _connect(device)
    assert device.powered and device.claimed

    assert connection.send_and_receive(b"\x00\xa4\x04\x00") == (b"answer", 0x9000)
    assert seen == [b"\x00\xa4\x04\x00"]

    connection.close()
    assert not device.powered and not device.claimed


def test_status_word_is_returned_not_raised(fake_usb):
    connection = _connect(_Device(lambda _apdu: b"\x6a\x82"))
    assert connection.send_and_receive(b"\x00\xa4\x04\x00") == (b"", 0x6A82)


def test_slot_is_read_as_hex():
    from yubikit.piv import SLOT

    assert piv.slot_of({"slot": "82"}) == SLOT.RETIRED1
    assert piv.slot_of({"slot": "9c"}) == SLOT.SIGNATURE
