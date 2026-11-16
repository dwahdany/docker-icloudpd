"""A software FIDO2 security key whose credentials live in a file.

Apple IDs protected by security keys never get a six-digit code: every new
sign-in must be confirmed by a registered key. A hardware key cannot do that
for an unattended container, so this module implements the authenticator side
of CTAP2 in software. It is used in two places:

- at registration, behind a USB bridge that makes it look like a USB key to
  the Mac that adds it to the Apple ID (scripts/softkey);
- in the container, where it answers Apple's sign-in challenge in-process
  (see ``SoftCtapDevice``).

The key file IS the second factor. Anyone who can read it (together with the
account password) can sign in to the Apple ID. It is written 0600. The
exception is a key file set up for a YubiKey (piv.py): there the private key
is in the YubiKey and the file holds nothing secret.

Only what the above needs is implemented: ES256, no PIN, no resident keys, no
U2F (CTAP1). User presence is always asserted — that is the point.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
import tempfile
import time
from typing import Any, Callable, Iterator

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

# ---- CTAP2 ----------------------------------------------------------------------------------

CMD_MAKE_CREDENTIAL = 0x01
CMD_GET_ASSERTION = 0x02
CMD_GET_INFO = 0x04

OK = 0x00
ERR_INVALID_COMMAND = 0x01
ERR_INVALID_CBOR = 0x12
ERR_MISSING_PARAMETER = 0x14
ERR_CREDENTIAL_EXCLUDED = 0x19
ERR_UNSUPPORTED_ALGORITHM = 0x26
ERR_UNSUPPORTED_OPTION = 0x2B
ERR_NO_CREDENTIALS = 0x2E
ERR_PIN_NOT_SET = 0x35
ERR_OTHER = 0x7F

_ES256 = -7
_FLAG_UP = 0x01
_FLAG_AT = 0x40


class CtapError(Exception):
    def __init__(self, code: int) -> None:
        super().__init__(f"CTAP error 0x{code:02x}")
        self.code = code


def _cbor():  # fido2 ships with icloudpd; import late so the supervisor starts without it
    from fido2 import cbor

    return cbor


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _new_attestation(aaguid: bytes) -> dict[str, str]:
    """An attestation key and its certificate, as the packed format requires them."""
    import datetime

    from cryptography import x509
    from cryptography.x509.oid import NameOID

    def name(common_name: str, unit: str | None = None) -> x509.Name:
        attributes = [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "DE"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "docker-icloudpd"),
        ]
        if unit:
            attributes.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, unit))
        attributes.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))
        return x509.Name(attributes)

    now = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
    until = now + datetime.timedelta(days=365 * 30)
    root_key = ec.generate_private_key(ec.SECP256R1())  # used once, then forgotten
    key = ec.generate_private_key(ec.SECP256R1())
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name("Soft Security Key", "Authenticator Attestation"))
        .issuer_name(name("Soft Security Key Root"))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(until)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(  # id-fido-gen-ce-aaguid: an OCTET STRING holding the AAGUID
            x509.UnrecognizedExtension(
                x509.ObjectIdentifier("1.3.6.1.4.1.45724.1.1.4"), b"\x04\x10" + aaguid
            ),
            critical=False,
        )
        .sign(root_key, hashes.SHA256())
    )
    return {
        "key": key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode(),
        "certificate": _b64(certificate.public_bytes(serialization.Encoding.DER)),
    }


class SoftAuthenticator:
    """CTAP2 authenticator backed by a JSON key file."""

    def __init__(
        self,
        path: str,
        log: Callable[[str], None] | None = None,
        hardware_sign: Callable[[dict[str, Any], bytes], bytes] | None = None,
    ) -> None:
        self._path = path
        self._log = log or (lambda _msg: None)
        self._hardware_sign = hardware_sign
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                self._state = json.load(f)
        else:
            self._state = {"version": 1, "aaguid": os.urandom(16).hex(), "credentials": []}
        if "attestation" not in self._state:
            self._state["attestation"] = _new_attestation(bytes.fromhex(self._state["aaguid"]))

    # --- storage ---------------------------------------------------------------

    @property
    def credentials(self) -> list[dict[str, Any]]:
        return list(self._state["credentials"])

    def _save(self) -> None:
        directory = os.path.dirname(os.path.abspath(self._path))
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".softkey-")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(self._state, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, self._path)
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise

    def _find(self, rp_id: str, credential_id: bytes) -> dict[str, Any] | None:
        wanted = _b64(credential_id)
        for cred in self._state["credentials"]:
            if cred["id"] == wanted and cred["rp_id"] == rp_id:
                return cred
        return None

    # --- protocol --------------------------------------------------------------

    @staticmethod
    def wants_presence(request: bytes) -> bool:
        """Whether a hardware key would wait for a touch before answering this."""
        if not request:
            return False
        if request[0] == CMD_MAKE_CREDENTIAL:
            return True
        if request[0] == CMD_GET_ASSERTION:
            try:
                options = _cbor().decode(request[1:]).get(5) or {}
            except (ValueError, AttributeError, TypeError, IndexError):
                return False
            return options.get("up", True) is not False
        return False

    def handle(self, request: bytes) -> bytes:
        """One CTAP2 request (command byte + CBOR) -> response (status byte + CBOR)."""
        cbor = _cbor()
        if not request:
            return bytes([ERR_INVALID_COMMAND])
        command, body = request[0], request[1:]
        try:
            params = cbor.decode(body) if body else {}
            if not isinstance(params, dict):
                raise CtapError(ERR_INVALID_CBOR)
            if command == CMD_GET_INFO:
                result = self._get_info()
            elif command == CMD_MAKE_CREDENTIAL:
                result = self._make_credential(params)
            elif command == CMD_GET_ASSERTION:
                result = self._get_assertion(params)
            else:
                self._log(f"unsupported CTAP2 command 0x{command:02x}")
                raise CtapError(ERR_INVALID_COMMAND)
        except CtapError as error:
            self._log(f"command 0x{command:02x} -> error 0x{error.code:02x}")
            return bytes([error.code])
        except (ValueError, KeyError, TypeError, IndexError) as error:
            self._log(f"command 0x{command:02x} -> malformed request ({error!r})")
            return bytes([ERR_INVALID_CBOR])
        except Exception as error:  # noqa: BLE001 - e.g. the YubiKey holding the key is gone
            self._log(f"command 0x{command:02x} failed: {error}")
            return bytes([ERR_OTHER])
        return bytes([OK]) + cbor.encode(result)

    def _get_info(self) -> dict[int, Any]:
        return {
            1: ["FIDO_2_0"],
            3: bytes.fromhex(self._state["aaguid"]),
            4: {"rk": False, "up": True, "plat": False},
            5: 7609,  # maxMsgSize
            9: ["usb"],
            10: [{"alg": _ES256, "type": "public-key"}],
        }

    @staticmethod
    def _check_common(params: dict[int, Any], options_key: int, pin_key: int) -> None:
        options = params.get(options_key) or {}
        if options.get("uv"):
            raise CtapError(ERR_UNSUPPORTED_OPTION)
        if options.get("rk"):
            raise CtapError(ERR_UNSUPPORTED_OPTION)
        if params.get(pin_key) is not None:
            raise CtapError(ERR_PIN_NOT_SET)

    def _make_credential(self, params: dict[int, Any]) -> dict[int, Any]:
        for key in (1, 2, 3, 4):
            if key not in params:
                raise CtapError(ERR_MISSING_PARAMETER)
        client_data_hash: bytes = params[1]
        rp: dict[str, Any] = params[2]
        user: dict[str, Any] = params[3]
        rp_id = rp["id"]
        if not any(p.get("alg") == _ES256 and p.get("type") == "public-key" for p in params[4]):
            raise CtapError(ERR_UNSUPPORTED_ALGORITHM)
        self._check_common(params, 7, 8)
        for excluded in params.get(5) or []:
            if self._find(rp_id, excluded["id"]):
                raise CtapError(ERR_CREDENTIAL_EXCLUDED)

        # The credential key: in the YubiKey if this key file is set up for one
        # (only its public half is needed here), else made now and kept in the file.
        hardware = self._state.get("piv")
        if hardware:
            private_key = None
            public_key = serialization.load_pem_public_key(hardware["public_key"].encode())
        else:
            private_key = ec.generate_private_key(ec.SECP256R1())
            public_key = private_key.public_key()
        credential_id = os.urandom(32)
        numbers = public_key.public_numbers()  # type: ignore[union-attr]
        cose_key = {
            1: 2,  # kty: EC2
            3: _ES256,
            -1: 1,  # crv: P-256
            -2: numbers.x.to_bytes(32, "big"),
            -3: numbers.y.to_bytes(32, "big"),
        }
        auth_data = (
            hashlib.sha256(rp_id.encode()).digest()
            + bytes([_FLAG_UP | _FLAG_AT])
            + struct.pack(">I", 0)
            + bytes.fromhex(self._state["aaguid"])
            + struct.pack(">H", len(credential_id))
            + credential_id
            + _cbor().encode(cose_key)
        )
        # Packed attestation with a certificate, the shape hardware keys produce
        # (Apple's server turns down self attestation). The certificate chains to
        # a root made up for this key file, not to a vendor.
        attestation = self._state["attestation"]
        attestation_key = serialization.load_pem_private_key(attestation["key"].encode(), None)
        signature = attestation_key.sign(  # type: ignore[union-attr, call-arg]
            auth_data + client_data_hash, ec.ECDSA(hashes.SHA256())
        )

        credential = {
            "id": _b64(credential_id),
            "rp_id": rp_id,
            "user_id": _b64(user.get("id", b"")),
            "user_name": user.get("name", ""),
            "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        if private_key is not None:
            credential["private_key"] = private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ).decode()
        self._state["credentials"].append(credential)
        self._save()
        self._log(f"registered a credential for {rp_id} ({user.get('name', '?')})")
        return {
            1: "packed",
            2: auth_data,
            3: {
                "alg": _ES256,
                "sig": signature,
                "x5c": [base64.b64decode(attestation["certificate"])],
            },
        }

    def _sign_in_hardware(self, message: bytes) -> bytes:
        hardware = self._state["piv"]
        sign = self._hardware_sign
        if sign is None:
            from . import piv

            sign = piv.sign
        signature = sign(hardware, message)
        # A different YubiKey, or a slot that was overwritten, would produce a
        # signature Apple rejects; say so here instead.
        public_key = serialization.load_pem_public_key(hardware["public_key"].encode())
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))  # type: ignore[union-attr, call-arg]
        return signature

    def _get_assertion(self, params: dict[int, Any]) -> dict[int, Any]:
        for key in (1, 2):
            if key not in params:
                raise CtapError(ERR_MISSING_PARAMETER)
        rp_id: str = params[1]
        client_data_hash: bytes = params[2]
        self._check_common(params, 5, 6)
        cred = None
        for allowed in params.get(3) or []:
            cred = self._find(rp_id, allowed["id"])
            if cred:
                break
        if cred is None:
            raise CtapError(ERR_NO_CREDENTIALS)

        # Signature counter 0 = "not supported": nothing to persist, nothing to
        # get out of step between the machine that registers and the one that signs.
        auth_data = (
            hashlib.sha256(rp_id.encode()).digest() + bytes([_FLAG_UP]) + struct.pack(">I", 0)
        )
        message = auth_data + client_data_hash
        if "private_key" in cred:
            private_key = serialization.load_pem_private_key(cred["private_key"].encode(), None)
            signature = private_key.sign(  # type: ignore[union-attr, call-arg]
                message, ec.ECDSA(hashes.SHA256())
            )
        else:
            signature = self._sign_in_hardware(message)
        self._log(f"signed a sign-in challenge for {rp_id}")
        return {
            1: {"id": base64.b64decode(cred["id"]), "type": "public-key"},
            2: auth_data,
            3: signature,
        }


# ---- CTAPHID framing (used by the USB bridge) -----------------------------------------------

HID_PACKET = 64
_HID_PING = 0x01
_HID_MSG = 0x03
_HID_INIT = 0x06
_HID_WINK = 0x08
_HID_CBOR = 0x10
_HID_CANCEL = 0x11
_HID_KEEPALIVE = 0x3B
_KEEPALIVE_UP_NEEDED = 2
_HID_ERROR = 0x3F
_CAP_WINK = 0x01
_CAP_CBOR = 0x04
_CAP_NMSG = 0x08
_HID_ERR_INVALID_CMD = 0x01
_HID_ERR_INVALID_SEQ = 0x04
_BROADCAST = 0xFFFFFFFF


class CtapHidSession:
    """Turns 64-byte HID reports from the host into reports to send back."""

    def __init__(self, authenticator: SoftAuthenticator, presence_delay: float = 0.0) -> None:
        self._authenticator = authenticator
        # Seconds to wait (sending "touch needed" keepalives, as a hardware key
        # does) before answering a request that needs user presence. Apple's
        # registration dialog gets stuck when the key answers before the dialog
        # has finished appearing.
        self._presence_delay = presence_delay
        self._next_cid = 1
        # cid -> [command, expected length, data so far, next sequence number]
        self._pending: dict[int, list[Any]] = {}

    def feed(self, packet: bytes) -> Iterator[bytes]:
        if len(packet) != HID_PACKET:
            return
        cid = struct.unpack(">I", packet[:4])[0]
        if packet[4] & 0x80:
            command = packet[4] & 0x7F
            length = struct.unpack(">H", packet[5:7])[0]
            self._pending[cid] = [command, length, bytearray(packet[7:]), 0]
        else:
            pending = self._pending.get(cid)
            if pending is None:
                return  # stray continuation packet
            if packet[4] != pending[3]:
                del self._pending[cid]
                yield from self._frames(cid, _HID_ERROR, bytes([_HID_ERR_INVALID_SEQ]))
                return
            pending[2] += packet[5:]
            pending[3] += 1
        command, length, data, _seq = self._pending[cid]
        if len(data) < length:
            return
        del self._pending[cid]
        yield from self._dispatch(cid, command, bytes(data[:length]))

    def _dispatch(self, cid: int, command: int, data: bytes) -> Iterator[bytes]:
        if command == _HID_INIT:
            new_cid = cid
            if cid == _BROADCAST:
                new_cid = self._next_cid
                self._next_cid += 1
            reply = (
                data[:8].ljust(8, b"\0")
                + struct.pack(">I", new_cid)
                + bytes([2, 1, 0, 0, _CAP_WINK | _CAP_CBOR | _CAP_NMSG])
            )
            yield from self._frames(cid, _HID_INIT, reply)
        elif command == _HID_PING:
            yield from self._frames(cid, _HID_PING, data)
        elif command == _HID_WINK:
            yield from self._frames(cid, _HID_WINK, b"")
        elif command == _HID_CBOR:
            if self._presence_delay > 0 and self._authenticator.wants_presence(data):
                deadline = time.monotonic() + self._presence_delay
                while time.monotonic() < deadline:
                    yield from self._frames(cid, _HID_KEEPALIVE, bytes([_KEEPALIVE_UP_NEEDED]))
                    time.sleep(0.1)
            yield from self._frames(cid, _HID_CBOR, self._authenticator.handle(data))
        elif command == _HID_CANCEL:
            return  # requests are answered immediately; nothing to cancel
        else:  # including _HID_MSG: no U2F
            yield from self._frames(cid, _HID_ERROR, bytes([_HID_ERR_INVALID_CMD]))

    @staticmethod
    def _frames(cid: int, command: int, data: bytes) -> Iterator[bytes]:
        head = struct.pack(">IBH", cid, command | 0x80, len(data)) + data[: HID_PACKET - 7]
        yield head.ljust(HID_PACKET, b"\0")
        rest = data[HID_PACKET - 7 :]
        seq = 0
        while rest:
            frame = struct.pack(">IB", cid, seq) + rest[: HID_PACKET - 5]
            yield frame.ljust(HID_PACKET, b"\0")
            rest = rest[HID_PACKET - 5 :]
            seq += 1


# ---- in-process device for python-fido2 (used in the container) ------------------------------


def make_ctap_device(
    path: str,
    log: Callable[[str], None] | None = None,
    hardware_sign: Callable[[dict[str, Any], bytes], bytes] | None = None,
) -> Any:
    """A python-fido2 ``CtapDevice`` that is answered by the key file at ``path``."""
    from fido2.ctap import CtapDevice, CtapError as Fido2CtapError
    from fido2.hid import CAPABILITY, CTAPHID

    authenticator = SoftAuthenticator(path, log, hardware_sign)

    class SoftCtapDevice(CtapDevice):
        @property
        def capabilities(self) -> Any:
            return CAPABILITY.CBOR | CAPABILITY.NMSG

        def call(self, cmd: int, data: bytes = b"", event: Any = None, on_keepalive: Any = None) -> bytes:
            if cmd != CTAPHID.CBOR:
                raise Fido2CtapError(Fido2CtapError.ERR.INVALID_COMMAND)
            return authenticator.handle(data)

        def close(self) -> None:
            pass

        @classmethod
        def list_devices(cls) -> Iterator[Any]:
            return iter(())

    return SoftCtapDevice()
