"""The software security key against python-fido2's own client and server."""

import json
import os
import stat
import struct

import pytest

pytest.importorskip("fido2")

from fido2.client import DefaultClientDataCollector, Fido2Client  # noqa: E402
from fido2.server import Fido2Server  # noqa: E402
from fido2.webauthn import (  # noqa: E402
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialRequestOptions,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialType,
    PublicKeyCredentialUserEntity,
    UserVerificationRequirement,
)

from icloudpd_supervisor import softkey  # noqa: E402

ORIGIN = "https://apple.com"


def _client(path):
    return Fido2Client(
        softkey.make_ctap_device(str(path)),
        client_data_collector=DefaultClientDataCollector(ORIGIN),
    )


def _register(path, server):
    options, state = server.register_begin(
        PublicKeyCredentialUserEntity(id=b"user-1", name="someone@example.com"),
        user_verification=UserVerificationRequirement.DISCOURAGED,
    )
    response = _client(path).make_credential(options.public_key)
    return server.register_complete(state, response)


class _AnyRoot:
    """Accept the made-up attestation root; the signature and the certificate
    profile (subject, AAGUID extension, not a CA) are still verified."""

    def __new__(cls):
        from fido2.attestation import AttestationVerifier

        class Verifier(AttestationVerifier):
            def ca_lookup(self, result, auth_data):
                return None

            def verify_attestation(self, attestation_object, client_data_hash):
                from fido2.attestation import PackedAttestation

                assert attestation_object.fmt == "packed"
                assert len(attestation_object.att_stmt["x5c"]) == 1
                PackedAttestation().verify(
                    attestation_object.att_stmt, attestation_object.auth_data, client_data_hash
                )

        return Verifier()


@pytest.mark.parametrize("attestation", [None, "direct"])
def test_register_then_sign_in(tmp_path, attestation):
    path = tmp_path / "softkey.json"
    server = Fido2Server(
        PublicKeyCredentialRpEntity(id="apple.com", name="Apple"),
        attestation=attestation,
        verify_attestation=_AnyRoot() if attestation else None,
    )
    auth_data = _register(path, server)
    credential = auth_data.credential_data

    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    stored = json.loads(path.read_text())["credentials"]
    assert [c["rp_id"] for c in stored] == ["apple.com"]

    # A fresh process (new device object) signs with what is on disk — the
    # same options icloudpd builds from Apple's fsaChallenge.
    options, state = server.authenticate_begin(
        [credential], user_verification=UserVerificationRequirement.DISCOURAGED
    )
    assertion = _client(path).get_assertion(options.public_key).get_response(0)
    server.authenticate_complete(state, [credential], assertion)


def test_unknown_credential_is_refused(tmp_path):
    from fido2.client import ClientError

    path = tmp_path / "softkey.json"
    options = PublicKeyCredentialRequestOptions(
        challenge=b"c" * 32,
        rp_id="apple.com",
        allow_credentials=[
            PublicKeyCredentialDescriptor(id=b"x" * 32, type=PublicKeyCredentialType.PUBLIC_KEY)
        ],
    )
    with pytest.raises(ClientError):
        _client(path).get_assertion(options)
    assert not path.exists()  # nothing is written until a credential is registered


def test_registering_twice_is_excluded(tmp_path):
    from fido2.client import ClientError

    path = tmp_path / "softkey.json"
    server = Fido2Server(PublicKeyCredentialRpEntity(id="apple.com", name="Apple"))
    credential = _register(path, server).credential_data
    options, _state = server.register_begin(
        PublicKeyCredentialUserEntity(id=b"user-1", name="someone@example.com"), [credential]
    )
    with pytest.raises(ClientError):
        _client(path).make_credential(options.public_key)


# ---- CTAPHID framing ------------------------------------------------------------------------


def _send(session, cid, command, payload):
    """Fragment a request like a host does; return (command, payload) of the reply."""
    frames = [struct.pack(">IBH", cid, command | 0x80, len(payload)) + payload[:57]]
    rest, seq = payload[57:], 0
    while rest:
        frames.append(struct.pack(">IB", cid, seq) + rest[:59])
        rest, seq = rest[59:], seq + 1
    replies = []
    for frame in frames:
        replies += list(session.feed(frame.ljust(64, b"\0")))
    assert replies and all(len(r) == 64 for r in replies)
    assert struct.unpack(">I", replies[0][:4])[0] == cid
    reply_command = replies[0][4] & 0x7F
    length = struct.unpack(">H", replies[0][5:7])[0]
    data = replies[0][7:]
    for index, reply in enumerate(replies[1:]):
        assert reply[4] == index
        data += reply[5:]
    return reply_command, data[:length]


def test_ctaphid_init_ping_and_multi_packet_cbor(tmp_path):
    from fido2 import cbor

    session = softkey.CtapHidSession(softkey.SoftAuthenticator(str(tmp_path / "k.json")))
    command, data = _send(session, 0xFFFFFFFF, 0x06, b"12345678")
    assert command == 0x06 and data[:8] == b"12345678"
    cid = struct.unpack(">I", data[8:12])[0]
    assert cid not in (0, 0xFFFFFFFF)
    assert data[16] & 0x04 and data[16] & 0x08  # CBOR, no U2F

    assert _send(session, cid, 0x01, b"p" * 300) == (0x01, b"p" * 300)

    command, data = _send(session, cid, 0x10, b"\x04")
    assert command == 0x10 and data[0] == 0
    assert cbor.decode(data[1:])[1] == ["FIDO_2_0"]

    request = {
        1: b"h" * 32,
        2: {"id": "apple.com", "name": "Apple"},
        3: {"id": b"u" * 40, "name": "someone@example.com", "displayName": "Some One"},
        4: [{"alg": -7, "type": "public-key"}],
    }
    command, data = _send(session, cid, 0x10, b"\x01" + cbor.encode(request))  # > 1 packet
    assert command == 0x10 and data[0] == 0
    assert cbor.decode(data[1:])[1] == "packed"

    # U2F is not offered
    assert _send(session, cid, 0x03, b"\x00\x03\x00\x00")[0] == 0x3F


# ---- the wrapper icloudpd is started through ---------------------------------------------------


def test_wrapper_makes_icloudpd_find_the_software_key(tmp_path, monkeypatch):
    """Same calls as pyicloud_ipd.base.confirm_security_key (icloudpd 1.33.0)."""
    import sys
    import types

    from fido2.hid import CtapHidDevice

    from icloudpd_supervisor import softkey_run

    path = tmp_path / "softkey.json"
    server = Fido2Server(PublicKeyCredentialRpEntity(id="apple.com", name="Apple"))
    credential = _register(path, server).credential_data
    options, state = server.authenticate_begin(
        [credential], user_verification=UserVerificationRequirement.DISCOURAGED
    )

    seen = {}

    def fake_cli():
        seen["argv"] = list(sys.argv)
        devices = list(CtapHidDevice.list_devices())
        assert len(devices) == 1
        client = Fido2Client(devices[0], client_data_collector=DefaultClientDataCollector(ORIGIN))
        seen["assertion"] = client.get_assertion(options.public_key).get_response(0)
        return 0

    monkeypatch.setattr(CtapHidDevice, "list_devices", CtapHidDevice.list_devices)  # restored after
    monkeypatch.setattr(sys, "argv", list(sys.argv))
    monkeypatch.setitem(sys.modules, "icloudpd", types.ModuleType("icloudpd"))
    monkeypatch.setitem(sys.modules, "icloudpd.cli", types.SimpleNamespace(cli=fake_cli))

    assert softkey_run.main([str(path), "--auth-only", "--mfa-provider", "console"]) == 0
    assert seen["argv"] == ["icloudpd", "--auth-only", "--mfa-provider", "console"]
    server.authenticate_complete(state, [credential], seen["assertion"])
