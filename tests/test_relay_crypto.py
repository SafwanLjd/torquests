"""Tests for the per-hop relay crypto.

A ``RelayCrypto`` built with the same key material on two sides models a client
and a relay: cells stamped and encrypted on one side decrypt and are recognized
on the other, and tampering is rejected without advancing the digest.
"""

from __future__ import annotations

import pytest

from torquests._proto.constants import CELL_PAYLOAD_LEN, RELAY_PAYLOAD_LEN, Relay
from torquests._proto.relay import RelayCell
from torquests._proto.relay_crypto import RelayCrypto
from torquests.exceptions import CircuitError


def test_forward_roundtrip_client_to_relay() -> None:
    km = bytes(range(72))
    client, relay = RelayCrypto.tor1(km), RelayCrypto.tor1(km)

    stamped = client.stamp_forward(RelayCell(Relay.DATA, 5, b"hello"))
    on_wire = client.apply_forward_cipher(stamped.pack())
    decrypted = relay.apply_forward_cipher(on_wire)
    recognized = relay.recognize_forward(decrypted)

    assert recognized is not None
    assert recognized.command == Relay.DATA
    assert recognized.stream_id == 5
    assert recognized.data == b"hello"


def test_backward_roundtrip_relay_to_client() -> None:
    km = bytes(range(72))
    client, relay = RelayCrypto.tor1(km), RelayCrypto.tor1(km)

    stamped = relay.stamp_backward(RelayCell(Relay.CONNECTED, 5, b"ok"))
    on_wire = relay.apply_backward_cipher(stamped.pack())
    decrypted = client.apply_backward_cipher(on_wire)
    recognized = client.recognize_backward(decrypted)

    assert recognized is not None
    assert recognized.data == b"ok"


def test_continuous_keystream_across_cells() -> None:
    km = bytes(range(72))
    client, relay = RelayCrypto.tor1(km), RelayCrypto.tor1(km)
    for i in range(3):
        payload = f"cell-{i}".encode()
        stamped = client.stamp_forward(RelayCell(Relay.DATA, 1, payload))
        decrypted = relay.apply_forward_cipher(client.apply_forward_cipher(stamped.pack()))
        got = relay.recognize_forward(decrypted)
        assert got is not None and got.data == payload


def test_nonzero_recognized_field_is_not_recognized() -> None:
    client = RelayCrypto.tor1(bytes(range(72)))
    body = RelayCell(Relay.DATA, 1, b"x", recognized=7).pack()
    assert client.recognize_forward(body) is None


def test_tampered_digest_rejected_and_state_not_committed() -> None:
    km = bytes(range(72))
    client, relay = RelayCrypto.tor1(km), RelayCrypto.tor1(km)
    valid = client.stamp_forward(RelayCell(Relay.DATA, 1, b"data")).pack()

    tampered = bytearray(valid)
    tampered[15] ^= 0xFF  # flip a data byte; the stamped digest no longer matches
    assert relay.recognize_forward(bytes(tampered)) is None
    # The failed attempt must not have advanced the digest: the valid cell for
    # this same position is still recognized.
    assert relay.recognize_forward(valid) is not None


def test_random_padding_differs_but_each_cell_still_verifies() -> None:
    # Two cells with identical fields get independent random padding, yet each
    # stamps and verifies end to end: the running digest is taken over the same
    # padded bytes that go on the wire, so random padding does not break the
    # recognize path (which hashes the raw received body, padding included).
    km = bytes(range(72))
    client, relay = RelayCrypto.tor1(km), RelayCrypto.tor1(km)
    first = RelayCell(Relay.DATA, 1, b"same")
    second = RelayCell(Relay.DATA, 1, b"same")
    assert first == second  # padding is excluded from equality
    assert first.pack()[15:] != second.pack()[15:]  # but the random tails differ
    for cell in (first, second):
        stamped = client.stamp_forward(cell)
        decrypted = relay.apply_forward_cipher(client.apply_forward_cipher(stamped.pack()))
        got = relay.recognize_forward(decrypted)
        assert got is not None and got.data == b"same"


def test_hs_v3_profile_roundtrip() -> None:
    km = bytes(range(128))
    client, relay = RelayCrypto.hs_v3(km), RelayCrypto.hs_v3(km)
    stamped = client.stamp_forward(RelayCell(Relay.DATA, 2, b"onion"))
    decrypted = relay.apply_forward_cipher(client.apply_forward_cipher(stamped.pack()))
    got = relay.recognize_forward(decrypted)
    assert got is not None and got.data == b"onion"


def test_insufficient_key_material_raises() -> None:
    with pytest.raises(ValueError):
        RelayCrypto.tor1(bytes(50))


def test_recognized_cell_with_oversize_length_raises_circuit_error() -> None:
    import hashlib
    import struct

    # The real crash shape: a peer sends a cell this hop *recognizes* (zero
    # recognized field plus a digest it computes over the body) but whose declared
    # length overflows the payload. The honest packer caps length at 498, so the
    # adversarial body is built by hand. Once recognized, parse must surface a
    # typed CircuitError -- not a bare ValueError that would escape untyped when
    # the receiver thread tears the circuit down.
    km = bytes(range(72))
    relay_side = RelayCrypto.tor1(km)

    body = bytearray(CELL_PAYLOAD_LEN)
    body[0] = Relay.DATA
    struct.pack_into(">H", body, 3, 1)  # stream_id
    struct.pack_into(">H", body, 9, RELAY_PAYLOAD_LEN + 1)  # oversize length field
    zeroed = bytes(body[:5]) + b"\x00\x00\x00\x00" + bytes(body[9:])
    # tor1 seeds the forward running digest with Df = the first 20 bytes of the
    # key material (SHA-1); the recognized digest is the first 4 bytes over the
    # body with the digest field zeroed.
    body[5:9] = hashlib.sha1(km[:20] + zeroed).digest()[:4]

    with pytest.raises(CircuitError):
        relay_side.recognize_forward(bytes(body))
