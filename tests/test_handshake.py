"""Tests for the ntor and hs-ntor handshakes.

ntor has no single published vector, so both sides are derived and checked to
agree. hs-ntor is pinned to the official Appendix-G vector: the INTRODUCE1 body
and the rendezvous key seed are reproduced exactly.
"""

from __future__ import annotations

import pytest

from torquests._crypto.primitives import (
    hkdf_sha256_expand,
    hmac_sha256,
    x25519,
    x25519_keypair,
)
from torquests._proto.constants import NTOR_PROTOID
from torquests._proto.handshake import HsNtorHandshake, NtorHandshake
from torquests.exceptions import CircuitError, RendezvousError


def _ntor_server_reply(onion_private: bytes, onion_public: bytes, node_id: bytes, skin: bytes):
    """The relay half of ntor: consume an onion skin, return (reply, key_material)."""
    client_pub = skin[52:84]
    y_priv, y_pub = x25519_keypair()
    secret_input = (
        x25519(y_priv, client_pub)
        + x25519(onion_private, client_pub)
        + node_id
        + onion_public
        + client_pub
        + y_pub
        + NTOR_PROTOID
    )
    key_seed = hmac_sha256(NTOR_PROTOID + b":key_extract", secret_input)
    verify = hmac_sha256(NTOR_PROTOID + b":verify", secret_input)
    auth_input = verify + node_id + onion_public + y_pub + client_pub + NTOR_PROTOID + b"Server"
    auth = hmac_sha256(NTOR_PROTOID + b":mac", auth_input)
    key_material = hkdf_sha256_expand(key_seed, NTOR_PROTOID + b":key_expand", 72)
    return y_pub + auth, key_material


def test_ntor_client_and_relay_agree() -> None:
    onion_priv, onion_pub = x25519_keypair()
    node_id = bytes(range(20))
    client = NtorHandshake(onion_pub, node_id)
    skin = client.create_onion_skin()
    assert len(skin) == 84
    assert skin[:20] == node_id
    assert skin[20:52] == onion_pub

    reply, server_km = _ntor_server_reply(onion_priv, onion_pub, node_id, skin)
    client_km = client.complete(reply)
    assert client_km == server_km
    assert len(client_km) == 72


def test_ntor_rejects_bad_auth() -> None:
    onion_priv, onion_pub = x25519_keypair()
    node_id = bytes(20)
    client = NtorHandshake(onion_pub, node_id)
    reply, _ = _ntor_server_reply(onion_priv, onion_pub, node_id, client.create_onion_skin())
    tampered = reply[:32] + bytes(32)  # zero AUTH
    with pytest.raises(CircuitError):
        client.complete(tampered)


def test_ntor_low_order_server_pubkey_raises_circuit_error() -> None:
    # A malicious relay can reply with a low-order Y (here the all-zero point),
    # whose x25519 shared secret is all zeros. That must surface as a CircuitError
    # (retryable/handled), not a bare ValueError that escapes the build retry.
    _onion_priv, onion_pub = x25519_keypair()
    node_id = bytes(20)
    client = NtorHandshake(onion_pub, node_id)
    client.create_onion_skin()
    reply = bytes(32) + bytes(32)  # low-order server pubkey, then AUTH
    with pytest.raises(CircuitError):
        client.complete(reply)


def test_ntor_rejects_bad_input_lengths() -> None:
    with pytest.raises(ValueError):
        NtorHandshake(b"short", bytes(20))
    with pytest.raises(ValueError):
        NtorHandshake(bytes(32), b"short")
    with pytest.raises(CircuitError):
        NtorHandshake(bytes(32), bytes(20)).complete(b"too short")


# --- hs-ntor against the official vector ----------------------------------- #


def test_hs_ntor_introduce_matches_vector(hs_ntor_vector: dict[str, bytes]) -> None:
    v = hs_ntor_vector
    hs = HsNtorHandshake(
        v["KP_hs_ipt_sid"], v["KP_hss_ntor"], v["N_hs_subcred"], ephemeral_private=v["x"]
    )
    assert hs.public_key == v["X"]
    body_tail = hs.encrypt_introduce(v["H"], v["P"])
    expected_tail = v["INTRODUCE1_body"][len(v["H"]) :]  # X | ENCRYPTED_DATA | MAC
    assert body_tail == expected_tail


def test_hs_ntor_rendezvous_matches_vector(hs_ntor_vector: dict[str, bytes]) -> None:
    v = hs_ntor_vector
    hs = HsNtorHandshake(
        v["KP_hs_ipt_sid"], v["KP_hss_ntor"], v["N_hs_subcred"], ephemeral_private=v["x"]
    )
    keys = hs.complete_rendezvous(v["Y"], v["AUTH_INPUT_MAC"])
    assert keys.ntor_key_seed == v["NTOR_KEY_SEED"]
    assert len(keys.key_material) == 128


def test_hs_ntor_rejects_bad_rendezvous_auth(hs_ntor_vector: dict[str, bytes]) -> None:
    v = hs_ntor_vector
    hs = HsNtorHandshake(
        v["KP_hs_ipt_sid"], v["KP_hss_ntor"], v["N_hs_subcred"], ephemeral_private=v["x"]
    )
    with pytest.raises(RendezvousError):
        hs.complete_rendezvous(v["Y"], bytes(32))


def test_hs_ntor_rejects_bad_key_lengths() -> None:
    with pytest.raises(ValueError):
        HsNtorHandshake(bytes(31), bytes(32), bytes(32))
