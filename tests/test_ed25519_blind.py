"""Tests for ed25519 key blinding, the highest-risk cryptographic unit.

The scheme has no official test vectors in torspec, so this pins it three ways:
a regression vector generated from a known seed and cross-validated against
libsodium's independent scalar arithmetic; the internal-consistency identity
``A' = h * A == (h * a) * B``; and real-world onion identity keys for the torsion
check. The blinding factor and subcredential are also checked structurally
against the spec formulas.
"""

from __future__ import annotations

import hashlib

import pytest
from nacl import bindings as nacl

from torquests._crypto import ed25519_blind as kb
from torquests._crypto.primitives import sha3_256

from .crypto_helpers import ed25519_public_from_seed

# Regression vector: seed = 00 01 02 ... 1f, default time period 16903 / 1440 min.
SEED = bytes(range(32))
PERIOD = 16903
A_HEX = "03A107BFF3CE10BE1D70DD18E74BC09967E4D6309BA50D5F1DDC8664125531B8"
H_HEX = "9066FE866EC8968383C8E5CE3DC38CE38A962FC0A4086BD79070D1F0C866AB73"
A_PRIME_HEX = "21F1137C952723C3F17D52604521CCC4AAC717EBB6733F872D141C7231055A4B"
CRED_HEX = "BBF4E32BC68DEA78B096DA509271674C9C95B3D67BBAB0A45672233E3E8ADDE0"
SUBCRED_HEX = "008044820C2D9BB24F97C2700BF10E108052CC2AB783EE8D5EDC822A8C7EC42A"


def _ddg_identity() -> bytes:
    # A real v3 onion identity key (DuckDuckGo), for the torsion check.
    import base64

    label = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad"
    return base64.b32decode(label.upper())[:32]


def test_time_period_spec_worked_example() -> None:
    # rend-spec deriving-keys worked example.
    assert kb.time_period(1460546101) == 16903


def test_blinding_regression_vector() -> None:
    a = ed25519_public_from_seed(SEED)
    assert a.hex().upper() == A_HEX
    assert kb.blinding_factor(a, PERIOD).hex().upper() == H_HEX
    a_prime = kb.blind_public_key(a, PERIOD)
    assert a_prime.hex().upper() == A_PRIME_HEX
    assert kb.credential(a).hex().upper() == CRED_HEX
    assert kb.subcredential(a, a_prime).hex().upper() == SUBCRED_HEX


@pytest.mark.parametrize("seed", [bytes(range(32)), bytes(32), bytes([255]) * 32])
def test_blinding_identity_public_equals_private(seed: bytes) -> None:
    # A' derived by blinding the public key must equal (h * a) * B, where a is the
    # secret scalar. This proves the public-only blinding path is correct.
    a_pub = ed25519_public_from_seed(seed)
    h = kb.blinding_factor(a_pub, PERIOD)
    a_prime_pub = kb.blind_public_key(a_pub, PERIOD)

    a_scalar = bytearray(hashlib.sha512(seed).digest()[:32])
    a_scalar[0] &= 248
    a_scalar[31] &= 63
    a_scalar[31] |= 64
    h_int = int.from_bytes(h, "little")
    a_int = int.from_bytes(a_scalar, "little")
    blinded_scalar = (h_int * a_int) % kb.ED25519_L
    a_prime_from_priv = nacl.crypto_scalarmult_ed25519_base_noclamp(
        blinded_scalar.to_bytes(32, "little")
    )
    assert a_prime_pub == a_prime_from_priv


def test_blinding_factor_is_clamped() -> None:
    h = kb.blinding_factor(ed25519_public_from_seed(SEED), PERIOD)
    assert h[0] & 0b0000_0111 == 0  # low 3 bits clear
    assert h[31] & 0b1000_0000 == 0  # top bit clear
    assert h[31] & 0b0100_0000 != 0  # second-top bit set


def test_subcredential_matches_spec_formula() -> None:
    a = ed25519_public_from_seed(SEED)
    a_prime = kb.blind_public_key(a, PERIOD)
    cred = sha3_256(b"credential" + a)
    assert kb.credential(a) == cred
    assert kb.subcredential(a, a_prime) == sha3_256(b"subcredential" + cred + a_prime)


def test_torsion_check() -> None:
    a = ed25519_public_from_seed(SEED)
    assert kb.is_torsion_free(a)
    assert kb.is_torsion_free(kb.blind_public_key(a, PERIOD))
    assert kb.is_torsion_free(_ddg_identity())
    # An all-zero encoding is not a valid subgroup point.
    assert not kb.is_torsion_free(bytes(32))
    # Wrong length is rejected, not crashed.
    assert not kb.is_torsion_free(b"\x00" * 31)


def test_blinding_rejects_bad_key_length() -> None:
    with pytest.raises(ValueError):
        kb.blinding_factor(b"\x00" * 31, PERIOD)
