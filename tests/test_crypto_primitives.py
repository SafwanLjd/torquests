"""Tests for the cryptographic primitive wrappers.

Anchored on published known-answer tests (RFC 5869 HKDF, RFC 7748 X25519, NIST
SP 800-38A AES-CTR) and the Tor hs-ntor gold vector for AES-256-CTR, with
standard-library cross-checks for the hash and MAC wrappers.
"""

from __future__ import annotations

import hashlib
import hmac

import pytest

from torquests._crypto import primitives as p

from .crypto_helpers import ed25519_public_from_seed, ed25519_sign


def test_hashes_match_stdlib() -> None:
    data = b"the quick brown fox"
    assert p.sha3_256(data) == hashlib.sha3_256(data).digest()


def test_shake256_length_and_value() -> None:
    data = b"onion"
    assert p.shake256(data, 32) == hashlib.shake_256(data).digest(32)
    assert len(p.shake256(data, 64)) == 64
    # The first 32 bytes of a longer output are a prefix of the shorter one.
    assert p.shake256(data, 64)[:32] == p.shake256(data, 32)


def test_hmac_and_const_time_eq() -> None:
    key, msg = b"key", b"message"
    assert p.hmac_sha256(key, msg) == hmac.new(key, msg, hashlib.sha256).digest()
    assert p.const_time_eq(b"abc", b"abc")
    assert not p.const_time_eq(b"abc", b"abd")


# --- HKDF: RFC 5869 Test Case 1 (SHA-256) ---------------------------------- #


def test_hkdf_rfc5869_test_case_1() -> None:
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    prk = bytes.fromhex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
    okm = bytes.fromhex(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    )
    # ntor supplies the key seed directly as the PRK, so only expand is exposed.
    assert p.hkdf_sha256_expand(prk, info, 42) == okm


def test_hkdf_expand_length_bounds() -> None:
    prk = b"\x00" * 32
    assert p.hkdf_sha256_expand(prk, b"", 0) == b""
    with pytest.raises(ValueError):
        p.hkdf_sha256_expand(prk, b"", -1)
    with pytest.raises(ValueError):
        p.hkdf_sha256_expand(prk, b"", 255 * 32 + 1)


# --- X25519: RFC 7748 Section 5.2 ------------------------------------------ #


def test_x25519_rfc7748_vector() -> None:
    scalar = bytes.fromhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
    u = bytes.fromhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
    expected = bytes.fromhex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
    assert p.x25519(scalar, u) == expected


def test_x25519_keypair_roundtrip() -> None:
    priv, pub = p.x25519_keypair()
    assert len(priv) == 32 and len(pub) == 32
    assert p.x25519_public_from_private(priv) == pub
    # Diffie-Hellman agreement between two parties.
    priv2, pub2 = p.x25519_keypair()
    assert p.x25519(priv, pub2) == p.x25519(priv2, pub)


def test_x25519_low_order_public_raises() -> None:
    # An all-zero public key yields the point at infinity; cryptography rejects it,
    # which is the ntor point-at-infinity check.
    priv, _ = p.x25519_keypair()
    with pytest.raises(ValueError):
        p.x25519(priv, b"\x00" * 32)


# --- Ed25519 --------------------------------------------------------------- #


def test_ed25519_verify_accepts_and_rejects() -> None:
    seed = bytes(range(32))
    pub = ed25519_public_from_seed(seed)
    msg = b"authenticate me"
    sig = ed25519_sign(seed, msg)
    assert p.ed25519_verify(pub, sig, msg)
    # A tampered message or signature fails without raising.
    assert not p.ed25519_verify(pub, sig, msg + b"!")
    assert not p.ed25519_verify(pub, bytes(64), msg)


# --- AES-CTR --------------------------------------------------------------- #


def test_aes128_ctr_nist_vector() -> None:
    # NIST SP 800-38A F.5.1 CTR-AES128.Encrypt, first block.
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    iv = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    plaintext = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
    expected = bytes.fromhex("874d6191b620e3261bef6864990db6ce")
    assert p.aes_ctr(key, iv, plaintext) == expected


def test_aes256_ctr_matches_hs_ntor_vector(hs_ntor_vector: dict[str, bytes]) -> None:
    # The hs-ntor vector encrypts its plaintext P under ENC_KEY with a zero IV;
    # the ciphertext is the C slice of the INTRODUCE1 body (H | X | C | M).
    v = hs_ntor_vector
    c = p.aes_ctr(v["ENC_KEY"], p.ZERO_IV16, v["P"])
    body = v["INTRODUCE1_body"]
    c_from_body = body[len(v["H"]) + 32 : len(v["H"]) + 32 + len(v["P"])]
    assert c == c_from_body


def test_ctr_cipher_is_continuous() -> None:
    key = bytes(range(32))
    whole = p.aes_ctr(key, p.ZERO_IV16, b"A" * 40)
    cipher = p.ctr_cipher(key)
    piecewise = cipher.update(b"A" * 10) + cipher.update(b"A" * 30)
    assert piecewise == whole


def test_ctr_cipher_rejects_bad_key_length() -> None:
    with pytest.raises(ValueError):
        p.ctr_cipher(b"\x00" * 24)
