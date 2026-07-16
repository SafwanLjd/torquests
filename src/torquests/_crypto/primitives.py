"""Thin wrappers over ``cryptography`` and the standard library.

These are the cryptographic building blocks the Tor protocol composes: the
curve25519/ed25519 operations, the hash and MAC functions, HKDF, and AES-CTR.
Nothing here knows anything about Tor; the protocol-specific derivations live in
the layers above. Keeping the primitives in one small, typed module makes the
crypto surface easy to audit.
"""

from __future__ import annotations

import hashlib
import hmac as _hmac

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers import Cipher, CipherContext, algorithms, modes

ZERO_IV16 = b"\x00" * 16

# --------------------------------------------------------------------------- #
# Hashes
# --------------------------------------------------------------------------- #


def sha3_256(data: bytes) -> bytes:
    """SHA3-256 digest (used throughout the v3 onion protocol)."""
    return hashlib.sha3_256(data).digest()


def shake256(data: bytes, length: int) -> bytes:
    """SHAKE256 extendable-output function, producing exactly ``length`` bytes."""
    return hashlib.shake_256(data).digest(length)


# --------------------------------------------------------------------------- #
# MAC and constant-time comparison
# --------------------------------------------------------------------------- #


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    """HMAC-SHA256 of ``message`` under ``key``."""
    return _hmac.new(key, message, hashlib.sha256).digest()


def const_time_eq(a: bytes, b: bytes) -> bool:
    """Constant-time equality, for comparing MACs and authenticators."""
    return _hmac.compare_digest(a, b)


# --------------------------------------------------------------------------- #
# HKDF (RFC 5869), used by the ntor handshake
# --------------------------------------------------------------------------- #


def hkdf_sha256_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand: stretch a pseudorandom key to ``length`` bytes.

    ntor supplies its key seed directly as the PRK (tor-spec skips the extract
    step), so only the expand half is needed.
    """
    if length < 0:
        raise ValueError("length must be non-negative")
    if length > 255 * 32:
        raise ValueError("HKDF-SHA256 cannot expand beyond 255 * 32 bytes")
    okm = bytearray()
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac_sha256(prk, block + info + bytes([counter]))
        okm += block
        counter += 1
    return bytes(okm[:length])


# --------------------------------------------------------------------------- #
# X25519 (curve25519 ECDH), used by ntor and hs-ntor
# --------------------------------------------------------------------------- #


def x25519_keypair() -> tuple[bytes, bytes]:
    """Generate a curve25519 keypair, returned as ``(private, public)`` raw bytes."""
    private = X25519PrivateKey.generate()
    return (
        private.private_bytes_raw(),
        private.public_key().public_bytes_raw(),
    )


def x25519_public_from_private(private: bytes) -> bytes:
    """Return the 32-byte public key for a raw curve25519 private key."""
    return X25519PrivateKey.from_private_bytes(private).public_key().public_bytes_raw()


def x25519(private: bytes, public: bytes) -> bytes:
    """Curve25519 Diffie-Hellman: EXP(public, private).

    ``cryptography`` rejects a shared secret of all zeros (a low-order public
    point), which is exactly the point-at-infinity check the ntor handshake
    requires; that rejection surfaces here as :class:`ValueError`.
    """
    priv = X25519PrivateKey.from_private_bytes(private)
    pub = X25519PublicKey.from_public_bytes(public)
    return priv.exchange(pub)


# --------------------------------------------------------------------------- #
# Ed25519 signatures, used to verify certificate chains and descriptors
# --------------------------------------------------------------------------- #


def ed25519_verify(public: bytes, signature: bytes, message: bytes) -> bool:
    """Verify an Ed25519 signature. Returns ``False`` rather than raising."""
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(signature, message)
    except (InvalidSignature, ValueError):
        return False
    return True


# --------------------------------------------------------------------------- #
# AES-CTR, used for relay-cell layering and descriptor encryption
# --------------------------------------------------------------------------- #


def ctr_cipher(key: bytes, iv: bytes = ZERO_IV16) -> CipherContext:
    """Return a stateful AES-CTR context (AES-128 or AES-256 by key length).

    CTR is symmetric, so a single context both encrypts and decrypts. The relay
    layer keeps one context per direction alive for the whole circuit, because
    the keystream is continuous rather than reset per cell.
    """
    if len(key) not in (16, 32):
        raise ValueError("AES key must be 16 or 32 bytes")
    return Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()


def aes_ctr(key: bytes, iv: bytes, data: bytes) -> bytes:
    """One-shot AES-CTR of ``data`` (encrypt or decrypt; they are identical)."""
    cipher = ctr_cipher(key, iv)
    return cipher.update(data) + cipher.finalize()
