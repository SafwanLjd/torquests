"""Tests for the test-only ed25519 signing helpers."""

from __future__ import annotations

from torquests._crypto.primitives import ed25519_verify

from .crypto_helpers import ed25519_public_from_seed, ed25519_sign


def test_sign_produces_a_verifiable_signature() -> None:
    seed = bytes(range(32))
    pub = ed25519_public_from_seed(seed)
    sig = ed25519_sign(seed, b"authenticate me")
    assert ed25519_verify(pub, sig, b"authenticate me")
