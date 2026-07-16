"""Ed25519 signing helpers used only by the test doubles.

The client never signs. It only verifies certificate chains and descriptors.
The fake relays and onion services in the test tree play the server role, so the
signing side lives here rather than widening the audited crypto surface.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def ed25519_sign(private_seed: bytes, message: bytes) -> bytes:
    """Sign ``message`` with an Ed25519 seed."""
    return Ed25519PrivateKey.from_private_bytes(private_seed).sign(message)


def ed25519_public_from_seed(private_seed: bytes) -> bytes:
    """Return the 32-byte Ed25519 public key for a seed."""
    return Ed25519PrivateKey.from_private_bytes(private_seed).public_key().public_bytes_raw()
