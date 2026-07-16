"""Ed25519 key blinding for v3 onion services.

This is the one operation ``cryptography`` cannot express: multiplying an
ed25519 point by a scalar. A v3 onion client derives a *blinded* public key
``A' = h * A`` from the service's identity key ``A`` and a per-time-period
blinding factor ``h``, and it derives the *subcredential* that keys descriptor
decryption from ``A`` and ``A'``. The scalar-by-point multiplication is done with
libsodium via PyNaCl.

All blinding math is isolated in this module so it can be hammered against test
vectors before anything depends on it. A client never needs to blind a *private*
key (that is the service's job), so only the public-key path lives here.

References: Tor rendezvous specification v3, "Deriving blinded keys and
subcredentials" and "The key blinding scheme".
"""

from __future__ import annotations

import struct

from nacl import bindings as _nacl

from .primitives import sha3_256

#: The order of the ed25519 prime-order subgroup, l.
ED25519_L = 2**252 + 27742317777372353535851937790883648493

#: Default time-period length, in minutes (consensus parameter ``hsdir_interval``).
DEFAULT_PERIOD_LENGTH_MINUTES = 1440

#: Default rotation offset, in minutes (12 voting periods at one hour each).
DEFAULT_ROTATION_OFFSET_MINUTES = 720

# Personalization strings for the blinding-factor hash, exactly as the spec
# defines them. BLIND_STRING carries an explicit trailing NUL byte.
_BLIND_STRING = b"Derive temporary signing key" + bytes([0])

# The ed25519 base point enters the hash as its ASCII decimal "(x, y)" string,
# not as the 32-byte point encoding.
_BASEPOINT_STRING = (
    b"(15112221349535400772501151409588531511454012693041857206046113283949847762202,"
    b" 46316835694926478169428394003475163141307993866256225615783033603165251855960)"
)


def time_period(
    valid_after_unix: int,
    period_length_minutes: int = DEFAULT_PERIOD_LENGTH_MINUTES,
    rotation_offset_minutes: int = DEFAULT_ROTATION_OFFSET_MINUTES,
) -> int:
    """Return the current time-period number for a consensus ``valid-after`` time.

    Always uses the consensus valid-after, never the wall clock. With the default
    parameters, the spec's worked example (``1460546101`` seconds) yields period
    ``16903``.
    """
    minutes = valid_after_unix // 60
    return (minutes - rotation_offset_minutes) // period_length_minutes


def blinding_factor(
    identity_public_key: bytes,
    period_number: int,
    period_length_minutes: int = DEFAULT_PERIOD_LENGTH_MINUTES,
) -> bytes:
    """Compute the clamped 32-byte blinding factor ``h`` for a time period."""
    if len(identity_public_key) != 32:
        raise ValueError("identity public key must be 32 bytes")
    nonce = (
        b"key-blind" + struct.pack(">Q", period_number) + struct.pack(">Q", period_length_minutes)
    )
    h = bytearray(sha3_256(_BLIND_STRING + identity_public_key + _BASEPOINT_STRING + nonce))
    # Clamp exactly like an ed25519 secret scalar.
    h[0] &= 248
    h[31] &= 63
    h[31] |= 64
    return bytes(h)


def blind_public_key(
    identity_public_key: bytes,
    period_number: int,
    period_length_minutes: int = DEFAULT_PERIOD_LENGTH_MINUTES,
) -> bytes:
    """Derive the blinded public key ``A' = h * A`` for a time period.

    ``h`` is already clamped, so the multiplication uses the ``noclamp`` variant
    (clamping again would change the result). Raises :class:`ValueError` if the
    identity key is not a usable point.
    """
    h = blinding_factor(identity_public_key, period_number, period_length_minutes)
    return _nacl.crypto_scalarmult_ed25519_noclamp(h, identity_public_key)


def credential(identity_public_key: bytes) -> bytes:
    """N_hs_cred = SHA3-256("credential" | KP_hs_id)."""
    return sha3_256(b"credential" + identity_public_key)


def subcredential(identity_public_key: bytes, blinded_public_key: bytes) -> bytes:
    """N_hs_subcred = SHA3-256("subcredential" | N_hs_cred | blinded-public-key)."""
    return sha3_256(b"subcredential" + credential(identity_public_key) + blinded_public_key)


def is_torsion_free(public_key: bytes) -> bool:
    """Return whether ``public_key`` is a valid point of the prime-order subgroup.

    This is the mandatory address-validation check (equivalent to ``l * A``
    equalling the identity element): it rejects non-canonical encodings and
    small-order points.
    """
    if len(public_key) != 32:
        return False
    return bool(_nacl.crypto_core_ed25519_is_valid_point(public_key))
