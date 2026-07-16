"""Parsing, validation, and encoding of v3 ``.onion`` addresses.

A v3 address encodes a 32-byte ed25519 identity key plus a checksum and a version
byte in base32::

    onion_address = base32(PUBKEY | CHECKSUM | VERSION) + ".onion"
    CHECKSUM      = SHA3-256(".onion checksum" | PUBKEY | VERSION)[:2]
    VERSION       = 0x03

The label is always 56 lowercase base32 characters. Validating an address means
checking the length, the version, the checksum, and (the security-relevant one)
that the identity key is a torsion-free point of the prime-order subgroup.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass

from .._crypto.ed25519_blind import is_torsion_free
from .._crypto.primitives import sha3_256
from ..exceptions import InvalidOnionAddress

ONION_SUFFIX = ".onion"
ONION_VERSION = 3
LABEL_LENGTH = 56
_CHECKSUM_PREFIX = b".onion checksum"


def _checksum(identity_key: bytes, version: int) -> bytes:
    return sha3_256(_CHECKSUM_PREFIX + identity_key + bytes([version]))[:2]


@dataclass(frozen=True)
class OnionAddress:
    """A validated v3 onion address."""

    identity_key: bytes  #: the 32-byte ed25519 public identity key (KP_hs_id)

    @property
    def label(self) -> str:
        """The 56-character base32 label, without the ``.onion`` suffix."""
        payload = (
            self.identity_key + _checksum(self.identity_key, ONION_VERSION) + bytes([ONION_VERSION])
        )
        return base64.b32encode(payload).decode("ascii").lower()

    @property
    def hostname(self) -> str:
        """The full ``<label>.onion`` hostname."""
        return self.label + ONION_SUFFIX

    def __str__(self) -> str:
        return self.hostname


def parse(address: str) -> OnionAddress:
    """Parse and fully validate a v3 ``.onion`` address.

    Accepts the address with or without the ``.onion`` suffix and is
    case-insensitive. In v3 the onion address is the label immediately before
    ``.onion``; any leading labels are subdomains (a vhost, or a redirect target
    such as ``www.<addr>.onion``) and are ignored for address resolution, so a
    subdomained hostname resolves to its underlying service. The last label is
    still validated in full. Raises :class:`InvalidOnionAddress` on any failure.
    """
    hostname = address.strip().lower()
    if hostname.endswith(ONION_SUFFIX):
        hostname = hostname[: -len(ONION_SUFFIX)]
    label = hostname.rpartition(".")[2]

    if len(label) != LABEL_LENGTH:
        raise InvalidOnionAddress(
            f"onion label must be {LABEL_LENGTH} characters, got {len(label)}"
        )

    try:
        payload = base64.b32decode(label.upper())
    except (binascii.Error, ValueError) as exc:
        raise InvalidOnionAddress(f"onion label is not valid base32: {exc}") from exc

    # A 56-character base32 label always decodes to exactly 35 bytes.
    identity_key, checksum, version = payload[:32], payload[32:34], payload[34]

    if version != ONION_VERSION:
        raise InvalidOnionAddress(f"unsupported onion version {version}; expected {ONION_VERSION}")
    if _checksum(identity_key, version) != checksum:
        raise InvalidOnionAddress("onion address checksum mismatch")
    if not is_torsion_free(identity_key):
        raise InvalidOnionAddress("onion identity key is not a valid prime-order point")

    return OnionAddress(identity_key)


def encode(identity_key: bytes) -> str:
    """Encode a 32-byte ed25519 identity key as a full ``.onion`` hostname."""
    if len(identity_key) != 32:
        raise ValueError("identity key must be 32 bytes")
    return OnionAddress(identity_key).hostname


def is_onion_host(host: str) -> bool:
    """Return whether ``host`` is a ``.onion`` hostname (no validation)."""
    return host.lower().rstrip(".").endswith(ONION_SUFFIX)
