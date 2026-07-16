"""Link specifiers: how a relay is addressed inside EXTEND2 and descriptors.

A link specifier is ``LSTYPE(1) | LSLEN(1) | LSPEC(LSLEN)``. A block of them is a
one-byte count followed by that many specifiers. Clients send an IPv4 address, a
legacy RSA identity digest, and an ed25519 identity for each hop they extend to.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass

from .constants import LinkSpecType


@dataclass(frozen=True)
class LinkSpecifier:
    """A single link specifier: a type and its raw specifier bytes."""

    type: int
    data: bytes

    def pack(self) -> bytes:
        if len(self.data) > 255:
            raise ValueError("link specifier data too long")
        return bytes([self.type, len(self.data)]) + self.data

    # --- constructors ------------------------------------------------------ #

    @classmethod
    def ipv4(cls, host: str, port: int) -> LinkSpecifier:
        packed = ipaddress.IPv4Address(host).packed + struct.pack(">H", port)
        return cls(LinkSpecType.IPV4, packed)

    @classmethod
    def ipv6(cls, host: str, port: int) -> LinkSpecifier:
        packed = ipaddress.IPv6Address(host).packed + struct.pack(">H", port)
        return cls(LinkSpecType.IPV6, packed)

    @classmethod
    def legacy_id(cls, rsa_id_digest: bytes) -> LinkSpecifier:
        if len(rsa_id_digest) != 20:
            raise ValueError("legacy identity digest must be 20 bytes")
        return cls(LinkSpecType.LEGACY_ID, rsa_id_digest)

    @classmethod
    def ed25519_id(cls, ed25519_id: bytes) -> LinkSpecifier:
        if len(ed25519_id) != 32:
            raise ValueError("ed25519 identity must be 32 bytes")
        return cls(LinkSpecType.ED25519_ID, ed25519_id)

    # --- accessors --------------------------------------------------------- #

    @property
    def endpoint(self) -> tuple[str, int]:
        """Return ``(host, port)`` for an IPv4/IPv6 specifier.

        Raises :class:`ValueError` on a specifier whose length does not match its
        type, so a malformed (but MAC-valid) descriptor fails loud here instead of
        letting a bare ``struct.error`` escape the caller's typed handling.
        """
        if self.type == LinkSpecType.IPV4:
            if len(self.data) != 6:
                raise ValueError(f"IPv4 link specifier must be 6 bytes, got {len(self.data)}")
            (port,) = struct.unpack(">H", self.data[4:6])
            return (str(ipaddress.IPv4Address(self.data[:4])), port)
        if self.type == LinkSpecType.IPV6:
            if len(self.data) != 18:
                raise ValueError(f"IPv6 link specifier must be 18 bytes, got {len(self.data)}")
            (port,) = struct.unpack(">H", self.data[16:18])
            return (str(ipaddress.IPv6Address(self.data[:16])), port)
        raise ValueError(f"link specifier type {self.type} has no endpoint")


def pack_block(specs: list[LinkSpecifier]) -> bytes:
    """Encode a counted block of link specifiers (NSPEC + specifiers)."""
    if len(specs) > 255:
        raise ValueError("too many link specifiers")
    return bytes([len(specs)]) + b"".join(s.pack() for s in specs)


def parse_block(data: bytes) -> list[LinkSpecifier]:
    """Decode a counted block of link specifiers."""
    if not data:
        raise ValueError("empty link-specifier block")
    count = data[0]
    offset = 1
    specs: list[LinkSpecifier] = []
    for _ in range(count):
        if offset + 2 > len(data):
            raise ValueError("truncated link specifier header")
        lstype, lslen = data[offset], data[offset + 1]
        offset += 2
        if offset + lslen > len(data):
            raise ValueError("truncated link specifier body")
        specs.append(LinkSpecifier(lstype, data[offset : offset + lslen]))
        offset += lslen
    return specs
