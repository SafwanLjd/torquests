"""A relay reference and an established circuit hop.

``RelayInfo`` is the minimum a client needs to reach and handshake with a relay:
where it is, its ntor onion key, and its identities. ``CircuitHop`` pairs that
with the relay crypto derived once the hop's handshake completes.
"""

from __future__ import annotations

from dataclasses import dataclass

from .._proto.linkspec import LinkSpecifier
from .._proto.relay_crypto import RelayCrypto


@dataclass(frozen=True)
class RelayInfo:
    """Everything needed to extend a circuit to a relay."""

    address: tuple[str, int]  # (host, ORPort)
    ntor_onion_key: bytes  # curve25519 KP_ntor (32)
    identity_digest: bytes  # legacy RSA identity digest (20), the ntor node id
    ed_identity: bytes  # ed25519 identity (32)

    def link_specifiers(self) -> list[LinkSpecifier]:
        """Link specifiers for an EXTEND2 cell, in the recommended order."""
        host, port = self.address
        return [
            LinkSpecifier.ipv4(host, port),
            LinkSpecifier.legacy_id(self.identity_digest),
            LinkSpecifier.ed25519_id(self.ed_identity),
        ]


@dataclass
class CircuitHop:
    """An established hop: the relay it reaches and the crypto for it."""

    relay: RelayInfo
    crypto: RelayCrypto
