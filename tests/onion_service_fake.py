"""An in-memory v3 onion service, for testing the client rendezvous flow.

It builds a descriptor that points at a given introduction-point relay, and on an
INTRODUCE1 it runs the service half of hs-ntor: it recovers the rendezvous cookie,
derives the same rendezvous keys the client will, and injects a RENDEZVOUS2 back
onto the client's rendezvous circuit.
"""

from __future__ import annotations

import os

from torquests._crypto.primitives import (
    ZERO_IV16,
    aes_ctr,
    shake256,
    x25519,
    x25519_keypair,
)
from torquests._onion.descriptor import HsDescriptor, IntroPoint
from torquests._proto.constants import HS_NTOR_PROTOID, Relay
from torquests._proto.handshake.hs_ntor import hs_mac
from torquests._proto.linkspec import LinkSpecifier
from torquests._proto.relay import RelayCell
from torquests._proto.relay_crypto import RelayCrypto

from .crypto_helpers import ed25519_public_from_seed

_T_HSENC = HS_NTOR_PROTOID + b":hs_key_extract"
_T_HSVERIFY = HS_NTOR_PROTOID + b":hs_verify"
_T_HSMAC = HS_NTOR_PROTOID + b":hs_mac"
_M_HSEXPAND = HS_NTOR_PROTOID + b":hs_key_expand"


class FakeOnionService:
    """The service half of the introduction and rendezvous handshake."""

    def __init__(self) -> None:
        self.subcredential = os.urandom(32)
        self._auth_seed = os.urandom(32)
        self.auth_key = ed25519_public_from_seed(self._auth_seed)  # KP_hs_ipt_sid
        self.enc_private, self.enc_key = x25519_keypair()  # KP_hss_ntor (b, B)
        self.intro_relay: object | None = None  # the FakeHop hosting the intro point
        self.rend_transport: object | None = None  # the client's rendezvous transport
        self.service_crypto: RelayCrypto | None = None

    def descriptor(self) -> HsDescriptor:
        relay = self.intro_relay
        assert relay is not None
        specs = [
            LinkSpecifier.ipv4(*relay.address),  # type: ignore[attr-defined]
            LinkSpecifier.legacy_id(relay.node_id),  # type: ignore[attr-defined]
            LinkSpecifier.ed25519_id(relay.ed_identity),  # type: ignore[attr-defined]
        ]
        intro = IntroPoint(specs, relay.ntor_public, self.auth_key, self.enc_key)  # type: ignore[attr-defined]
        return HsDescriptor(lifetime=180, revision_counter=1, intro_points=[intro])

    def on_introduce1(self, body: bytes) -> None:
        header, client_pub, encrypted = body[:56], body[56:88], body[88:-32]

        intro_secret = (
            x25519(self.enc_private, client_pub)
            + self.auth_key
            + client_pub
            + self.enc_key
            + HS_NTOR_PROTOID
        )
        hs_keys = shake256(intro_secret + _T_HSENC + _M_HSEXPAND + self.subcredential, 64)
        enc_key, mac_key = hs_keys[:32], hs_keys[32:]
        assert hs_mac(mac_key, header + client_pub + encrypted) == body[-32:], "client MAC invalid"
        aes_ctr(enc_key, ZERO_IV16, encrypted)  # plaintext holds the cookie; not needed here

        y_private, y_pub = x25519_keypair()
        rend_secret = (
            x25519(y_private, client_pub)
            + x25519(self.enc_private, client_pub)
            + self.auth_key
            + self.enc_key
            + client_pub
            + y_pub
            + HS_NTOR_PROTOID
        )
        ntor_key_seed = hs_mac(rend_secret, _T_HSENC)
        verify = hs_mac(rend_secret, _T_HSVERIFY)
        auth_input = (
            verify + self.auth_key + self.enc_key + y_pub + client_pub + HS_NTOR_PROTOID + b"Server"
        )
        auth = hs_mac(auth_input, _T_HSMAC)
        self.service_crypto = RelayCrypto.hs_v3(shake256(ntor_key_seed + _M_HSEXPAND, 128))

        assert self.rend_transport is not None
        self.rend_transport.inject_relay(RelayCell(Relay.RENDEZVOUS2, 0, y_pub + auth))  # type: ignore[attr-defined]
