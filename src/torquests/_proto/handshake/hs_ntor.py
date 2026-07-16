"""The hs-ntor handshake for v3 onion introduction and rendezvous.

The client runs two phases against one ephemeral key ``x``:

* **Introduce**: encrypt the INTRODUCE1 plaintext for the introduction point,
  using keys derived from the intro point's encryption key ``B`` and the service
  subcredential, and MAC the whole body.
* **Rendezvous**: on the service's ``Y | AUTH`` reply, verify ``AUTH`` and derive
  128 bytes of rendezvous-circuit key material (``Df | Db | Kf | Kb``).

The MAC is ``SHA3-256(INT_8(len(key)) | key | message)``. The large shared secret
is the key, the short tweak string is the message.

Reference: rend-spec, "The introduction protocol" and "The rendezvous protocol".
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from ..._crypto.primitives import (
    ZERO_IV16,
    aes_ctr,
    const_time_eq,
    sha3_256,
    shake256,
    x25519,
    x25519_keypair,
    x25519_public_from_private,
)
from ...exceptions import RendezvousError
from ..constants import HS_NTOR_PROTOID

_T_HSENC = HS_NTOR_PROTOID + b":hs_key_extract"
_T_HSVERIFY = HS_NTOR_PROTOID + b":hs_verify"
_T_HSMAC = HS_NTOR_PROTOID + b":hs_mac"
_M_HSEXPAND = HS_NTOR_PROTOID + b":hs_key_expand"

#: Rendezvous-circuit key material (Df|Db|Kf|Kb, 32 bytes each).
_KEY_MATERIAL_LEN = 128


def hs_mac(key: bytes, message: bytes) -> bytes:
    """The hs-ntor MAC: SHA3-256(INT_8(len(key)) | key | message)."""
    return sha3_256(struct.pack(">Q", len(key)) + key + message)


@dataclass(frozen=True)
class RendezvousKeys:
    """The result of completing the rendezvous handshake."""

    ntor_key_seed: bytes
    key_material: bytes  # Df | Db | Kf | Kb, 128 bytes


class HsNtorHandshake:
    """Client side of the hs-ntor introduction and rendezvous handshake."""

    def __init__(
        self,
        intro_auth_key: bytes,
        intro_enc_key: bytes,
        subcredential: bytes,
        *,
        ephemeral_private: bytes | None = None,
    ) -> None:
        if len(intro_auth_key) != 32 or len(intro_enc_key) != 32 or len(subcredential) != 32:
            raise ValueError("hs-ntor keys and subcredential must be 32 bytes")
        self._auth_key = intro_auth_key  # AUTH_KEY: intro point KP_hs_ipt_sid (ed25519)
        self._enc_key = intro_enc_key  # B: intro point KP_hss_ntor (curve25519)
        self._subcredential = subcredential
        self._x = ephemeral_private or x25519_keypair()[0]
        self._pub_x = x25519_public_from_private(self._x)

    @property
    def public_key(self) -> bytes:
        """The ephemeral public key ``X`` placed in the INTRODUCE1 body."""
        return self._pub_x

    def encrypt_introduce(self, header: bytes, plaintext: bytes) -> bytes:
        """Return ``X | ENCRYPTED_DATA | MAC`` for an INTRODUCE1 body.

        ``header`` is the INTRODUCE1 header ``H`` (up to and including the
        AUTH_KEY and extension count); the MAC covers ``H | X | ENCRYPTED_DATA``.
        """
        exp_bx = x25519(self._x, self._enc_key)
        intro_secret = exp_bx + self._auth_key + self._pub_x + self._enc_key + HS_NTOR_PROTOID
        hs_keys = shake256(intro_secret + _T_HSENC + _M_HSEXPAND + self._subcredential, 64)
        enc_key, mac_key = hs_keys[:32], hs_keys[32:]
        encrypted = aes_ctr(enc_key, ZERO_IV16, plaintext)
        mac = hs_mac(mac_key, header + self._pub_x + encrypted)
        return self._pub_x + encrypted + mac

    def complete_rendezvous(self, server_pub: bytes, auth: bytes) -> RendezvousKeys:
        """Verify the service's ``Y | AUTH`` and derive the circuit keys."""
        try:
            exp_xy = x25519(self._x, server_pub)
            exp_xb = x25519(self._x, self._enc_key)
        except ValueError as exc:
            # A malicious rendezvous point can send a low-order Y whose shared
            # secret is all zeros; x25519 rejects that as ValueError. Surface it as
            # a RendezvousError so the onion-connect retry treats it like any other
            # failed handshake rather than aborting the connection on a bare
            # ValueError the retry loop does not catch.
            raise RendezvousError("hs-ntor rendezvous produced a degenerate shared secret") from exc
        rend_secret = (
            exp_xy
            + exp_xb
            + self._auth_key
            + self._enc_key
            + self._pub_x
            + server_pub
            + HS_NTOR_PROTOID
        )
        ntor_key_seed = hs_mac(rend_secret, _T_HSENC)
        verify = hs_mac(rend_secret, _T_HSVERIFY)
        auth_input = (
            verify
            + self._auth_key
            + self._enc_key
            + server_pub
            + self._pub_x
            + HS_NTOR_PROTOID
            + b"Server"
        )
        expected_auth = hs_mac(auth_input, _T_HSMAC)
        if not const_time_eq(auth, expected_auth):
            raise RendezvousError("hs-ntor rendezvous authentication failed")
        key_material = shake256(ntor_key_seed + _M_HSEXPAND, _KEY_MATERIAL_LEN)
        return RendezvousKeys(ntor_key_seed, key_material)
