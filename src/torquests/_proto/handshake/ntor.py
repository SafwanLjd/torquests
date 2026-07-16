"""The ntor circuit handshake (CREATE2 handshake type 2).

The client sends ``NODEID | KEYID=B | X`` where ``B`` is the relay's ntor onion
key and ``X`` is a fresh ephemeral public key. The relay replies with ``Y | AUTH``;
the client checks ``AUTH`` and derives 72 bytes of relay-crypto key material
(``Df | Db | Kf | Kb``) with HKDF-SHA256.

Reference: tor-spec, "The ntor handshake".
"""

from __future__ import annotations

from ..._crypto.primitives import (
    const_time_eq,
    hkdf_sha256_expand,
    hmac_sha256,
    x25519,
    x25519_keypair,
    x25519_public_from_private,
)
from ...exceptions import CircuitError
from ..constants import NTOR_PROTOID

_T_MAC = NTOR_PROTOID + b":mac"
_T_KEY = NTOR_PROTOID + b":key_extract"
_T_VERIFY = NTOR_PROTOID + b":verify"
_M_EXPAND = NTOR_PROTOID + b":key_expand"

#: Bytes of relay-crypto key material a classic hop needs (Df|Db|Kf|Kb).
_KEY_MATERIAL_LEN = 72


class NtorHandshake:
    """Client side of one ntor key agreement."""

    def __init__(
        self, onion_key: bytes, node_id: bytes, *, ephemeral_private: bytes | None = None
    ) -> None:
        if len(onion_key) != 32:
            raise ValueError("ntor onion key must be 32 bytes")
        if len(node_id) != 20:
            raise ValueError("ntor node id must be a 20-byte identity digest")
        self._onion_key = onion_key
        self._node_id = node_id
        self._x = ephemeral_private or x25519_keypair()[0]
        self._pub_x = x25519_public_from_private(self._x)

    def create_onion_skin(self) -> bytes:
        return self._node_id + self._onion_key + self._pub_x

    def complete(self, reply: bytes) -> bytes:
        if len(reply) < 64:
            raise CircuitError("ntor reply too short")
        server_pub = reply[:32]
        auth = reply[32:64]

        try:
            exp_yx = x25519(self._x, server_pub)
            exp_bx = x25519(self._x, self._onion_key)
        except ValueError as exc:
            # A malicious relay can send a low-order Y whose shared secret is all
            # zeros; x25519 rejects that as ValueError. Surface it as a CircuitError
            # so it is handled (and retried) like any other failed handshake rather
            # than escaping the circuit-build retry as a bare ValueError.
            raise CircuitError("ntor handshake produced a degenerate shared secret") from exc
        secret_input = (
            exp_yx
            + exp_bx
            + self._node_id
            + self._onion_key
            + self._pub_x
            + server_pub
            + NTOR_PROTOID
        )
        key_seed = hmac_sha256(_T_KEY, secret_input)
        verify = hmac_sha256(_T_VERIFY, secret_input)
        auth_input = (
            verify
            + self._node_id
            + self._onion_key
            + server_pub
            + self._pub_x
            + NTOR_PROTOID
            + b"Server"
        )
        expected_auth = hmac_sha256(_T_MAC, auth_input)
        if not const_time_eq(auth, expected_auth):
            raise CircuitError("ntor handshake authentication failed")
        return hkdf_sha256_expand(key_seed, _M_EXPAND, _KEY_MATERIAL_LEN)
