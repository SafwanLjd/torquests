"""Per-hop relay-cell cryptography.

Each circuit hop keeps a :class:`RelayCrypto`: a running digest and an AES-CTR
keystream in each direction. The forward pair (``Df``/``Kf``) protects cells the
client sends; the backward pair (``Db``/``Kb``) protects cells it receives. The
keystream is continuous for the life of the circuit, and the running digest is
seeded with the digest key and advanced by every cell in that direction.

The same class serves both profiles: classic hops use a SHA-1 digest and AES-128,
while the v3 onion virtual hop uses SHA3-256 and AES-256. It also serves both
roles: a client stamps forward cells and recognizes backward cells, while a relay
(the in-memory test relay, or a real one) does the mirror.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable

from .._crypto.primitives import ctr_cipher
from .relay import RelayCell

_Digest = Callable[[bytes], "hashlib._Hash"]


class RelayCrypto:
    """Forward and backward relay-cell crypto for a single circuit hop."""

    def __init__(self, key_material: bytes, *, digest: _Digest, key_len: int) -> None:
        digest_len = digest(b"").digest_size
        needed = 2 * digest_len + 2 * key_len
        if len(key_material) < needed:
            raise ValueError(f"need {needed} bytes of key material, got {len(key_material)}")
        df = key_material[0:digest_len]
        db = key_material[digest_len : 2 * digest_len]
        kf = key_material[2 * digest_len : 2 * digest_len + key_len]
        kb = key_material[2 * digest_len + key_len : 2 * digest_len + 2 * key_len]
        self._forward_digest = digest(df)
        self._backward_digest = digest(db)
        self._forward_cipher = ctr_cipher(kf)
        self._backward_cipher = ctr_cipher(kb)

    @classmethod
    def tor1(cls, key_material: bytes) -> RelayCrypto:
        """Classic hop: SHA-1 digest, AES-128 (72 bytes of key material)."""
        return cls(key_material, digest=hashlib.sha1, key_len=16)

    @classmethod
    def hs_v3(cls, key_material: bytes) -> RelayCrypto:
        """v3 onion virtual hop: SHA3-256 digest, AES-256 (128 bytes)."""
        return cls(key_material, digest=hashlib.sha3_256, key_len=32)

    # --- ciphers (symmetric; naming reflects which keystream) -------------- #

    def apply_forward_cipher(self, body: bytes) -> bytes:
        """Advance the forward keystream over ``body`` (encrypt when sending,
        decrypt when receiving as a relay)."""
        return self._forward_cipher.update(body)

    def apply_backward_cipher(self, body: bytes) -> bytes:
        """Advance the backward keystream over ``body``."""
        return self._backward_cipher.update(body)

    # --- digests ----------------------------------------------------------- #

    def stamp_forward(self, cell: RelayCell) -> RelayCell:
        """Advance the forward digest and return the cell with its digest set."""
        self._forward_digest.update(cell.digest_input())
        return cell.with_digest(self._forward_digest.digest()[:4])

    def stamp_backward(self, cell: RelayCell) -> RelayCell:
        """Advance the backward digest and return the cell with its digest set."""
        self._backward_digest.update(cell.digest_input())
        return cell.with_digest(self._backward_digest.digest()[:4])

    def forward_digest(self) -> bytes:
        """The current forward running-digest value (for authenticated SENDMEs)."""
        return self._forward_digest.digest()

    def backward_digest(self) -> bytes:
        """The current backward running-digest value (for authenticated SENDMEs)."""
        return self._backward_digest.digest()

    def recognize_forward(self, body: bytes) -> RelayCell | None:
        """As a relay: return the cell if this hop recognizes a forward body."""
        return self._recognize(body, forward=True)

    def recognize_backward(self, body: bytes) -> RelayCell | None:
        """As a client: return the cell if it originated at this hop."""
        return self._recognize(body, forward=False)

    def _recognize(self, body: bytes, *, forward: bool) -> RelayCell | None:
        if body[1:3] != b"\x00\x00":  # recognized field must be zero
            return None
        # Hash the raw received body with the 4 digest bytes zeroed. This must use
        # the bytes exactly as received (padding included), not a re-serialized
        # form, so it matches a peer that padded a cell with random bytes.
        received_digest = body[5:9]
        zeroed_body = body[:5] + b"\x00\x00\x00\x00" + body[9:]
        running = self._forward_digest if forward else self._backward_digest
        probe = running.copy()
        probe.update(zeroed_body)
        if probe.digest()[:4] != received_digest:
            return None
        # Commit the advanced digest only once the cell is recognized.
        if forward:
            self._forward_digest = probe
        else:
            self._backward_digest = probe
        return RelayCell.parse(body)
