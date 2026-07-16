"""The v3 onion HSDir hash ring.

A v3 descriptor is stored on, and fetched from, a small set of "responsible"
directory relays chosen deterministically from the consensus. Both the service
(when uploading) and the client (when fetching) compute the same ring so they
meet at the same relays without any coordination.

Two indices place things on the ring, both 32-byte SHA3-256 digests compared as
unsigned big-endian numbers:

* ``hsdir_index`` positions each HSDir relay by its ed25519 identity, the current
  shared-random value, and the time period.
* ``hs_index`` positions the descriptor itself, once per replica.

For each replica the client sorts the relays by ``hsdir_index`` and walks
forward from the descriptor's ``hs_index``, taking the next ``spread_fetch``
relays around the (circular) ring. The union across replicas is the responsible
set. The two index formulas differ in field order by design
(``period_length``/``period_num`` are swapped); it is specified that way.

Reference: Tor rendezvous specification v3, "Deriving blinded keys and
subcredentials" (WHERE-HSDESC / hash-ring) and the shared-random specification.
"""

from __future__ import annotations

import bisect
import struct
from collections.abc import Sequence
from typing import Protocol, TypeVar

from .._crypto.primitives import sha3_256

_HS_INDEX_PREFIX = b"store-at-idx"
_HSDIR_INDEX_PREFIX = b"node-idx"
_DISASTER_SRV_PREFIX = b"shared-random-disaster"

#: Consensus default for ``hsdir_n_replicas``.
DEFAULT_N_REPLICAS = 2

#: Consensus default for ``hsdir_spread_fetch`` (the client fetch spread).
DEFAULT_SPREAD_FETCH = 3


class HsDirNode(Protocol):
    """A consensus relay usable as an HSDir: anything exposing an ed25519 id."""

    @property
    def ed_identity(self) -> bytes:
        """The relay's 32-byte ed25519 master identity key."""


NodeT = TypeVar("NodeT", bound=HsDirNode)


def _int8(value: int) -> bytes:
    """INT_8: an unsigned integer as 8 big-endian bytes."""
    return struct.pack(">Q", value)


def hs_index(
    blinded_pubkey: bytes,
    replica_num: int,
    period_length: int,
    period_num: int,
) -> bytes:
    """The descriptor's ring position for one replica.

    ``SHA3-256("store-at-idx" | blinded_pubkey | INT_8(replica_num) |
    INT_8(period_length) | INT_8(period_num))``. Note the field order:
    ``period_length`` precedes ``period_num`` here (the opposite of
    :func:`hsdir_index`).
    """
    return sha3_256(
        _HS_INDEX_PREFIX
        + blinded_pubkey
        + _int8(replica_num)
        + _int8(period_length)
        + _int8(period_num)
    )


def hsdir_index(
    node_ed_identity: bytes,
    srv: bytes,
    period_num: int,
    period_length: int,
) -> bytes:
    """A relay's ring position.

    ``SHA3-256("node-idx" | node_ed_identity | srv | INT_8(period_num) |
    INT_8(period_length))``. Note the field order: ``period_num`` precedes
    ``period_length`` here (the opposite of :func:`hs_index`).
    """
    return sha3_256(
        _HSDIR_INDEX_PREFIX + node_ed_identity + srv + _int8(period_num) + _int8(period_length)
    )


def disaster_srv(period_length: int, period_num: int) -> bytes:
    """The fallback shared-random value when the consensus lacks a usable one.

    ``SHA3-256("shared-random-disaster" | INT_8(period_length) |
    INT_8(period_num))``.
    """
    return sha3_256(_DISASTER_SRV_PREFIX + _int8(period_length) + _int8(period_num))


def responsible_hsdirs(
    blinded_pubkey: bytes,
    hsdir_nodes: Sequence[NodeT],
    srv: bytes,
    period_num: int,
    period_length: int,
    *,
    n_replicas: int = DEFAULT_N_REPLICAS,
    spread_fetch: int = DEFAULT_SPREAD_FETCH,
) -> list[NodeT]:
    """Select the relays responsible for a descriptor, in fetch order.

    Sorts ``hsdir_nodes`` by their :func:`hsdir_index`, then for each replica
    walks forward (wrapping around the ring) from the descriptor's
    :func:`hs_index`, taking up to ``spread_fetch`` relays and skipping any
    already chosen for an earlier replica. Returns the deduplicated selection,
    preserving selection order (at most ``n_replicas * spread_fetch`` relays).
    """
    if not hsdir_nodes:
        return []

    ordered = sorted(
        hsdir_nodes,
        key=lambda node: hsdir_index(node.ed_identity, srv, period_num, period_length),
    )
    indices = [hsdir_index(node.ed_identity, srv, period_num, period_length) for node in ordered]
    total = len(ordered)

    selected: list[NodeT] = []
    chosen: set[bytes] = set()

    for replica in range(1, n_replicas + 1):
        target = hs_index(blinded_pubkey, replica, period_length, period_num)
        start = bisect.bisect_left(indices, target)
        if start == total:
            start = 0
        pos = start
        added = 0
        while added < spread_fetch:
            node = ordered[pos]
            if node.ed_identity not in chosen:
                chosen.add(node.ed_identity)
                selected.append(node)
                added += 1
            pos += 1
            if pos == total:
                pos = 0
            if pos == start:
                # Traversed the entire ring for this replica; stop.
                break

    return selected
