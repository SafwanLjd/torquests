"""The consensus rule for a relay's usable ed25519 identity.

The consensus ``m`` line commits to the SHA-256 of each relay's microdescriptor
(dir-spec/computing-consensus.md, "Microdescriptor consensus"), and the parser
computes every microdescriptor's digest from its raw bytes, so a microdescriptor
is bound to its router by digest before its keys are ever used.

Per dir-spec/computing-microdescriptors.md ("id ed25519"), a relay's ed25519
identity MUST then be ignored when its consensus entry carries the
``NoEdConsensus`` flag; such routers have no usable ed identity even when their
microdescriptor names one.
"""

from __future__ import annotations

from .models import Microdescriptor


def usable_ed_identity(flags: frozenset[str], microdescriptor: Microdescriptor) -> bytes | None:
    """The relay's ed25519 identity, or ``None`` when the consensus forbids it.

    Per dir-spec/computing-microdescriptors.md ("id ed25519"), a client MUST
    ignore a relay's ed25519 identity when its consensus entry carries the
    ``NoEdConsensus`` flag, even if the microdescriptor names one. Every caller
    derives the usable identity through here so the rule is applied in exactly
    one place.
    """
    return microdescriptor.ed25519_id if "NoEdConsensus" not in flags else None
