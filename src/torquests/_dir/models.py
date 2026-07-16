"""Typed views of the directory documents a client keeps.

A :class:`Consensus` is the parsed microdescriptor-flavor network status: the
validity interval, network parameters, shared-random values, one
:class:`RouterStatus` per relay, and the signature records needed to verify it.
A :class:`Microdescriptor` carries the per-relay keys and exit-policy summary
that the consensus deliberately omits; once matched to its router (by the
consensus ``m`` digest) the pair is enough to build a circuit hop.

References: dir-spec/consensus-formats.md (status document items),
dir-spec/computing-consensus.md ("Microdescriptor consensus"), and
dir-spec/computing-microdescriptors.md.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class ExitPolicySummary:
    """A microdescriptor ``p`` line: which exit ports are open to most addresses.

    With microdescriptors, clients only see this summary, so it is a guess: a
    relay may still refuse a matching BEGIN with an exit-policy reason
    (dir-spec/computing-microdescriptors.md, "Approximate calculation").
    """

    accept: bool
    ports: tuple[tuple[int, int], ...]  # inclusive (low, high) ranges

    def allows(self, port: int) -> bool:
        """Whether the summary says the relay exits to ``port``."""
        listed = any(low <= port <= high for low, high in self.ports)
        return listed if self.accept else not listed


@dataclass(frozen=True)
class Microdescriptor:
    """One relay's microdescriptor (dir-spec/computing-microdescriptors.md)."""

    digest: bytes  # SHA-256 of the raw document; the consensus 'm' value (32)
    ntor_onion_key: bytes  # curve25519 KP_ntor, the circuit-extension key (32)
    ed25519_id: bytes | None  # KP_relayid_ed master identity (32), if present
    exit_policy: ExitPolicySummary | None  # None means "reject 1-65535"
    family: frozenset[str]  # declared family entries ("$HEXID" or nicknames)


@dataclass(frozen=True)
class RouterStatus:
    """One relay's entry in the microdescriptor consensus.

    ``ed_identity`` and ``microdescriptor`` default to ``None`` and hold the
    relay's usable ed25519 identity and matched microdescriptor once those have
    been resolved from the consensus ``m`` digest.
    """

    nickname: str
    fingerprint: bytes  # SHA1(DER(KP_relayid_rsa)) (20); the ntor node id
    address: str  # IPv4 dotted quad
    or_port: int
    dir_port: int  # 0 means no directory port
    flags: frozenset[str]
    bandwidth: int  # consensus weight from 'w Bandwidth=' (0 if unmeasured/absent)
    microdescriptor_digest: bytes | None  # SHA-256 from the 'm' line (32)
    ed_identity: bytes | None = None
    microdescriptor: Microdescriptor | None = None

    @property
    def is_guard(self) -> bool:
        """Whether the relay carries the ``Guard`` flag."""
        return "Guard" in self.flags

    @property
    def is_exit(self) -> bool:
        """Whether the relay is usable as an exit: ``Exit`` and not ``BadExit``."""
        return "Exit" in self.flags and "BadExit" not in self.flags

    @property
    def is_hsdir(self) -> bool:
        """Whether the relay carries the ``HSDir`` flag."""
        return "HSDir" in self.flags

    @property
    def is_v2dir(self) -> bool:
        """Whether the relay is a directory cache (the ``V2Dir`` flag).

        A ``V2Dir`` relay has an open DirPort or a ``tunnelled-dir-server`` line,
        so it answers directory requests, including tunneled BEGIN_DIR requests
        over its OR port (dir-spec/assigning-flags-vote.md). Those are the relays
        usable as the last hop of a directory-fetch circuit.
        """
        return "V2Dir" in self.flags


@dataclass(frozen=True)
class ConsensusSignature:
    """One ``directory-signature`` item (dir-spec/consensus-formats.md)."""

    algorithm: str  # "sha1" or "sha256"; unknown values are kept but never counted
    identity: bytes  # authority identity-key fingerprint (20)
    signing_key_digest: bytes  # SHA1 of the authority's current signing key (20)
    signature: bytes  # PKCS#1 v1.5 signature over the bare document digest


@dataclass(frozen=True)
class Consensus:
    """A parsed microdescriptor-flavor consensus."""

    valid_after: datetime  # timezone-aware UTC
    fresh_until: datetime
    valid_until: datetime
    routers: list[RouterStatus]
    params: dict[str, int]
    bandwidth_weights: dict[str, int]  # footer 'bandwidth-weights' Wxy factors ({} if absent)
    shared_random_current: bytes | None  # 32-byte SRV, if the consensus has one
    shared_random_previous: bytes | None
    signatures: tuple[ConsensusSignature, ...]

    def is_live(self, now: datetime) -> bool:
        """Whether ``now`` falls inside [valid-after, valid-until].

        (dir-spec/client-operation.md: a consensus is "live" in that interval.)
        """
        return self.valid_after <= now <= self.valid_until
