"""A minimal in-memory guard manager.

Guard-spec basics (guard-spec/algorithm.md): a client keeps a small random
sample of the consensus guard set ({GUARDS} = relays flagged
Guard+Stable+Fast+V2Dir), marks sampled guards unlisted when they drop out of
the consensus, and routes user traffic through the first few usable sampled
guards (its primary guards) so its entry point into the network stays stable.

This implements that skeleton for the lifetime of the process: bandwidth-weighted
sampling in a stable order and listed/unlisted tracking on every new consensus.
The state is held in memory only and is not written to disk, keeping the
library's clean forensic profile; the sample is re-drawn on each start. It
leaves out confirmed-guard promotion and reachability retry scheduling.
"""

from __future__ import annotations

import random
from collections.abc import Sequence
from dataclasses import dataclass

from .models import RouterStatus
from .pathselect import GUARD_FLAGS, BandwidthWeights, bandwidth_weighted_choice


@dataclass
class GuardEntry:
    """One sampled guard: its identity and whether the latest consensus lists it."""

    fingerprint: str  # upper-case hex of the 20-byte RSA identity digest
    listed: bool = True  # present in the latest consensus seen


class GuardManager:
    """Maintains the sampled-guard list across consensuses, in memory for the process."""

    def __init__(
        self,
        *,
        sample_size: int = 3,
        rng: random.Random | None = None,
    ) -> None:
        if sample_size < 1:
            raise ValueError(f"sample_size must be at least 1, got {sample_size}")
        self._sample_size = sample_size
        self._rng: random.Random = rng if rng is not None else random.SystemRandom()
        self._entries: list[GuardEntry] = []

    def update(
        self,
        routers: Sequence[RouterStatus],
        *,
        weights: BandwidthWeights | None = None,
    ) -> None:
        """Refresh the sample from a new consensus.

        Marks sampled guards listed/unlisted and tops the sample back up to
        ``sample_size`` listed guards with bandwidth-weighted picks (using the
        consensus guard-position ``weights`` when supplied). Unlisted entries are
        kept: a relay that returns to the consensus regains its place in the
        sample order, as guard-spec prescribes.
        """
        eligible = {
            router.fingerprint.hex().upper(): router
            for router in routers
            if router.flags >= GUARD_FLAGS
        }
        for entry in self._entries:
            entry.listed = entry.fingerprint in eligible
        sampled = {entry.fingerprint for entry in self._entries}
        remaining = [r for fp, r in eligible.items() if fp not in sampled]
        while sum(entry.listed for entry in self._entries) < self._sample_size and remaining:
            pick = bandwidth_weighted_choice(
                self._rng, remaining, position="guard", weights=weights
            )
            remaining.remove(pick)
            self._entries.append(GuardEntry(fingerprint=pick.fingerprint.hex().upper()))

    def primary_guards(self, routers: Sequence[RouterStatus]) -> list[RouterStatus]:
        """The first ``sample_size`` listed sampled guards, resolved in ``routers``."""
        by_fingerprint = {router.fingerprint.hex().upper(): router for router in routers}
        primary: list[RouterStatus] = []
        for entry in self._entries:
            if not entry.listed:
                continue
            router = by_fingerprint.get(entry.fingerprint)
            if router is not None:
                primary.append(router)
            if len(primary) == self._sample_size:
                break
        return primary
