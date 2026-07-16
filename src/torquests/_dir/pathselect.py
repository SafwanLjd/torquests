"""Bandwidth-weighted path selection over the consensus relay set.

Positions have flag requirements: a guard needs
``Guard+Stable+Fast+V2Dir+Running+Valid`` (the guard-spec {GUARDS} definition,
guard-spec/algorithm.md, plus the always-implied Running/Valid) and a middle
needs only ``Running+Valid``. Within a path no two relays may share an identity,
an IPv4 /16, or a declared family (path-spec path-selection constraints); the
family check is one-way: either relay naming the other is enough, the
conservative reading.

Relays are drawn with probability proportional to their consensus
``w Bandwidth=`` weight, scaled by the per-position ``bandwidth-weights``
factors from the consensus footer (Wgg, Wgd, Wee, Wed, Wmg, ...). Those factors
depend on both the target position (guard/middle/exit) and the relay's flags,
so a relay carrying both Guard and Exit is weighted by its dual-flag factor
(dir-spec bandwidth-weights, path-spec 2.2 "Bandwidth weighting"). When a
consensus carries no ``bandwidth-weights`` line the weights are simply absent
and selection falls back to raw ``w Bandwidth=``.

The RNG is injectable so tests are deterministic; production uses
``random.SystemRandom``.
"""

from __future__ import annotations

import random
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass

from ..exceptions import ConsensusError
from .models import RouterStatus

#: guard-spec/algorithm.md: {GUARDS} = Guard+Stable+Fast+V2Dir, plus Running+Valid.
GUARD_FLAGS = frozenset({"Guard", "Stable", "Fast", "V2Dir", "Running", "Valid"})
MIDDLE_FLAGS = frozenset({"Running", "Valid"})

#: dir-spec default when the consensus omits ``params bwweightscale``.
DEFAULT_BWWEIGHTSCALE = 10000

#: Positions for which the consensus publishes bandwidth-weight factors.
_WEIGHTED_POSITIONS = frozenset({"guard", "middle", "exit"})

#: Per-position weight key for each relay flag class (dir-spec bandwidth-weights,
#: mirroring C Tor's ``compute_weighted_bandwidths``). An exit-only relay has no
#: key in the guard position: C Tor weights it zero there.
_POSITION_WEIGHT_KEYS: dict[str, dict[str, str]] = {
    "guard": {"guard": "Wgg", "middle": "Wgm", "dual": "Wgd"},
    "middle": {"guard": "Wmg", "middle": "Wmm", "exit": "Wme", "dual": "Wmd"},
    "exit": {"guard": "Weg", "middle": "Wem", "exit": "Wee", "dual": "Wed"},
}


def _flag_class(router: RouterStatus) -> str:
    """Which bandwidth-weight class ``router`` falls in: guard/exit/dual/middle."""
    is_guard = "Guard" in router.flags
    is_exit = router.is_exit
    if is_guard and is_exit:
        return "dual"
    if is_guard:
        return "guard"
    if is_exit:
        return "exit"
    return "middle"


@dataclass(frozen=True)
class BandwidthWeights:
    """The consensus footer ``bandwidth-weights`` factors, applied per position.

    ``weights`` maps each ``Wxy`` key to its integer value and ``scale`` is the
    ``bwweightscale`` consensus parameter (default :data:`DEFAULT_BWWEIGHTSCALE`);
    a relay's effective weight for a position is its bandwidth times
    ``factor(...)`` (dir-spec bandwidth-weights).
    """

    weights: Mapping[str, int]
    scale: int

    def factor(self, router: RouterStatus, position: str) -> float:
        """The multiplier applied to ``router``'s bandwidth for ``position``.

        Returns ``0.0`` for a relay that cannot serve the position under the
        published weights (an exit-only relay in the guard position), and
        ``1.0`` for positions with no published weights (e.g. an HSDir lookup).
        Raises :class:`ConsensusError` if a needed weight key is missing.
        """
        keys = _POSITION_WEIGHT_KEYS.get(position)
        if keys is None:
            return 1.0
        key = keys.get(_flag_class(router))
        if key is None:
            return 0.0
        try:
            return self.weights[key] / self.scale
        except KeyError as exc:
            raise ConsensusError(
                f"consensus bandwidth-weights missing {key} for the {position} position"
            ) from exc


def bandwidth_weighted_choice(
    rng: random.Random,
    candidates: Sequence[RouterStatus],
    *,
    position: str = "relay",
    weights: BandwidthWeights | None = None,
) -> RouterStatus:
    """Pick one relay with probability proportional to its consensus bandwidth.

    When ``weights`` is given, each candidate's bandwidth is scaled by its
    per-position factor (:meth:`BandwidthWeights.factor`). Falls back to a
    uniform pick if every candidate ends up with zero weight; raises
    :class:`ConsensusError` when there is nothing to pick from.
    """
    if not candidates:
        raise ConsensusError(f"no usable relay for the {position} position")
    if weights is None:
        effective = [float(router.bandwidth) for router in candidates]
    else:
        effective = [router.bandwidth * weights.factor(router, position) for router in candidates]
    total = sum(effective)
    if total <= 0:
        return candidates[rng.randrange(len(candidates))]
    point = rng.random() * total
    accumulated = 0.0
    for router, weight in zip(candidates, effective, strict=True):
        accumulated += weight
        if point < accumulated:
            return router
    return candidates[-1]


def normalize_family(entries: Iterable[str]) -> frozenset[str]:
    """The ``$HEXID`` family members in ``entries``, normalized to upper hex.

    Only the ``$``-prefixed fingerprint forms are kept, tolerating the
    pre-canonical ``$hexid=name`` / ``$hexid~name`` variants; a bare nickname is
    ignored, since a relay is identified within a family by its fingerprint.
    """
    ids = set()
    for entry in entries:
        if entry.startswith("$"):
            ids.add(entry[1:].partition("=")[0].partition("~")[0].upper())
    return frozenset(ids)


def family_conflict(
    fp_a: bytes, family_a: frozenset[str], fp_b: bytes, family_b: frozenset[str]
) -> bool:
    """Whether two relays share a declared family, given each one's family set.

    The check is one-way: either relay naming the other's fingerprint is enough,
    the conservative reading of the path-spec family constraint.
    """
    return fp_b.hex().upper() in family_a or fp_a.hex().upper() in family_b


def _family_ids(router: RouterStatus) -> frozenset[str]:
    """The ``$HEXID`` family members a relay declares, from its microdescriptor."""
    if router.microdescriptor is None:
        return frozenset()
    return normalize_family(router.microdescriptor.family)


def _same_family(a: RouterStatus, b: RouterStatus) -> bool:
    return family_conflict(a.fingerprint, _family_ids(a), b.fingerprint, _family_ids(b))


def _same_subnet(a: RouterStatus, b: RouterStatus) -> bool:
    """Whether two relays share an IPv4 /16 (first two octets)."""
    return a.address.split(".")[:2] == b.address.split(".")[:2]


def _conflicts(candidate: RouterStatus, chosen: RouterStatus) -> bool:
    return (
        candidate.fingerprint == chosen.fingerprint
        or _same_subnet(candidate, chosen)
        or _same_family(candidate, chosen)
    )


class PathSelector:
    """Selects relays for circuit positions from a consensus relay set."""

    def __init__(
        self,
        routers: Sequence[RouterStatus],
        *,
        rng: random.Random | None = None,
        weights: BandwidthWeights | None = None,
    ) -> None:
        self._routers = list(routers)
        self._rng: random.Random = rng if rng is not None else random.SystemRandom()
        self._weights = weights

    def _pick(
        self,
        required: frozenset[str],
        exclude: Sequence[RouterStatus],
        position: str,
    ) -> RouterStatus:
        candidates = []
        for router in self._routers:
            if not required <= router.flags:
                continue
            if any(_conflicts(router, chosen) for chosen in exclude):
                continue
            candidates.append(router)
        weights = self._weights if position in _WEIGHTED_POSITIONS else None
        return bandwidth_weighted_choice(self._rng, candidates, position=position, weights=weights)

    def _is_usable_guard(self, router: RouterStatus, exclude: Sequence[RouterStatus]) -> bool:
        """Whether ``router`` still qualifies as a guard disjoint from ``exclude``."""
        return router.flags >= GUARD_FLAGS and not any(
            _conflicts(router, chosen) for chosen in exclude
        )

    def select_guard(
        self,
        *,
        exclude: Sequence[RouterStatus] = (),
        prefer: Sequence[RouterStatus] = (),
    ) -> RouterStatus:
        """A guard disjoint from ``exclude``, preferring the client's primary guards.

        ``prefer`` is the stable primary-guard list (guard-spec): the first entry
        that still carries the guard flags and does not conflict with ``exclude``
        is returned, so the entry guard stays fixed across circuits. When none is
        usable the guard is drawn bandwidth-weighted from the whole consensus.
        """
        for candidate in prefer:
            if self._is_usable_guard(candidate, exclude):
                return candidate
        return self._pick(GUARD_FLAGS, exclude, "guard")

    def select_middle(self, *, exclude: Sequence[RouterStatus] = ()) -> RouterStatus:
        """A bandwidth-weighted middle relay, disjoint from ``exclude``."""
        return self._pick(MIDDLE_FLAGS, exclude, "middle")
