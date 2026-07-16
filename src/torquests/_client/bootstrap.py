"""Bootstrapping a live view of the Tor network.

The client needs a verified consensus before it can build a circuit, but it has
no circuit yet, a chicken-and-egg the network solves by letting anyone fetch
directory documents from a directory over plain HTTP. Those documents are signed,
so the transport does not have to be trusted: the authority signing keys are
verified against the hardcoded identity fingerprints, and the consensus is checked
against a majority of them. Only the relay selection that follows is anonymized.

This fetches over HTTP with the standard library (no extra dependency) and hands
out full circuit paths, fetching each relay's microdescriptor (its ntor key and
exit policy) on demand. Those on-demand fetches would otherwise leak, in
cleartext from the client's real IP, which relay a circuit is about to use; once
a :attr:`~LiveDirectory.set_dir_tunnel` hook is installed they are carried over a
Tor directory circuit (BEGIN_DIR) instead, and only fall back to cleartext if the
tunnel fails.
"""

from __future__ import annotations

import base64
import logging
import random
import threading
import urllib.request
from collections.abc import Callable, Iterable, Mapping, Sequence
from datetime import datetime, timezone
from itertools import islice
from typing import TYPE_CHECKING

from .._dir.authorities import DirectoryAuthority
from .._dir.microdesc import usable_ed_identity
from .._dir.models import Consensus, Microdescriptor, RouterStatus
from .._dir.pathselect import family_conflict, normalize_family
from .._net.hop import RelayInfo
from ..exceptions import (
    ChannelError,
    CircuitError,
    DirectoryError,
    StreamError,
    TorBootstrapError,
    TorReadTimeout,
)

#: A hook that fetches a directory document (given its request path) over Tor.
DirTunnel = Callable[[str], str]

if TYPE_CHECKING:
    from .._dir.keycerts import KeyCertificate

_MD_BATCH = 50

#: How many times a path is re-drawn to avoid two same-family relays before the
#: last draw is accepted anyway. Family conflicts among a stable guard, a random
#: middle, and a random exit are rare, so a handful of attempts converges.
_FAMILY_SELECT_ATTEMPTS = 8

logger = logging.getLogger(__name__)


def _http_get(host: str, port: int, path: str, timeout: float) -> bytes:
    # No tool-identifying User-Agent to the directory over cleartext. urllib adds
    # "User-Agent: Python-urllib/<ver>" when none is set, which fingerprints the
    # client, so set an explicit empty header: urllib then sends "User-Agent:"
    # with no value and does not substitute its default.
    url = f"http://{host}:{port}{path}"
    request = urllib.request.Request(url)
    request.add_header("User-Agent", "")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return bytes(response.read())


def _fetch(
    path: str,
    mirrors: Sequence[tuple[str, int]],
    timeout: float,
    rng: random.Random,
) -> str:
    # Shuffle the mirror order per fetch so no single authority is always the
    # first (or only) directory contacted for a client.
    order = list(mirrors)
    rng.shuffle(order)
    failures = []
    for host, port in order:
        try:
            return _http_get(host, port, path, timeout).decode("ascii", "replace")
        except Exception as exc:
            failures.append(f"{host}:{port} {exc}")
    raise DirectoryError(f"all directory mirrors failed for {path}: {'; '.join(failures)}")


def _batched(items: Sequence[bytes], size: int) -> Iterable[list[bytes]]:
    iterator = iter(items)
    while chunk := list(islice(iterator, size)):
        yield chunk


def _authorities_with_keys(
    authority_set: Sequence[DirectoryAuthority],
    certs: Mapping[bytes, KeyCertificate],
) -> list[DirectoryAuthority]:
    """Return every authority in the full set, keyed where a cert was fetched.

    The returned list always has ``len(authority_set)`` entries: each authority
    carries its fetched signing key when one is available, and is kept bare
    otherwise. A bare authority can never be counted toward the consensus quorum
    (it has no key to verify a signature with) yet still counts toward the
    denominator, so an on-path attacker who truncates ``/tor/keys/all`` cannot
    shrink the authority set the majority threshold is computed against.
    """
    result: list[DirectoryAuthority] = []
    for authority in authority_set:
        cert = certs.get(authority.v3ident)
        if cert is not None:
            result.append(authority.with_signing_key(cert.signing_key_pem))
        else:
            result.append(authority)
    return result


def _microdesc_path(digests: Sequence[bytes]) -> str:
    """The ``/tor/micro/d/`` request path for a batch of microdescriptor digests."""
    encoded = [base64.b64encode(d).decode("ascii").rstrip("=") for d in digests]
    return "/tor/micro/d/" + "-".join(encoded)


class LiveDirectory:
    """A verified consensus plus on-demand microdescriptor fetching."""

    def __init__(
        self,
        consensus: Consensus,
        mirrors: Sequence[tuple[str, int]],
        *,
        timeout: float,
        rng: random.Random | None = None,
    ) -> None:
        from .._dir.guards import GuardManager
        from .._dir.pathselect import DEFAULT_BWWEIGHTSCALE, BandwidthWeights, PathSelector

        self.consensus = consensus
        # Only relays whose ed25519 identity the consensus agrees on are usable:
        # this client pins the ed identity on every channel, so a NoEdConsensus
        # relay (disputed identity) cannot serve as a hop. Filtering here keeps it
        # out of guard, middle, exit, HSDir, and directory-cache selection alike.
        self._routers = [r for r in consensus.routers if "NoEdConsensus" not in r.flags]
        self._mirrors = list(mirrors)
        self._timeout = timeout
        self._rng: random.Random = rng if rng is not None else random.SystemRandom()
        scale = consensus.params.get("bwweightscale", DEFAULT_BWWEIGHTSCALE)
        self._weights = (
            BandwidthWeights(consensus.bandwidth_weights, scale)
            if consensus.bandwidth_weights
            else None
        )
        self._selector = PathSelector(self._routers, rng=self._rng, weights=self._weights)
        # A stable, process-lifetime primary-guard set: every path built by this
        # directory enters through the same guard instead of a fresh random one.
        self._guards = GuardManager(sample_size=3, rng=self._rng)
        self._guards.update(self._routers, weights=self._weights)
        self._microdescriptors: dict[bytes, Microdescriptor] = {}
        # When set, directory documents are fetched over a Tor circuit instead of
        # in cleartext from the client's real IP. Left unset (cleartext) until a
        # bootstrapped client installs a tunnel; see :meth:`set_dir_tunnel`. This
        # directory is shared across every client in the process, so it holds the
        # installed tunnels in an ordered registry and points ``_dir_tunnel`` at the
        # newest one still installed. Closing a client in any order then re-points it
        # at a live sibling, never a dead circuit. The lock guards the registry,
        # since clients install and close concurrently.
        self._dir_tunnel: DirTunnel | None = None
        self._dir_tunnels: list[DirTunnel] = []
        self._tunnel_lock = threading.Lock()

    def set_dir_tunnel(self, fetch: DirTunnel | None) -> None:
        """Install (or clear) a hook that fetches directory documents over Tor.

        When set, the on-demand microdescriptor fetches this directory performs
        go over a Tor circuit (a BEGIN_DIR directory stream) rather than being
        requested in cleartext from the client's real IP, so an on-path observer
        of the directory traffic no longer learns which middle relay a circuit is
        about to use. Fetching is best-effort: a tunnel failure falls back to the
        cleartext fetch, so installing a tunnel can only remove the leak, never
        break the client. Pass ``None`` to restore cleartext fetching.
        """
        with self._tunnel_lock:
            self._dir_tunnel = fetch

    def install_dir_tunnel(self, fetch: DirTunnel) -> None:
        """Register ``fetch`` as the active directory tunnel.

        This directory is process-global (see :func:`get_directory`), so several
        clients can hold a tunnel at once. Each call appends ``fetch`` to an ordered
        registry and makes it the active tunnel; :meth:`restore_dir_tunnel` drops it
        again when the client closes. The registry records every installed tunnel, so
        any close order leaves the active tunnel on a live circuit and never reverts a
        surviving client to cleartext directory fetches from the real IP.
        """
        with self._tunnel_lock:
            self._dir_tunnels.append(fetch)
            self._dir_tunnel = self._dir_tunnels[-1]

    def restore_dir_tunnel(self, fetch: DirTunnel) -> None:
        """Undo an :meth:`install_dir_tunnel`: drop ``fetch`` from the registry.

        Removes ``fetch`` wherever it sits in the registry and re-points the active
        tunnel at the newest one still installed, or clears it when none remain.
        Closing a client that a later one shadowed leaves the active tunnel alone;
        closing the active one falls back to a live sibling, never a dead circuit.
        """
        with self._tunnel_lock:
            for index, installed in enumerate(self._dir_tunnels):
                if installed is fetch:
                    del self._dir_tunnels[index]
                    break
            self._dir_tunnel = self._dir_tunnels[-1] if self._dir_tunnels else None

    def _primary_guards(self) -> list[RouterStatus]:
        """The client's stable primary guards, resolved in the current consensus."""
        return self._guards.primary_guards(self._routers)

    def _fetch_dir(self, path: str, *, allow_tunnel: bool = True) -> str:
        """Fetch a directory document, over the Tor tunnel when one is installed.

        With a tunnel installed and ``allow_tunnel`` true, the fetch is carried
        over a Tor circuit (BEGIN_DIR); any transport or protocol failure on that
        circuit falls back to the cleartext fetch. ``allow_tunnel=False`` forces
        cleartext, which is how the tunnel's own circuit is bootstrapped without
        recursing into a not-yet-built tunnel.
        """
        tunnel = self._dir_tunnel
        if tunnel is not None and allow_tunnel:
            try:
                return tunnel(path)
            except (
                TorBootstrapError,
                ChannelError,
                CircuitError,
                StreamError,
                TorReadTimeout,
            ) as exc:
                # Best-effort: routing over Tor can only remove the metadata leak,
                # never remove functionality, so a failed tunnel fetch falls back to
                # a cleartext fetch. Warn: that fallback re-exposes, in cleartext
                # from the real IP, which relay a circuit is about to use, so an
                # operator relying on the tunnel needs the degradation to be visible.
                logger.warning(
                    "directory tunnel fetch failed (%s); falling back to a cleartext "
                    "fetch of %s from the real IP",
                    exc,
                    path,
                )
        return _fetch(path, self._mirrors, self._timeout, self._rng)

    def _missing_digests(self, routers: Sequence[RouterStatus]) -> list[bytes]:
        """The microdescriptor digests of ``routers`` not already cached."""
        return [
            r.microdescriptor_digest
            for r in routers
            if r.microdescriptor_digest and r.microdescriptor_digest not in self._microdescriptors
        ]

    def _store_microdescriptors(self, text: str) -> None:
        from .._dir.parsers import parse_microdescriptors

        for md in parse_microdescriptors(text):
            self._microdescriptors[md.digest] = md

    def _fetch_microdescriptors(
        self, routers: Sequence[RouterStatus], *, allow_tunnel: bool = True
    ) -> None:
        for chunk in _batched(self._missing_digests(routers), _MD_BATCH):
            self._store_microdescriptors(
                self._fetch_dir(_microdesc_path(chunk), allow_tunnel=allow_tunnel)
            )

    def _relay_info(self, router: RouterStatus) -> RelayInfo:
        md = self._microdescriptors.get(router.microdescriptor_digest or b"")
        if md is None:
            raise DirectoryError(f"missing microdescriptor for relay {router.nickname}")
        ed_identity = usable_ed_identity(router.flags, md)
        if ed_identity is None:
            raise DirectoryError(f"relay {router.nickname} has no usable ed25519 identity")
        return RelayInfo(
            address=(router.address, router.or_port),
            ntor_onion_key=md.ntor_onion_key,
            identity_digest=router.fingerprint,
            ed_identity=ed_identity,
        )

    def _select_exit(self, port: int) -> RouterStatus:
        from .._dir.pathselect import bandwidth_weighted_choice

        # Consider every exit whose policy allows the port, not a raw-bandwidth
        # top-N slice: capping by bandwidth first would shrink the exit anonymity
        # set toward a handful of high-capacity relays. Position weighting then
        # applies over the full policy-allowed set.
        candidates = [r for r in self._routers if r.is_exit]
        self._fetch_microdescriptors_parallel(candidates)
        allowed = []
        for router in candidates:
            md = self._microdescriptors.get(router.microdescriptor_digest or b"")
            if md is not None and md.exit_policy is not None and md.exit_policy.allows(port):
                allowed.append(router)
        if not allowed:
            raise DirectoryError(f"no exit relay allows port {port}")
        return bandwidth_weighted_choice(self._rng, allowed, position="exit", weights=self._weights)

    def _family_of(self, router: RouterStatus) -> frozenset[str]:
        """The relay's declared family fingerprints, from its cached microdescriptor."""
        md = self._microdescriptors.get(router.microdescriptor_digest or b"")
        return normalize_family(md.family) if md is not None else frozenset()

    def _has_family_conflict(self, relays: Sequence[RouterStatus]) -> bool:
        """Whether any two of ``relays`` declare each other in family."""
        families = [(r.fingerprint, self._family_of(r)) for r in relays]
        for index, (fp_a, family_a) in enumerate(families):
            for fp_b, family_b in families[index + 1 :]:
                if family_conflict(fp_a, family_a, fp_b, family_b):
                    return True
        return False

    def _select_family_disjoint(
        self, select: Callable[[], list[RouterStatus]], *, allow_tunnel: bool = True
    ) -> list[RouterStatus]:
        """Draw a path with ``select`` until its relays share no declared family.

        Family membership lives in the microdescriptors, which this directory
        fetches on demand, so it can only be checked after selection: each attempt
        draws relays, fetches their microdescriptors, and accepts the draw when no
        two are family. A stable guard, a random middle, and a random exit rarely
        collide, so a few attempts converge; the last draw is returned regardless
        so a pathological consensus never fails the request (identity and /16
        separation are already enforced during selection).
        """
        relays = select()
        for _ in range(_FAMILY_SELECT_ATTEMPTS - 1):
            self._fetch_microdescriptors(relays, allow_tunnel=allow_tunnel)
            if not self._has_family_conflict(relays):
                return relays
            relays = select()
        self._fetch_microdescriptors(relays, allow_tunnel=allow_tunnel)
        return relays

    def path_provider(self, host: str, port: int) -> list[RelayInfo]:
        """Select a guard -> middle -> exit path that allows ``port``.

        The guard is the client's stable primary guard (guard-spec); only the
        middle and exit vary between circuits. No two hops share an identity or a
        /16 (enforced during selection); family separation is best-effort, applied
        by :meth:`_select_family_disjoint`.
        """

        def select() -> list[RouterStatus]:
            exit_relay = self._select_exit(port)
            guard = self._selector.select_guard(exclude=[exit_relay], prefer=self._primary_guards())
            middle = self._selector.select_middle(exclude=[guard, exit_relay])
            return [guard, middle, exit_relay]

        guard, middle, exit_relay = self._select_family_disjoint(select)
        return [self._relay_info(guard), self._relay_info(middle), self._relay_info(exit_relay)]

    def path_to(self, target: RouterStatus) -> list[RelayInfo]:
        """A guard -> middle -> ``target`` path (used to reach an HSDir, intro, or RP)."""

        def select() -> list[RouterStatus]:
            guard = self._selector.select_guard(exclude=[target], prefer=self._primary_guards())
            middle = self._selector.select_middle(exclude=[guard, target])
            return [guard, middle, target]

        guard, middle, target = self._select_family_disjoint(select)
        return [self._relay_info(guard), self._relay_info(middle), self._relay_info(target)]

    def rendezvous_path(self) -> list[RelayInfo]:
        """A three-hop path whose last hop is usable as a rendezvous point."""

        def select() -> list[RouterStatus]:
            guard = self._selector.select_guard(prefer=self._primary_guards())
            middle = self._selector.select_middle(exclude=[guard])
            rp = self._selector.select_middle(exclude=[guard, middle])
            return [guard, middle, rp]

        guard, middle, rp = self._select_family_disjoint(select)
        return [self._relay_info(guard), self._relay_info(middle), self._relay_info(rp)]

    def path_ending_at(self, target: RelayInfo) -> list[RelayInfo]:
        """A guard -> middle -> ``target`` path where the last hop is given directly.

        Used to reach an introduction point named by an onion descriptor rather
        than by the consensus. The guard and middle are drawn family-disjoint from
        each other (best-effort); the target comes from the descriptor, not the
        consensus, so it carries no declared family to check here.
        """

        def select() -> list[RouterStatus]:
            guard = self._selector.select_guard(prefer=self._primary_guards())
            middle = self._selector.select_middle(exclude=[guard])
            return [guard, middle]

        guard, middle = self._select_family_disjoint(select)
        return [self._relay_info(guard), self._relay_info(middle), target]

    # --- directory tunnel -------------------------------------------------- #

    def dir_circuit_path(self) -> list[RelayInfo]:
        """Select a guard -> middle -> directory-cache path for the directory tunnel.

        The last hop carries the ``V2Dir`` flag, so it answers tunneled BEGIN_DIR
        directory requests over its OR port (dir-spec/assigning-flags-vote.md).
        The three relays on this path have their microdescriptors fetched in
        *cleartext* (``allow_tunnel=False``): this is the single, unavoidable
        residual cleartext fetch, done once when the tunnel is built, that lets
        every later microdescriptor fetch be tunneled without recursing back into
        a not-yet-built tunnel. The guard is the client's stable primary guard,
        which an on-path observer already learns from the TLS connection, so only
        the middle and the cache are newly exposed, once.
        """
        from .._dir.pathselect import bandwidth_weighted_choice

        caches = [r for r in self._routers if r.is_v2dir]
        if not caches:
            raise DirectoryError("consensus has no V2Dir directory cache to tunnel through")

        def select() -> list[RouterStatus]:
            cache = bandwidth_weighted_choice(
                self._rng, caches, position="middle", weights=self._weights
            )
            guard = self._selector.select_guard(exclude=[cache], prefer=self._primary_guards())
            middle = self._selector.select_middle(exclude=[guard, cache])
            return [guard, middle, cache]

        guard, middle, cache = self._select_family_disjoint(select, allow_tunnel=False)
        return [self._relay_info(guard), self._relay_info(middle), self._relay_info(cache)]

    # --- onion-service directory support ----------------------------------- #

    def _fetch_microdescriptors_parallel(
        self, routers: Sequence[RouterStatus], *, allow_tunnel: bool = True
    ) -> None:
        import concurrent.futures

        batches = list(_batched(self._missing_digests(routers), _MD_BATCH))
        if not batches:
            return

        def fetch(chunk: list[bytes]) -> str:
            return self._fetch_dir(_microdesc_path(chunk), allow_tunnel=allow_tunnel)

        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            # pool.map yields on this thread, so the microdescriptor store is
            # only ever mutated here, never concurrently from the worker threads.
            for text in pool.map(fetch, batches):
                self._store_microdescriptors(text)

    def _hsdir_nodes(self) -> list[_HsDirNode]:
        hsdirs = [r for r in self._routers if r.is_hsdir]
        self._fetch_microdescriptors_parallel(hsdirs)
        nodes = []
        for router in hsdirs:
            md = self._microdescriptors.get(router.microdescriptor_digest or b"")
            if md is None:
                continue
            ed_identity = usable_ed_identity(router.flags, md)
            if ed_identity is not None:
                nodes.append(_HsDirNode(ed_identity, router))
        return nodes

    def responsible_hsdirs(
        self, blinded_pubkey: bytes, *, use_previous_srv: bool
    ) -> list[RouterStatus]:
        """The HSDirs that should hold a descriptor, for the current time period."""
        from .._onion.hsdir import disaster_srv, responsible_hsdirs

        period = self.time_period()
        period_length = self.period_length()
        srv = (
            self.consensus.shared_random_previous
            if use_previous_srv
            else self.consensus.shared_random_current
        )
        if srv is None:
            srv = disaster_srv(period_length, period)
        chosen = responsible_hsdirs(blinded_pubkey, self._hsdir_nodes(), srv, period, period_length)
        return [node.router for node in chosen]

    def period_length(self) -> int:
        """The time-period length in minutes (consensus ``hsdir_interval``)."""
        from .._crypto.ed25519_blind import DEFAULT_PERIOD_LENGTH_MINUTES

        return self.consensus.params.get("hsdir_interval", DEFAULT_PERIOD_LENGTH_MINUTES)

    def time_period(self) -> int:
        from .._crypto.ed25519_blind import time_period

        return time_period(int(self.consensus.valid_after.timestamp()), self.period_length())


class _HsDirNode:
    """Adapts a RouterStatus to the hash-ring node interface (``.ed_identity``)."""

    def __init__(self, ed_identity: bytes, router: RouterStatus) -> None:
        self.ed_identity = ed_identity
        self.router = router


def bootstrap(
    *,
    authorities: Sequence[DirectoryAuthority] | None = None,
    timeout: float = 60.0,
    rng: random.Random | None = None,
) -> LiveDirectory:
    """Fetch and verify the consensus, returning a live directory."""
    from .._dir.authorities import DEFAULT_AUTHORITIES
    from .._dir.consensus import verify_consensus
    from .._dir.keycerts import parse_key_certificates

    resolved_rng: random.Random = rng if rng is not None else random.SystemRandom()
    authority_set = list(authorities) if authorities is not None else list(DEFAULT_AUTHORITIES)
    mirrors = [a.dir_address for a in authority_set]

    cert_text = _fetch("/tor/keys/all", mirrors, timeout, resolved_rng)
    certs = {c.v3ident: c for c in parse_key_certificates(cert_text)}
    fetched = sum(1 for a in authority_set if a.v3ident in certs)
    if fetched * 2 <= len(authority_set):
        raise TorBootstrapError(
            f"only {fetched} of {len(authority_set)} authority signing keys verified"
        )
    # Verify the consensus against the FULL authority set (keyed where possible),
    # not just the authorities whose cert we happened to fetch: the majority
    # threshold must be computed over every authority, so withholding certs cannot
    # lower the quorum.
    authorities_with_keys = _authorities_with_keys(authority_set, certs)

    consensus_text = _fetch(
        "/tor/status-vote/current/consensus-microdesc", mirrors, timeout, resolved_rng
    )
    consensus = verify_consensus(
        consensus_text, authorities_with_keys, now=datetime.now(timezone.utc)
    )
    return LiveDirectory(consensus, mirrors, timeout=timeout, rng=resolved_rng)


_cache_lock = threading.Lock()
_cached_directory: LiveDirectory | None = None


def get_directory(*, timeout: float = 60.0, refresh: bool = False) -> LiveDirectory:
    """Return a process-global live directory, bootstrapping once and reusing it.

    Re-bootstraps when ``refresh`` is set or the cached consensus is no longer live,
    so a client created after the consensus expires (a fresh session, or the module
    verbs) selects paths from a current network view rather than a stale one.
    """
    global _cached_directory
    with _cache_lock:
        cached = _cached_directory
        stale = cached is not None and not cached.consensus.is_live(datetime.now(timezone.utc))
        if cached is None or refresh or stale:
            cached = bootstrap(timeout=timeout)
            _cached_directory = cached
        return cached
