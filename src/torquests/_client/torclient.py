"""The Tor client: builds and pools circuits, and hands out streams.

A ``TorClient`` owns the guard channels and a pool of circuits keyed by isolation.
It implements the connector the requests adapter depends on: given a host and
port it returns a connected :class:`Stream`. Path selection and the transport are
both injectable, which is what lets the client be exercised offline and swapped to
real TLS in production.
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING

from .._net.channel import Channel
from .._net.circuit import Circuit, build_circuit
from .._net.hop import RelayInfo
from .._net.stream import Stream
from .._net.transport import TlsTransport, Transport
from .._onion.address import is_onion_host
from ..exceptions import ChannelError, CircuitError, OnionServiceError, TorBootstrapError
from .config import TorConfig

if TYPE_CHECKING:
    from .bootstrap import DirTunnel, LiveDirectory

#: Given a target host and port, return a full circuit path (guard first).
PathProvider = Callable[[str, int], list[RelayInfo]]
#: Given a guard, return a transport to it.
TransportFactory = Callable[[RelayInfo], Transport]

#: A v3 client-authorization private key is an x25519 scalar.
_CLIENT_AUTH_KEY_LEN = 32


def _normalize_onion_host(host: str) -> str:
    """Canonicalize an onion host for client-auth lookups.

    v3 addresses are case-insensitive base32, so a stored key and the host a
    request carries must be compared with case folded and a trailing ``.onion``
    stripped, or an authorized service would look unauthorized.
    """
    return host.lower().removesuffix(".onion")


def _validate_onion_auth(onion_auth: Mapping[str, bytes] | None) -> dict[str, bytes]:
    """Normalize and length-check a client-authorization mapping.

    A wrong-length key fails at construction, where the cause is clear, instead
    of deriving no cookie and surfacing later as "authorization required".
    """
    normalized: dict[str, bytes] = {}
    for host, key in (onion_auth or {}).items():
        if len(key) != _CLIENT_AUTH_KEY_LEN:
            raise ValueError(
                f"client-authorization key for {host!r} must be "
                f"{_CLIENT_AUTH_KEY_LEN} bytes, got {len(key)}"
            )
        normalized[_normalize_onion_host(host)] = key
    return normalized


class _DirTunnel:
    """A reusable Tor circuit that carries directory fetches over BEGIN_DIR.

    Building one dedicated directory circuit and fetching every relay's
    microdescriptor over it (instead of in cleartext from the client's real IP)
    is what hides, from an on-path observer of the directory traffic, which
    relays a circuit is about to use. The circuit is shared across concurrent
    fetches -- each opens its own BEGIN_DIR stream, which a circuit supports --
    and rebuilt if it dies. Any failure propagates so the caller can fall back to
    cleartext; tunneling is strictly best-effort.
    """

    def __init__(
        self,
        build_circuit: Callable[[], Circuit],
        *,
        connect_timeout: float,
        read_timeout: float | None,
    ) -> None:
        self._build_circuit = build_circuit
        self._connect_timeout = connect_timeout
        self._read_timeout = read_timeout
        self._lock = threading.Lock()
        self._circuit: Circuit | None = None

    def ensure_circuit(self) -> Circuit:
        """Return the shared directory circuit, building it if absent or dead.

        The build runs under the lock so concurrent first fetches share a single
        circuit rather than each racing to build its own.
        """
        with self._lock:
            circuit = self._circuit
            if circuit is None or circuit.destroyed:
                circuit = self._build_circuit()
                self._circuit = circuit
            return circuit

    def fetch(self, path: str) -> str:
        """Fetch a directory document over the shared circuit (BEGIN_DIR)."""
        from .._dir.dirhttp import dir_get

        circuit = self.ensure_circuit()
        stream = Stream(circuit, circuit.next_stream_id(), read_timeout=self._read_timeout)
        try:
            stream.connect_dir(timeout=self._connect_timeout)
            body = dir_get(stream, path)
        finally:
            stream.close()
        return body.decode("ascii", "replace")

    def close(self) -> None:
        """Tear down the shared directory circuit, if one is open."""
        with self._lock:
            circuit, self._circuit = self._circuit, None
        if circuit is not None:
            circuit.close()


class TorClient:
    """Owns guard channels and a circuit pool; hands out connected streams."""

    def __init__(
        self,
        config: TorConfig | None = None,
        *,
        path_provider: PathProvider,
        transport_factory: TransportFactory | None = None,
        directory: LiveDirectory | None = None,
        onion_auth: Mapping[str, bytes] | None = None,
    ) -> None:
        self.config = config or TorConfig()
        self._path_provider = path_provider
        self._transport_factory = transport_factory or self._default_transport
        self._directory = directory  # a LiveDirectory, required for .onion connections
        # onion host -> x25519 client-authorization private key, for reaching
        # authorized-only v3 services (keys normalized and length-checked once here).
        self._onion_auth = _validate_onion_auth(onion_auth)
        self._lock = threading.Lock()
        self._channels: dict[bytes, Channel] = {}
        self._circuits: dict[object, Circuit] = {}
        self._dir_tunnel: _DirTunnel | None = None
        # The tunnel hook this client installed on the shared directory, so close()
        # can drop it from the directory's registry rather than leaving a dead
        # tunnel behind (see LiveDirectory.install_dir_tunnel).
        self._dir_tunnel_fetch: DirTunnel | None = None
        self._closed = False

    @classmethod
    def bootstrap(
        cls,
        config: TorConfig | None = None,
        *,
        timeout: float = 60.0,
        onion_auth: Mapping[str, bytes] | None = None,
    ) -> TorClient:
        """Build a client on a live, verified consensus of the Tor network.

        Fetches the consensus once per process (shared across clients) and selects
        real relays over TLS. The consensus and key-certificate fetches are not
        anonymized, but the subsequent per-circuit microdescriptor fetches are
        tunneled over Tor (see :meth:`_install_dir_tunnel`), and the traffic the
        client then carries always is. ``onion_auth`` maps an onion host to the
        x25519 client-authorization private key used to reach an authorized-only
        v3 service.
        """
        from .bootstrap import get_directory

        config = config or TorConfig()
        directory = get_directory(timeout=timeout, cache_dir=config.cache_dir)
        client = cls(
            config,
            path_provider=directory.path_provider,
            directory=directory,
            onion_auth=onion_auth,
        )
        client._install_dir_tunnel(directory)
        return client

    def _install_dir_tunnel(self, directory: LiveDirectory) -> None:
        """Route the directory's on-demand fetches over Tor (best-effort).

        Builds a dedicated directory circuit whose last hop is a V2Dir cache and
        installs it as the directory's fetch tunnel, so every subsequent
        microdescriptor fetch is carried over Tor (BEGIN_DIR) instead of leaking,
        in cleartext from the client's real IP, which relay a circuit is about to
        use. Only this circuit's own relays are fetched in cleartext, once, while
        the tunnel is still unset (its guard is already known from the TLS link;
        the newly exposed hops are its middle and cache). If the circuit cannot be
        built the tunnel is left uninstalled and fetches stay cleartext, so this
        can only remove the leak, never break the client.
        """
        budget = self.config.connect_timeout

        def build_dir_circuit() -> Circuit:
            return self._build_with_retry(directory.dir_circuit_path, budget)

        tunnel = _DirTunnel(
            build_dir_circuit, connect_timeout=budget, read_timeout=self.config.read_timeout
        )
        try:
            tunnel.ensure_circuit()  # build eagerly so the first request is already tunneled
        except (CircuitError, ChannelError, TorBootstrapError):
            return  # best-effort only: leave the existing cleartext fetching in place
        with self._lock:
            if self._closed:
                tunnel.close()
                return
            fetch = tunnel.fetch
            self._dir_tunnel = tunnel
            self._dir_tunnel_fetch = fetch
            directory.install_dir_tunnel(fetch)

    # --- the adapter's connector interface --------------------------------- #

    def connect_stream(
        self,
        host: str,
        port: int,
        *,
        isolation_key: object,
        connect_timeout: float | None,
        read_timeout: float | None,
    ) -> Stream:
        read_deadline = read_timeout if read_timeout is not None else self.config.read_timeout
        if is_onion_host(host):
            return self._connect_onion(host, port, connect_timeout, read_deadline)
        circuit = self._acquire_circuit(host, port, isolation_key, connect_timeout)
        try:
            stream = Stream(circuit, circuit.next_stream_id(), read_timeout=read_deadline)
            stream.connect(host, port, timeout=connect_timeout or self.config.connect_timeout)
        except BaseException:
            # An unpooled (request-isolated) circuit is owned by this call, so it
            # must be torn down if the stream never opens; pooled circuits are not.
            if isolation_key is None:
                circuit.close()
            raise
        return stream

    # --- onion services ---------------------------------------------------- #

    def _build_circuit_along(
        self, path: list[RelayInfo], timeout: float | None, *, close_when_idle: bool = False
    ) -> Circuit:
        channel = self._ensure_channel(path[0], timeout)
        return build_circuit(
            channel,
            path,
            timeout=timeout or self.config.connect_timeout,
            close_when_idle=close_when_idle,
        )

    def _build_with_retry(
        self,
        make_path: Callable[[], list[RelayInfo]],
        timeout: float | None,
        *,
        close_when_idle: bool = False,
    ) -> Circuit:
        """Build a circuit, re-selecting a fresh path if a relay times out or drops it.

        A single unresponsive relay should not fail the whole request: real Tor
        clients try a few paths. Each attempt draws a new path (and so a new guard,
        middle, and exit) from ``make_path``.
        """
        attempts = max(1, self.config.circuit_build_attempts)
        last_exc: Exception | None = None
        for _ in range(attempts):
            path = make_path()
            if not path:
                raise TorBootstrapError("no usable path was selected")
            try:
                return self._build_circuit_along(path, timeout, close_when_idle=close_when_idle)
            except (CircuitError, ChannelError) as exc:
                last_exc = exc
        assert last_exc is not None  # attempts >= 1, so the loop ran and set it
        raise last_exc

    def _client_auth_key(self, host: str) -> bytes | None:
        """Return the x25519 client-authorization key configured for ``host``, if any."""
        return self._onion_auth.get(_normalize_onion_host(host))

    def _connect_onion(
        self, host: str, port: int, connect_timeout: float | None, read_timeout: float | None
    ) -> Stream:
        import base64

        from .._crypto.ed25519_blind import blind_public_key, subcredential
        from .._dir.dirhttp import dir_get
        from .._onion.address import parse as parse_onion
        from .._onion.descriptor import parse_descriptor_with_auth
        from .._onion.rendezvous import connect_to_service
        from ..exceptions import (
            DescriptorError,
            DescriptorNotFound,
            DirectoryError,
            StreamError,
        )

        directory = self._directory
        if directory is None:
            raise OnionServiceError("this client has no directory; use TorClient.bootstrap()")

        address = parse_onion(host)
        period = directory.time_period()
        blinded = blind_public_key(address.identity_key, period, directory.period_length())
        subcred = subcredential(address.identity_key, blinded)
        z = base64.b64encode(blinded).decode("ascii").rstrip("=")
        budget = connect_timeout or self.config.connect_timeout
        client_auth_key = self._client_auth_key(host)

        descriptor = None
        for use_previous in (False, True):
            for hsdir in directory.responsible_hsdirs(blinded, use_previous_srv=use_previous):
                try:
                    circuit = self._build_circuit_along(directory.path_to(hsdir), budget)
                    stream = Stream(circuit, circuit.next_stream_id(), read_timeout=read_timeout)
                    stream.connect_dir(timeout=budget)
                    body = dir_get(stream, f"/tor/hs/3/{z}")
                    descriptor = parse_descriptor_with_auth(
                        body.decode("ascii", "replace"),
                        blinded,
                        subcred,
                        client_auth_privkey=client_auth_key,
                    )
                    break
                except (
                    CircuitError,
                    ChannelError,
                    StreamError,
                    DirectoryError,
                    DescriptorError,
                    ValueError,
                ):
                    # A corrupt or undecryptable descriptor from one HSDir must not
                    # abort the fetch: try the next responsible HSDir.
                    continue
            if descriptor is not None:
                break
        if descriptor is None:
            raise DescriptorNotFound(f"no HSDir served a descriptor for {host}")

        selected: dict[str, list[RelayInfo]] = {}

        def rendezvous_path() -> list[RelayInfo]:
            path: list[RelayInfo] = directory.rendezvous_path()
            selected["path"] = path
            return path

        rendezvous_circuit = self._build_with_retry(rendezvous_path, budget)
        rendezvous_point = selected["path"][-1]

        def build_intro_circuit(intro_info: RelayInfo) -> Circuit:
            return self._build_with_retry(
                lambda: directory.path_ending_at(intro_info),
                budget,
            )

        joined = connect_to_service(
            descriptor,
            subcred,
            rendezvous_circuit,
            rendezvous_point,
            build_intro_circuit,
            timeout=budget,
        )
        stream = Stream(joined, joined.next_stream_id(), read_timeout=read_timeout)
        stream.connect("", port, timeout=budget)
        return stream

    # --- circuit pool ------------------------------------------------------ #

    def _acquire_circuit(
        self, host: str, port: int, isolation_key: object, timeout: float | None
    ) -> Circuit:
        # isolation_key is None for "request" isolation: build a fresh, unpooled
        # circuit that tears itself down when its stream ends, so per-request
        # circuits cannot accumulate in the pool.
        if isolation_key is None:
            with self._lock:
                if self._closed:
                    raise TorBootstrapError("client is closed")
            return self._build_with_retry(
                lambda: self._path_provider(host, port), timeout, close_when_idle=True
            )

        with self._lock:
            if self._closed:
                raise TorBootstrapError("client is closed")
            # Drop circuits destroyed since we last looked so the pool cannot grow
            # without bound as circuits die.
            self._circuits = {k: c for k, c in self._circuits.items() if not c.destroyed}
            existing = self._circuits.get(isolation_key)
            if existing is not None:
                return existing

        circuit = self._build_with_retry(lambda: self._path_provider(host, port), timeout)

        # Re-check under the lock: another thread may have built the same circuit,
        # or the client may have closed, while we were building.
        with self._lock:
            if self._closed:
                circuit_winner: Circuit | None = None
            else:
                existing_circuit = self._circuits.get(isolation_key)
                if existing_circuit is not None and not existing_circuit.destroyed:
                    circuit_winner = existing_circuit
                else:
                    self._circuits[isolation_key] = circuit
                    circuit_winner = circuit
        if circuit_winner is not circuit:
            circuit.close()
        if circuit_winner is None:
            raise TorBootstrapError("client is closed")
        return circuit_winner

    def _default_transport(self, guard: RelayInfo) -> Transport:
        host, port = guard.address
        return TlsTransport(host, port, connect_timeout=self.config.connect_timeout)

    def _ensure_channel(self, guard: RelayInfo, timeout: float | None) -> Channel:
        key = guard.ed_identity
        with self._lock:
            channel = self._channels.get(key)
            if channel is not None and not channel.closed:
                return channel

        built = Channel.open(
            self._transport_factory(guard),
            guard.address[0],
            expected_identity=guard.ed_identity,
            connect_timeout=timeout or self.config.connect_timeout,
        )
        with self._lock:
            if self._closed:
                channel_winner: Channel | None = None
            else:
                existing_channel = self._channels.get(key)
                if existing_channel is not None and not existing_channel.closed:
                    channel_winner = existing_channel
                else:
                    self._channels[key] = built
                    channel_winner = built
        if channel_winner is not built:
            built.close()  # lost the race, or the client closed mid-build
        if channel_winner is None:
            raise TorBootstrapError("client is closed")
        return channel_winner

    # --- identity / lifecycle ---------------------------------------------- #

    def new_identity(self) -> None:
        """Drop all pooled circuits so subsequent requests take fresh paths."""
        with self._lock:
            circuits = list(self._circuits.values())
            self._circuits.clear()
        for circuit in circuits:
            circuit.close()

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            circuits = list(self._circuits.values())
            channels = list(self._channels.values())
            dir_tunnel = self._dir_tunnel
            dir_tunnel_fetch = self._dir_tunnel_fetch
            self._dir_tunnel = None
            self._dir_tunnel_fetch = None
            self._circuits.clear()
            self._channels.clear()
        # Drop this client's tunnel from the shared directory's registry before
        # tearing the circuit down, so closing one client cannot leave the
        # process-global directory pointing at a dead tunnel (which would drop a
        # surviving client to cleartext fetches). The registry re-points the
        # active tunnel at a live sibling for any close order.
        if self._directory is not None and dir_tunnel_fetch is not None:
            self._directory.restore_dir_tunnel(dir_tunnel_fetch)
        # Close channels first: closing a channel's transport fails any send that is
        # blocked writing to a wedged guard, so a circuit's teardown DESTROY does not
        # hang on the TCP timeout. Closing the channel also cascades teardown to its
        # circuits; the explicit circuit close afterwards is then idempotent cleanup.
        for channel in channels:
            channel.close()
        for circuit in circuits:
            circuit.close()
        # The directory circuit rides a guard channel already closed above; this
        # is idempotent cleanup that also drops the tunnel's reference to it.
        if dir_tunnel is not None:
            dir_tunnel.close()

    def __enter__(self) -> TorClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
