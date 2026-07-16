"""Tests for tunneling directory (microdescriptor) fetches over Tor (BEGIN_DIR).

The leak these guard against: fetching a relay's microdescriptor in cleartext,
from the client's real IP, tells an on-path observer (and the directory server)
which middle relay a circuit is about to use. Once a directory tunnel is
installed the fetches ride a Tor circuit instead, falling back to cleartext only
if the tunnel fails, so tunneling can only remove the leak, never break the
client.
"""

from __future__ import annotations

import concurrent.futures
import logging
import random

import pytest

from torquests._client import bootstrap as bootstrap_mod
from torquests._client.bootstrap import LiveDirectory
from torquests._client.torclient import TorClient, _DirTunnel
from torquests._dir.dirhttp import dir_get
from torquests._dir.models import Consensus
from torquests._dir.parsers import parse_consensus
from torquests._net.channel import Channel
from torquests._net.circuit import Circuit, build_circuit
from torquests._net.stream import Stream
from torquests.exceptions import DirectoryError

from .dir_fixtures import SyntheticDirectory, synthetic_directory
from .fakes import FakeRelay, FakeRelayTransport


@pytest.fixture
def network() -> SyntheticDirectory:
    return synthetic_directory()


@pytest.fixture
def consensus(network: SyntheticDirectory) -> Consensus:
    return parse_consensus(network.consensus_text)


def _serving_dir_circuit(document: bytes) -> tuple[Circuit, Channel, FakeRelay]:
    """A built three-hop circuit whose last hop serves ``document`` over BEGIN_DIR."""
    relay = FakeRelay(3, dir_document=document)
    channel = Channel.open(FakeRelayTransport(relay), "203.0.113.9")
    circuit = build_circuit(channel, relay.path())
    return circuit, channel, relay


def _live_directory(consensus: Consensus, *, seed: int) -> LiveDirectory:
    return LiveDirectory(consensus, [("dir.example", 80)], timeout=5.0, rng=random.Random(seed))


# --------------------------------------------------------------------------- #
# The V2Dir directory-cache flag
# --------------------------------------------------------------------------- #


def test_router_status_is_v2dir(consensus: Consensus) -> None:
    by_nickname = {router.nickname: router for router in consensus.routers}
    assert by_nickname["guardian1"].is_v2dir  # "... V2Dir ..." in its flags
    assert not by_nickname["middleman"].is_v2dir  # "Fast Running Valid", no V2Dir


# --------------------------------------------------------------------------- #
# The fake relay serves directory documents over a BEGIN_DIR stream
# --------------------------------------------------------------------------- #


def test_fake_relay_serves_directory_document_over_begin_dir() -> None:
    circuit, channel, relay = _serving_dir_circuit(b"microdescriptor-bytes")
    try:
        stream = Stream(circuit, circuit.next_stream_id(), read_timeout=5)
        stream.connect_dir(timeout=5)
        assert dir_get(stream, "/tor/micro/d/abc-def") == b"microdescriptor-bytes"
        assert relay.dir_requests == ["/tor/micro/d/abc-def"]
    finally:
        channel.close()


# --------------------------------------------------------------------------- #
# _DirTunnel: a reusable BEGIN_DIR circuit
# --------------------------------------------------------------------------- #


def test_dir_tunnel_fetch_uses_begin_dir() -> None:
    circuit, channel, relay = _serving_dir_circuit(b"doc-body")
    try:
        tunnel = _DirTunnel(lambda: circuit, connect_timeout=5, read_timeout=5)
        assert tunnel.fetch("/tor/micro/d/xyz") == "doc-body"
        assert relay.dir_requests == ["/tor/micro/d/xyz"]
    finally:
        channel.close()


def test_dir_tunnel_rebuilds_a_dead_circuit() -> None:
    built: list[tuple[Circuit, Channel]] = []

    def build() -> Circuit:
        circuit, channel, _ = _serving_dir_circuit(b"served")
        built.append((circuit, channel))
        return circuit

    tunnel = _DirTunnel(build, connect_timeout=5, read_timeout=5)
    try:
        assert tunnel.fetch("/tor/micro/d/a") == "served"
        assert len(built) == 1
        built[0][0].close()  # the shared circuit dies
        assert tunnel.fetch("/tor/micro/d/b") == "served"  # the next fetch rebuilds it
        assert len(built) == 2
    finally:
        for _, channel in built:
            channel.close()


def test_dir_tunnel_serves_concurrent_fetches_on_one_circuit() -> None:
    # A circuit supports many streams: concurrent tunneled fetches must all share
    # the single dir circuit and each get their own answer, with no crossed wires.
    circuit, channel, relay = _serving_dir_circuit(b"payload")
    try:
        tunnel = _DirTunnel(lambda: circuit, connect_timeout=5, read_timeout=5)
        paths = [f"/tor/micro/d/{index}" for index in range(12)]
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            results = list(pool.map(tunnel.fetch, paths))
        assert results == ["payload"] * 12
        assert sorted(relay.dir_requests) == sorted(paths)
    finally:
        channel.close()


# --------------------------------------------------------------------------- #
# LiveDirectory: tunneled fetch, cleartext fallback, and the untouched default
# --------------------------------------------------------------------------- #


def test_live_directory_tunnels_microdescriptor_fetches(
    network: SyntheticDirectory, consensus: Consensus, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden_http_get(*args: object, **kwargs: object) -> bytes:
        raise AssertionError("cleartext _http_get used while a working tunnel was installed")

    monkeypatch.setattr(bootstrap_mod, "_http_get", forbidden_http_get)

    circuit, channel, relay = _serving_dir_circuit(network.microdescriptors_text.encode("ascii"))
    try:
        tunnel = _DirTunnel(lambda: circuit, connect_timeout=5, read_timeout=5)
        directory = _live_directory(consensus, seed=7)
        directory.set_dir_tunnel(tunnel.fetch)

        path = directory.path_provider("example.com", 443)

        assert len(path) == 3  # a full guard -> middle -> exit path was resolved
        assert relay.dir_requests  # every microdescriptor fetch rode BEGIN_DIR
        assert all(request.startswith("/tor/micro/d/") for request in relay.dir_requests)
    finally:
        channel.close()


def test_tunnel_failure_falls_back_to_cleartext(
    network: SyntheticDirectory,
    consensus: Consensus,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    cleartext_paths: list[str] = []

    def recording_http_get(host: str, port: int, path: str, timeout: float) -> bytes:
        cleartext_paths.append(path)
        return network.microdescriptors_text.encode("ascii")

    monkeypatch.setattr(bootstrap_mod, "_http_get", recording_http_get)

    def failing_tunnel(path: str) -> str:
        raise DirectoryError("dir circuit is down")

    directory = _live_directory(consensus, seed=7)
    directory.set_dir_tunnel(failing_tunnel)

    with caplog.at_level(logging.WARNING, logger="torquests._client.bootstrap"):
        path = directory.path_provider("example.com", 443)

    assert len(path) == 3  # the client still works despite the dead tunnel
    assert cleartext_paths  # the cleartext fetch was used as the fallback
    assert all(p.startswith("/tor/micro/d/") for p in cleartext_paths)
    # The silent-degradation gap is closed: the fallback logs a visible warning.
    assert any("cleartext" in record.message for record in caplog.records)


def test_no_tunnel_keeps_cleartext_behavior_unchanged(
    network: SyntheticDirectory, consensus: Consensus, monkeypatch: pytest.MonkeyPatch
) -> None:
    cleartext_paths: list[str] = []

    def recording_http_get(host: str, port: int, path: str, timeout: float) -> bytes:
        cleartext_paths.append(path)
        return network.microdescriptors_text.encode("ascii")

    monkeypatch.setattr(bootstrap_mod, "_http_get", recording_http_get)

    directory = _live_directory(consensus, seed=7)
    assert directory._dir_tunnel is None  # no tunnel installed by default

    directory.path_provider("example.com", 443)

    assert cleartext_paths  # fetches go straight to cleartext, exactly as before


# --------------------------------------------------------------------------- #
# The dir circuit's own path: V2Dir last hop, fetched cleartext (no recursion)
# --------------------------------------------------------------------------- #


def test_dir_circuit_path_uses_v2dir_last_hop_and_stays_cleartext(
    network: SyntheticDirectory, consensus: Consensus, monkeypatch: pytest.MonkeyPatch
) -> None:
    cleartext_paths: list[str] = []

    def recording_http_get(host: str, port: int, path: str, timeout: float) -> bytes:
        cleartext_paths.append(path)
        return network.microdescriptors_text.encode("ascii")

    monkeypatch.setattr(bootstrap_mod, "_http_get", recording_http_get)

    tunnel_paths: list[str] = []

    def recording_tunnel(path: str) -> str:
        tunnel_paths.append(path)
        return network.microdescriptors_text

    directory = _live_directory(consensus, seed=3)
    directory.set_dir_tunnel(recording_tunnel)  # a tunnel IS installed...

    path = directory.dir_circuit_path()

    assert len(path) == 3
    cache_router = next(r for r in consensus.routers if r.fingerprint == path[-1].identity_digest)
    assert cache_router.is_v2dir  # the last hop is a directory cache
    # ...yet the dir circuit's own relays were fetched cleartext, never tunneled,
    # so building it cannot recurse into a not-yet-built tunnel.
    assert cleartext_paths
    assert tunnel_paths == []


def test_dir_circuit_path_without_a_cache_raises(consensus: Consensus) -> None:
    import dataclasses

    no_caches = dataclasses.replace(
        consensus,
        routers=[
            dataclasses.replace(r, flags=frozenset(r.flags - {"V2Dir"})) for r in consensus.routers
        ],
    )
    directory = _live_directory(no_caches, seed=1)
    with pytest.raises(DirectoryError, match="V2Dir"):
        directory.dir_circuit_path()


# --------------------------------------------------------------------------- #
# TorClient wiring: install the tunnel, then route fetches over the circuit
# --------------------------------------------------------------------------- #


def test_torclient_installs_and_uses_the_dir_tunnel(
    network: SyntheticDirectory, consensus: Consensus, monkeypatch: pytest.MonkeyPatch
) -> None:
    def serve_cleartext(host: str, port: int, path: str, timeout: float) -> bytes:
        # The dir circuit's own relays are (correctly) resolved in cleartext.
        return network.microdescriptors_text.encode("ascii")

    monkeypatch.setattr(bootstrap_mod, "_http_get", serve_cleartext)

    circuit, channel, relay = _serving_dir_circuit(network.microdescriptors_text.encode("ascii"))
    directory = _live_directory(consensus, seed=11)
    client = TorClient(path_provider=directory.path_provider, directory=directory)
    try:
        # Building a real circuit to the synthetic relays is impossible offline
        # (their ntor keys are synthetic), so stub the circuit build to return the
        # fake dir circuit. dir_circuit_path itself still runs for real, selecting
        # a V2Dir last hop and resolving its relays in cleartext.
        def fake_build(make_path: object, timeout: object, **kwargs: object) -> Circuit:
            make_path()  # exercise dir_circuit_path (V2Dir selection + cleartext fetch)
            return circuit

        monkeypatch.setattr(client, "_build_with_retry", fake_build)

        client._install_dir_tunnel(directory)
        assert client._dir_tunnel is not None
        assert directory._dir_tunnel is not None  # the hook is installed on the directory

        # A subsequent microdescriptor fetch now rides the fake dir circuit. Drop
        # the cache first: dir_circuit_path already resolved every relay cleartext
        # (the fake authority serves the whole batch), so force a fresh fetch.
        relay.dir_requests.clear()
        directory._microdescriptors.clear()
        directory._fetch_microdescriptors(list(consensus.routers))
        assert relay.dir_requests
        assert all(request.startswith("/tor/micro/d/") for request in relay.dir_requests)
    finally:
        client.close()
        channel.close()


def test_dir_tunnel_install_and_restore_track_the_active_tunnel(consensus: Consensus) -> None:
    directory = _live_directory(consensus, seed=1)

    def tunnel_a(path: str) -> str:
        return "a"

    def tunnel_b(path: str) -> str:
        return "b"

    directory.install_dir_tunnel(tunnel_a)  # first install becomes active
    assert directory._dir_tunnel is tunnel_a
    directory.install_dir_tunnel(tunnel_b)  # b shadows a
    assert directory._dir_tunnel is tunnel_b
    directory.restore_dir_tunnel(tunnel_b)  # closing b restores a, not a dead ref
    assert directory._dir_tunnel is tunnel_a
    directory.restore_dir_tunnel(tunnel_a)  # closing a clears
    assert directory._dir_tunnel is None


def test_dir_tunnel_restore_is_noop_when_not_the_active_tunnel(consensus: Consensus) -> None:
    # A client shadowed by a later one must not clobber the active tunnel on close.
    directory = _live_directory(consensus, seed=1)

    def tunnel_a(path: str) -> str:
        return "a"

    def tunnel_b(path: str) -> str:
        return "b"

    directory.install_dir_tunnel(tunnel_a)
    directory.install_dir_tunnel(tunnel_b)
    directory.restore_dir_tunnel(tunnel_a)  # a (shadowed, not active) closes -> b stays active
    assert directory._dir_tunnel is tunnel_b
    directory.restore_dir_tunnel(tunnel_b)  # b closes too -> registry empty, no dead ref left
    assert directory._dir_tunnel is None


def test_dir_tunnel_registry_survives_non_lifo_close(consensus: Consensus) -> None:
    # Three clients share the process-global directory, each installing its own
    # tunnel. Closing the middle one, then the newest, must leave the active tunnel
    # on a still-installed (live) circuit, never a closed one, so a surviving client
    # never reverts to cleartext dir fetches from the real IP. The per-client
    # shadow-stack this replaced tracked only the tunnel each install shadowed, so a
    # non-LIFO close could point the directory at a dead circuit.
    directory = _live_directory(consensus, seed=1)

    def tunnel_s(path: str) -> str:
        return "s"

    def tunnel_t(path: str) -> str:
        return "t"

    def tunnel_c(path: str) -> str:
        return "c"

    for tunnel in (tunnel_s, tunnel_t, tunnel_c):
        directory.install_dir_tunnel(tunnel)
    assert directory._dir_tunnel is tunnel_c

    directory.restore_dir_tunnel(tunnel_t)  # close the middle one (non-LIFO)
    assert directory._dir_tunnel is tunnel_c  # active tunnel untouched and still live

    directory.restore_dir_tunnel(tunnel_c)  # close the newest
    assert directory._dir_tunnel is tunnel_s  # falls back to the live sibling, not dead t

    directory.restore_dir_tunnel(tunnel_s)
    assert directory._dir_tunnel is None


def test_closing_a_client_restores_a_sibling_dir_tunnel(
    network: SyntheticDirectory, consensus: Consensus, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Two clients share the process-global directory (get_directory caches one).
    # The second shadows the first's tunnel; when it closes it must restore the
    # first's, not leave the directory pointing at its own dead circuit, which
    # would drop the surviving client to cleartext fetches from the real IP.
    monkeypatch.setattr(
        bootstrap_mod,
        "_http_get",
        lambda *a, **k: network.microdescriptors_text.encode("ascii"),
    )
    circuit_a, channel_a, _ = _serving_dir_circuit(network.microdescriptors_text.encode("ascii"))
    circuit_b, channel_b, _ = _serving_dir_circuit(network.microdescriptors_text.encode("ascii"))
    directory = _live_directory(consensus, seed=11)
    client_a = TorClient(path_provider=directory.path_provider, directory=directory)
    client_b = TorClient(path_provider=directory.path_provider, directory=directory)
    try:
        monkeypatch.setattr(client_a, "_build_with_retry", lambda mp, t, **k: (mp(), circuit_a)[1])
        monkeypatch.setattr(client_b, "_build_with_retry", lambda mp, t, **k: (mp(), circuit_b)[1])

        client_a._install_dir_tunnel(directory)
        a_fetch = directory._dir_tunnel
        assert a_fetch is not None
        client_b._install_dir_tunnel(directory)
        assert directory._dir_tunnel is not a_fetch  # b shadowed a

        client_b.close()
        assert directory._dir_tunnel is a_fetch  # a's live tunnel restored, not left dead
    finally:
        client_a.close()
        channel_a.close()
        channel_b.close()


def test_install_dir_tunnel_leaves_cleartext_when_the_circuit_cannot_build(
    consensus: Consensus, monkeypatch: pytest.MonkeyPatch
) -> None:
    from torquests.exceptions import CircuitError

    directory = _live_directory(consensus, seed=5)
    client = TorClient(path_provider=directory.path_provider, directory=directory)
    try:

        def failing_build(make_path: object, timeout: object, **kwargs: object) -> Circuit:
            raise CircuitError("no relay answered")

        monkeypatch.setattr(client, "_build_with_retry", failing_build)

        client._install_dir_tunnel(directory)  # must not raise

        assert client._dir_tunnel is None
        assert directory._dir_tunnel is None  # best-effort: cleartext left in place
    finally:
        client.close()
