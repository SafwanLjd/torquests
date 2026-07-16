"""Tests for TorClient circuit pooling, isolation, and lifecycle."""

from __future__ import annotations

import pytest

from torquests._client.torclient import TorClient
from torquests.exceptions import OnionServiceError

from .fakes import FakeRelay, FakeRelayTransport


def make_client(relay: FakeRelay) -> TorClient:
    transport = FakeRelayTransport(relay)
    return TorClient(
        path_provider=lambda host, port: relay.path(),
        transport_factory=lambda guard: transport,
    )


def test_same_isolation_key_reuses_the_circuit() -> None:
    client = make_client(FakeRelay())
    try:
        a = client.connect_stream("a.com", 80, isolation_key="K", connect_timeout=5, read_timeout=5)
        b = client.connect_stream("a.com", 80, isolation_key="K", connect_timeout=5, read_timeout=5)
        assert a._circuit is b._circuit  # pooled by isolation key
    finally:
        client.close()


def test_request_isolation_uses_fresh_unpooled_circuits() -> None:
    client = make_client(FakeRelay())

    def unpooled() -> object:
        return client.connect_stream(
            "a.com", 80, isolation_key=None, connect_timeout=5, read_timeout=5
        )

    try:
        a = unpooled()
        circ_a = a._circuit
        assert client._circuits == {}  # an unpooled circuit is never stored
        a.close()
        assert circ_a.destroyed  # and it tears down when its stream ends

        b = unpooled()
        assert b._circuit is not circ_a  # a fresh circuit per request
        assert client._circuits == {}
        b.close()
    finally:
        client.close()


def test_close_destroys_pooled_circuits() -> None:
    client = make_client(FakeRelay())
    stream = client.connect_stream(
        "a.com", 80, isolation_key="K", connect_timeout=5, read_timeout=5
    )
    circuit = stream._circuit
    client.close()
    assert circuit.destroyed


def test_connect_stream_rejects_onion_hosts() -> None:
    client = make_client(FakeRelay())
    try:
        with pytest.raises(OnionServiceError):
            client.connect_stream(
                "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion",
                80,
                isolation_key="K",
                connect_timeout=5,
                read_timeout=5,
            )
    finally:
        client.close()


def test_connect_stream_after_close_raises() -> None:
    from torquests.exceptions import TorBootstrapError

    client = make_client(FakeRelay())
    client.close()
    with pytest.raises(TorBootstrapError):
        client.connect_stream("a.com", 80, isolation_key="K", connect_timeout=5, read_timeout=5)


_ONION = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"


def test_client_auth_key_lookup_normalizes_host() -> None:
    key = bytes(range(32))
    client = TorClient(
        path_provider=lambda host, port: [],
        onion_auth={_ONION.upper(): key},
    )
    try:
        # Case and a trailing ``.onion`` are normalized on both the stored keys
        # and the lookup, so the address the request carries matches.
        assert client._client_auth_key(_ONION) == key
        assert client._client_auth_key(_ONION.removesuffix(".onion")) == key
        assert client._client_auth_key("nowhere.onion") is None
    finally:
        client.close()


def test_onion_auth_rejects_wrong_length_key() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        TorClient(path_provider=lambda host, port: [], onion_auth={_ONION: b"short"})
