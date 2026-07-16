"""Tests for streams and the socket facade, driven by the fake relay's exit."""

from __future__ import annotations

import pytest
import requests

from torquests._http.streamsocket import TorStreamSocket
from torquests._net.channel import Channel
from torquests._net.circuit import build_circuit
from torquests._net.stream import Stream
from torquests.exceptions import StreamConnectError, StreamConnectTimeout, TorReadTimeout

from .fakes import FakeRelay, FakeRelayTransport


def open_circuit(**relay_kwargs):
    relay = FakeRelay(**relay_kwargs)
    transport = FakeRelayTransport(relay)
    channel = Channel.open(transport, "203.0.113.1")
    circuit = build_circuit(channel, relay.path())
    return relay, transport, channel, circuit


def connected_stream(circuit, *, read_timeout=None) -> Stream:
    stream = Stream(circuit, circuit.next_stream_id(), read_timeout=read_timeout)
    stream.connect("example.com", 80)
    return stream


def test_stream_connect_send_recv() -> None:
    _, _, channel, circuit = open_circuit(num_hops=3)
    try:
        stream = connected_stream(circuit)
        stream.send(b"hello onion")
        assert stream.recv(100) == b"hello onion"
        stream.close()
    finally:
        channel.close()


def test_stream_socket_sendall_and_makefile() -> None:
    _, _, channel, circuit = open_circuit()
    try:
        stream = connected_stream(circuit, read_timeout=5.0)
        sock = TorStreamSocket(stream)
        sock.sendall(b"HELLO")
        reader = sock.makefile("rb")
        assert reader.read(5) == b"HELLO"
        sock.close()
    finally:
        channel.close()


def test_stream_read_timeout() -> None:
    _, _, channel, circuit = open_circuit()
    try:
        stream = connected_stream(circuit, read_timeout=0.2)
        with pytest.raises(TorReadTimeout):
            stream.recv(100)  # nothing was sent, so nothing echoes back
    finally:
        channel.close()


def test_stream_eof_on_end() -> None:
    relay, transport, channel, circuit = open_circuit()
    try:
        stream = connected_stream(circuit, read_timeout=5.0)
        transport.inject(relay.push_end(stream.stream_id))
        assert stream.recv(100) == b""  # END delivers EOF
    finally:
        channel.close()


def test_stream_connect_refused() -> None:
    _, _, channel, circuit = open_circuit(refuse_begin=True)
    try:
        stream = Stream(circuit, circuit.next_stream_id(), read_timeout=5.0)
        with pytest.raises(StreamConnectError):
            stream.connect("example.com", 80)
    finally:
        channel.close()


def test_stream_connect_timeout_is_a_connect_timeout() -> None:
    # A BEGIN that never yields CONNECTED is a timeout, not a refusal: it must
    # surface as a requests ConnectTimeout, distinct from the CONNECTREFUSED
    # StreamConnectError path above.
    _, _, channel, circuit = open_circuit(stall_begin=True)
    try:
        stream = Stream(circuit, circuit.next_stream_id(), read_timeout=5.0)
        with pytest.raises(requests.exceptions.ConnectTimeout) as excinfo:
            stream.connect("example.com", 80, timeout=0.2)
        assert isinstance(excinfo.value, StreamConnectTimeout)
        assert not isinstance(excinfo.value, StreamConnectError)
    finally:
        channel.close()


def test_stream_connect_refused_unregisters_stream() -> None:
    # A refused BEGIN must not leave the stream registered on the circuit: pooled
    # circuits outlive the failed request, so a leaked handler would accumulate.
    _, _, channel, circuit = open_circuit(refuse_begin=True)
    try:
        stream = Stream(circuit, circuit.next_stream_id(), read_timeout=5.0)
        with pytest.raises(StreamConnectError):
            stream.connect("example.com", 80)
        assert stream.stream_id not in circuit._streams
    finally:
        channel.close()


def test_stream_connect_timeout_unregisters_stream() -> None:
    _, _, channel, circuit = open_circuit(stall_begin=True)
    try:
        stream = Stream(circuit, circuit.next_stream_id(), read_timeout=5.0)
        with pytest.raises(StreamConnectTimeout):
            stream.connect("example.com", 80, timeout=0.2)
        assert stream.stream_id not in circuit._streams
    finally:
        channel.close()


def test_stream_makefile_rejects_write_mode() -> None:
    _, _, channel, circuit = open_circuit()
    try:
        sock = TorStreamSocket(connected_stream(circuit, read_timeout=5.0))
        with pytest.raises(ValueError):
            sock.makefile("wb")
    finally:
        channel.close()


def test_stream_close_is_idempotent() -> None:
    _, _, channel, circuit = open_circuit()
    try:
        stream = connected_stream(circuit)
        stream.close()
        stream.close()  # no error
    finally:
        channel.close()
