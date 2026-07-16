"""Tests for the guard channel: link handshake, CERTS validation, demux, shutdown.

All offline, driven by the in-memory fake relay.
"""

from __future__ import annotations

import threading

import pytest

from torquests._net.channel import Channel
from torquests._proto.cells import RawCell
from torquests._proto.constants import Cell
from torquests.exceptions import ChannelError, LinkAuthError

from .fakes import FakeRelay, FakeRelayTransport


class CapturingSink:
    def __init__(self) -> None:
        self.cells: list[RawCell] = []
        self.closed_error: object = "unset"
        self.received = threading.Event()

    def handle_cell(self, cell: RawCell) -> None:
        self.cells.append(cell)
        self.received.set()

    def on_channel_closed(self, error: Exception | None) -> None:
        self.closed_error = error


def open_channel(relay: FakeRelay | None = None) -> tuple[Channel, FakeRelayTransport]:
    transport = FakeRelayTransport(relay)
    channel = Channel.open(transport, "203.0.113.5")
    return channel, transport


class _TimeoutRecordingTransport:
    """Wraps a fake transport and records its set_read_timeout transitions."""

    def __init__(self, inner: FakeRelayTransport) -> None:
        self._inner = inner
        self.read_timeouts: list[float | None] = []

    def connect(self) -> None:
        self._inner.connect()

    def send(self, data: bytes) -> None:
        self._inner.send(data)

    def recv_exact(self, n: int) -> bytes:
        return self._inner.recv_exact(n)

    def set_read_timeout(self, timeout: float | None) -> None:
        self.read_timeouts.append(timeout)

    def close(self) -> None:
        self._inner.close()

    @property
    def certificate_digest(self) -> bytes:
        return self._inner.certificate_digest


def test_channel_open_bounds_the_handshake_then_unbounds() -> None:
    """A guard that accepts TCP then stalls must not hang the caller forever.

    The socket carries the connect budget through the handshake reads, then goes
    blocking for the receiver thread, which legitimately waits for cells with no
    deadline.
    """
    transport = _TimeoutRecordingTransport(FakeRelayTransport(FakeRelay()))
    channel = Channel.open(transport, "203.0.113.5", connect_timeout=12.5)
    try:
        assert transport.read_timeouts == [12.5, None]
    finally:
        channel.close()


def test_link_handshake_authenticates_relay() -> None:
    relay = FakeRelay()
    channel, _ = open_channel(relay)
    try:
        assert channel.link_version == 5
        assert channel.relay_identity == relay.guard.ed_identity
    finally:
        channel.close()


def test_bad_certs_chain_is_rejected() -> None:
    transport = FakeRelayTransport(FakeRelay(valid_certs=False))
    with pytest.raises(LinkAuthError):
        Channel.open(transport, "203.0.113.5")


def test_receiver_demultiplexes_cells_by_circuit() -> None:
    channel, transport = open_channel()
    try:
        circ_id = channel.new_circuit_id()
        sink = CapturingSink()
        channel.register(circ_id, sink)
        transport.inject(RawCell(circ_id, Cell.RELAY, b"\x01" * 20))
        assert sink.received.wait(timeout=5.0)
        assert sink.cells[0].circ_id == circ_id
        assert sink.cells[0].command == Cell.RELAY
    finally:
        channel.close()


def test_cell_for_unknown_circuit_is_dropped() -> None:
    channel, transport = open_channel()
    try:
        transport.inject(RawCell(0x80000009, Cell.RELAY, b"\x00" * 20))
        # The receiver must keep running and still deliver to a real sink.
        circ_id = channel.new_circuit_id()
        sink = CapturingSink()
        channel.register(circ_id, sink)
        transport.inject(RawCell(circ_id, Cell.RELAY, b"\x02" * 20))
        assert sink.received.wait(timeout=5.0)
    finally:
        channel.close()


def test_clean_shutdown_joins_receiver_and_notifies_sinks() -> None:
    channel, _ = open_channel()
    sink = CapturingSink()
    channel.register(channel.new_circuit_id(), sink)

    channel.close()

    assert not channel._receiver.is_alive()
    assert channel.closed
    assert sink.closed_error is None  # closed cleanly


def test_registration_rejects_duplicate_and_closed() -> None:
    channel, _ = open_channel()
    circ_id = channel.new_circuit_id()
    channel.register(circ_id, CapturingSink())
    with pytest.raises(ChannelError):
        channel.register(circ_id, CapturingSink())
    channel.close()
    with pytest.raises(ChannelError):
        channel.register(channel.new_circuit_id(), CapturingSink())
