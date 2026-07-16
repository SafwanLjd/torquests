"""Tests for circuit build/extend, onion round-trips, teardown, and flow control."""

from __future__ import annotations

import threading

import pytest

from torquests._net.channel import Channel
from torquests._net.circuit import build_circuit
from torquests._net.flowcontrol import DeliverCounter, PackageWindow, SendmeTracker
from torquests._proto.cells import DestroyCell
from torquests._proto.constants import (
    CIRCUIT_WINDOW_INCREMENT,
    CIRCUIT_WINDOW_INITIAL,
    Relay,
)
from torquests._proto.relay import RelayCell, begin_body, parse_sendme_v1, sendme_v1_body
from torquests.exceptions import CircuitDestroyed, CircuitError

from .fakes import FakeRelay, FakeRelayTransport


def _wait_until(predicate, *, timeout: float = 5.0, interval: float = 0.02) -> bool:
    """Poll ``predicate`` until it holds or the timeout elapses (no real socket)."""
    clock = threading.Event()
    for _ in range(int(timeout / interval)):
        if predicate():
            return True
        clock.wait(interval)
    return predicate()


class CapturingStream:
    def __init__(self) -> None:
        self.cells: list[RelayCell] = []
        self.received = threading.Event()
        self.closed_error: object = "unset"

    def handle_relay(self, cell: RelayCell) -> None:
        self.cells.append(cell)
        self.received.set()

    def on_circuit_closed(self, error: Exception | None) -> None:
        self.closed_error = error


def open_circuit(num_hops: int = 3):
    relay = FakeRelay(num_hops)
    transport = FakeRelayTransport(relay)
    channel = Channel.open(transport, "203.0.113.1")
    circuit = build_circuit(channel, relay.path())
    return relay, transport, channel, circuit


def test_build_three_hop_circuit() -> None:
    relay, _, channel, circuit = open_circuit(3)
    try:
        assert len(circuit.hops) == 3
        assert [h.relay.address for h in circuit.hops] == [hop.address for hop in relay.hops]
    finally:
        circuit.close()
        channel.close()


def test_relay_data_roundtrip_through_all_hops() -> None:
    _, _, channel, circuit = open_circuit(3)
    try:
        stream = CapturingStream()
        sid = circuit.next_stream_id()
        circuit.register_stream(sid, stream)
        circuit.send_relay(RelayCell(Relay.DATA, sid, b"ping through three hops"), is_data=True)
        assert stream.received.wait(timeout=5.0)
        echoed = stream.cells[0]
        assert echoed.command == Relay.DATA
        assert echoed.data == b"ping through three hops"
        assert echoed.stream_id == sid
    finally:
        circuit.close()
        channel.close()


def test_begin_gets_connected() -> None:
    _, _, channel, circuit = open_circuit(2)
    try:
        stream = CapturingStream()
        sid = circuit.next_stream_id()
        circuit.register_stream(sid, stream)
        circuit.send_relay(RelayCell(Relay.BEGIN, sid, begin_body("example.com", 80)))
        assert stream.received.wait(timeout=5.0)
        assert stream.cells[0].command == Relay.CONNECTED
    finally:
        circuit.close()
        channel.close()


def test_destroy_tears_down_circuit_and_notifies_streams() -> None:
    _, transport, channel, circuit = open_circuit(3)
    try:
        stream = CapturingStream()
        circuit.register_stream(circuit.next_stream_id(), stream)
        transport.inject(DestroyCell(reason=0).to_raw(circuit.circ_id))
        deadline = threading.Event()
        # Poll until the receiver thread has processed the DESTROY.
        for _ in range(50):
            if circuit.destroyed:
                break
            deadline.wait(0.05)
        assert circuit.destroyed
        assert isinstance(stream.closed_error, CircuitDestroyed)
    finally:
        channel.close()


def test_close_is_idempotent() -> None:
    _, _, channel, circuit = open_circuit(2)
    circuit.close()
    circuit.close()  # no error
    assert circuit.destroyed
    channel.close()


# --- flow control ---------------------------------------------------------- #


def test_package_window_blocks_until_refilled() -> None:
    window = PackageWindow(initial=2, increment=5)
    window.consume()
    window.consume()  # window is now 0
    unblocked = threading.Event()

    def waiter() -> None:
        window.consume(timeout=5.0)
        unblocked.set()

    threading.Thread(target=waiter, daemon=True).start()
    assert not unblocked.wait(0.2)  # still blocked at 0
    window.refill()
    assert unblocked.wait(2.0)


def test_package_window_close_raises_blocked_consumer() -> None:
    window = PackageWindow(initial=0, increment=5)
    result: list[Exception] = []

    def waiter() -> None:
        try:
            window.consume(timeout=5.0)
        except Exception as exc:
            result.append(exc)

    t = threading.Thread(target=waiter, daemon=True)
    t.start()
    window.close()
    t.join(timeout=2.0)
    assert result and isinstance(result[0], CircuitDestroyed)


def test_deliver_counter_signals_at_increment() -> None:
    counter = DeliverCounter(increment=3)
    assert not counter.note_received()
    assert not counter.note_received()
    assert counter.note_received()  # third cell -> SENDME due
    assert not counter.note_received()  # counter reset


# --- authenticated circuit SENDMEs (tor-spec flow control / proposal 289) --- #


def test_sendme_tracker_matches_boundary_digests_in_order() -> None:
    tracker = SendmeTracker(increment=2)
    tracker.note_sent(b"A" * 20)
    tracker.note_sent(b"B" * 20)  # second cell is the boundary -> remembers B
    tracker.note_sent(b"C" * 20)
    tracker.note_sent(b"D" * 20)  # next boundary -> remembers D
    assert tracker.verify(b"B" * 20)  # acknowledgements are matched FIFO
    assert tracker.verify(b"D" * 20)


def test_sendme_tracker_rejects_wrong_or_unexpected_digest() -> None:
    tracker = SendmeTracker(increment=2)
    assert not tracker.verify(b"Z" * 20)  # nothing outstanding to acknowledge
    tracker.note_sent(b"A" * 20)
    tracker.note_sent(b"B" * 20)  # remembers B
    assert not tracker.verify(b"Z" * 20)  # wrong digest for the boundary cell


def test_parse_sendme_v1_round_trips_and_rejects_bad_bodies() -> None:
    digest = bytes(range(20))
    assert parse_sendme_v1(sendme_v1_body(digest)) == digest
    with pytest.raises(ValueError):
        parse_sendme_v1(b"")  # empty old-format SENDME, authentication required
    with pytest.raises(ValueError):
        parse_sendme_v1(b"\x00\x00\x14" + digest)  # version 0 is unauthenticated
    with pytest.raises(ValueError):
        parse_sendme_v1(b"\x01\x00\x14" + digest[:10])  # DATA truncated


def test_authenticated_sendme_advances_send_window() -> None:
    _, _, channel, circuit = open_circuit(3)
    try:
        stream = CapturingStream()
        sid = circuit.next_stream_id()
        circuit.register_stream(sid, stream)
        # Send exactly one window increment of DATA cells. The fake exit echoes
        # each one and, at the boundary, returns an authenticated v1 SENDME.
        for _ in range(CIRCUIT_WINDOW_INCREMENT):
            circuit.send_relay(RelayCell(Relay.DATA, sid, b"x"), is_data=True)
        # A valid SENDME must refill the send window back to its initial value.
        assert _wait_until(lambda: circuit._package_window.remaining == CIRCUIT_WINDOW_INITIAL)
        assert not circuit.destroyed
        # Traffic continues after the acknowledgement is verified.
        stream.received.clear()
        circuit.send_relay(RelayCell(Relay.DATA, sid, b"after"), is_data=True)
        assert stream.received.wait(timeout=5.0)
        assert circuit.hops[-1]  # circuit is still usable
    finally:
        circuit.close()
        channel.close()


def test_forged_circuit_sendme_tears_down_circuit() -> None:
    _, transport, channel, circuit = open_circuit(3)
    try:
        stream = CapturingStream()
        circuit.register_stream(circuit.next_stream_id(), stream)
        # No DATA was sent, so no acknowledgement is outstanding: this SENDME is
        # forged and must be rejected and tear the circuit down, or a relay could
        # inflate the client's send window at will.
        transport.inject_relay(RelayCell(Relay.SENDME, 0, sendme_v1_body(b"\x00" * 20)))
        assert _wait_until(lambda: circuit.destroyed)
        assert isinstance(stream.closed_error, CircuitError)
        assert not isinstance(stream.closed_error, CircuitDestroyed)
    finally:
        channel.close()
