"""A circuit: an onion-encrypted path through a sequence of relays.

The client builds the first hop with CREATE2 and each further hop with an
EXTEND2 carried in a RELAY_EARLY cell, running an ntor handshake per hop. Sending
a relay cell stamps the target hop's forward digest and wraps the cell in each
hop's forward cipher; a received cell is unwrapped hop by hop until one is
recognized. The circuit is the receiver thread's sink for its circuit id.

Concurrency: forward crypto and cell ordering are serialized by ``_tx_lock``;
backward crypto runs only on the receiver thread; the stream and waiter registry
is guarded by ``_registry_lock`` and never held across I/O. A blocking send waits
on the package window *before* taking ``_tx_lock``, so the receiver can always
refill it.
"""

from __future__ import annotations

import contextlib
import threading
from typing import Protocol

from .._proto.cells import Create2Cell, Created2Cell, DestroyCell, RawCell
from .._proto.constants import (
    CIRCUIT_WINDOW_INCREMENT,
    CIRCUIT_WINDOW_INITIAL,
    Cell,
    HandshakeType,
    Relay,
)
from .._proto.handshake import NtorHandshake
from .._proto.relay import (
    Extended2,
    RelayCell,
    extend2_body,
    parse_sendme_v1,
    sendme_v1_body,
)
from .._proto.relay_crypto import RelayCrypto
from ..exceptions import ChannelError, CircuitBuildTimeout, CircuitDestroyed, CircuitError
from .channel import Channel
from .flowcontrol import DeliverCounter, PackageWindow, SendmeTracker
from .hop import CircuitHop, RelayInfo

_DEFAULT_TIMEOUT = 60.0


class StreamHandler(Protocol):
    """The slice of a stream the circuit routes cells to."""

    def handle_relay(self, cell: RelayCell) -> None: ...

    def on_circuit_closed(self, error: Exception | None) -> None: ...


class _Waiter:
    """A one-shot slot for a reply: build handshake data, or a control cell."""

    def __init__(self) -> None:
        self._event = threading.Event()
        self._result: object = None
        self._error: Exception | None = None

    def set_result(self, result: object) -> None:
        self._result = result
        self._event.set()

    def set_error(self, error: Exception) -> None:
        self._error = error
        self._event.set()

    def wait(self, timeout: float) -> object:
        if not self._event.wait(timeout):
            raise CircuitBuildTimeout("timed out waiting for a reply")
        if self._error is not None:
            raise self._error
        return self._result


class RelayFuture:
    """A pending control-cell reply that a caller blocks on."""

    def __init__(self, waiter: _Waiter, default_timeout: float) -> None:
        self._waiter = waiter
        self._default_timeout = default_timeout

    def result(self, timeout: float | None = None) -> RelayCell:
        cell = self._waiter.wait(timeout if timeout is not None else self._default_timeout)
        if not isinstance(cell, RelayCell):
            raise CircuitError("unexpected control-cell reply")
        return cell


class Circuit:
    """One onion-encrypted circuit over a channel."""

    def __init__(
        self,
        channel: Channel,
        circ_id: int,
        *,
        timeout: float = _DEFAULT_TIMEOUT,
        close_when_idle: bool = False,
    ) -> None:
        self.channel = channel
        self.circ_id = circ_id
        self.hops: list[CircuitHop] = []
        self._timeout = timeout
        # An unpooled (single-request) circuit tears itself down once its last
        # stream ends, so it does not linger until the client closes.
        self._close_when_idle = close_when_idle
        self._tx_lock = threading.Lock()
        self._registry_lock = threading.Lock()
        self._streams: dict[int, StreamHandler] = {}
        self._build_waiter: _Waiter | None = None
        self._relay_waiters: dict[int, _Waiter] = {}
        self._next_stream_id = 0
        self._destroyed = False
        self._error: Exception | None = None
        self._package_window = PackageWindow(CIRCUIT_WINDOW_INITIAL, CIRCUIT_WINDOW_INCREMENT)
        self._deliver = DeliverCounter(CIRCUIT_WINDOW_INCREMENT)
        self._sendme_tracker = SendmeTracker(CIRCUIT_WINDOW_INCREMENT)

    # --- building ---------------------------------------------------------- #

    def create(self, relay: RelayInfo) -> None:
        """Build the first hop with an ntor CREATE2."""
        handshake = NtorHandshake(relay.ntor_onion_key, relay.identity_digest)
        waiter = self._arm_build_waiter()
        self.channel.send_cell(
            Create2Cell(HandshakeType.NTOR, handshake.create_onion_skin()).to_raw(self.circ_id)
        )
        key_material = handshake.complete(self._build_reply(waiter))
        self.hops.append(CircuitHop(relay, RelayCrypto.tor1(key_material)))

    def extend(self, relay: RelayInfo) -> None:
        """Extend the circuit one more hop with an ntor EXTEND2."""
        if not self.hops:
            raise CircuitError("cannot extend a circuit with no first hop")
        handshake = NtorHandshake(relay.ntor_onion_key, relay.identity_digest)
        body = extend2_body(
            relay.link_specifiers(), HandshakeType.NTOR, handshake.create_onion_skin()
        )
        waiter = self._arm_build_waiter()
        self._send_relay(RelayCell(Relay.EXTEND2, 0, body), early=True)
        key_material = handshake.complete(Extended2.parse(self._build_reply(waiter)).handshake_data)
        self.hops.append(CircuitHop(relay, RelayCrypto.tor1(key_material)))

    def add_virtual_hop(self, crypto: RelayCrypto, relay: RelayInfo) -> None:
        """Install a hop whose keys came from a rendezvous handshake, not a CREATE.

        The onion service is spliced onto the circuit at the rendezvous point; no
        CREATE/EXTEND cell is sent for it.
        """
        self.hops.append(CircuitHop(relay, crypto))

    def _build_reply(self, waiter: _Waiter) -> bytes:
        reply = waiter.wait(self._timeout)
        if not isinstance(reply, (bytes, bytearray)):
            raise CircuitError("unexpected build reply")
        return bytes(reply)

    def _arm_build_waiter(self) -> _Waiter:
        waiter = _Waiter()
        with self._registry_lock:
            if self._destroyed:
                raise self._error or CircuitDestroyed("circuit is closed")
            self._build_waiter = waiter
        return waiter

    def arm_relay(self, command: int) -> RelayFuture:
        """Register a one-shot waiter for a control relay command.

        Arming before sending the request that triggers the reply avoids missing a
        reply that races back. Used for the onion-service control cells
        (RENDEZVOUS_ESTABLISHED, INTRODUCE_ACK, RENDEZVOUS2).
        """
        waiter = _Waiter()
        with self._registry_lock:
            if self._destroyed:
                raise self._error or CircuitDestroyed("circuit is closed")
            self._relay_waiters[command] = waiter
        return RelayFuture(waiter, self._timeout)

    # --- streams ----------------------------------------------------------- #

    def next_stream_id(self) -> int:
        with self._registry_lock:
            self._next_stream_id = (self._next_stream_id % 0xFFFF) + 1
            return self._next_stream_id

    def register_stream(self, stream_id: int, handler: StreamHandler) -> None:
        with self._registry_lock:
            if self._destroyed:
                raise self._error or CircuitDestroyed("circuit is closed")
            self._streams[stream_id] = handler

    def unregister_stream(self, stream_id: int) -> None:
        with self._registry_lock:
            self._streams.pop(stream_id, None)
            idle = self._close_when_idle and not self._streams
        if idle:
            self.close()

    # --- sending ----------------------------------------------------------- #

    def send_relay(self, cell: RelayCell, *, is_data: bool = False) -> None:
        """Send an application relay cell to the last hop."""
        if is_data:
            self._package_window.consume(self._timeout)
        self._send_relay(cell, count_data=is_data)

    def _send_relay(
        self, cell: RelayCell, *, early: bool = False, count_data: bool = False
    ) -> None:
        target = len(self.hops) - 1
        with self._tx_lock:
            if self._destroyed:
                raise self._error or CircuitDestroyed("circuit is closed")
            stamped = self.hops[target].crypto.stamp_forward(cell)
            if count_data:
                # Remember the forward running digest of every DATA cell so an
                # incoming circuit SENDME can be authenticated against the exact
                # cell that triggered it (tor-spec, flow control / proposal 289).
                # Captured under _tx_lock, immediately after stamping, so the
                # value recorded is the digest of precisely this cell.
                self._sendme_tracker.note_sent(self.hops[target].crypto.forward_digest())
            body = stamped.pack()
            for hop in reversed(self.hops[: target + 1]):
                body = hop.crypto.apply_forward_cipher(body)
            command = Cell.RELAY_EARLY if early else Cell.RELAY
            self.channel.send_cell(RawCell(self.circ_id, command, body))

    # --- receiving (runs on the channel receiver thread) ------------------- #

    def handle_cell(self, cell: RawCell) -> None:
        if cell.command == Cell.DESTROY:
            self._teardown(CircuitDestroyed(f"circuit {self.circ_id:#x} destroyed by relay"))
            return
        if cell.command == Cell.CREATED2:
            self._fire_build(Created2Cell.from_raw(cell).handshake_data)
            return
        if cell.command in (Cell.RELAY, Cell.RELAY_EARLY):
            self._handle_relay(cell)

    def _handle_relay(self, cell: RawCell) -> None:
        body = cell.payload
        for index, hop in enumerate(self.hops):
            body = hop.crypto.apply_backward_cipher(body)
            recognized = hop.crypto.recognize_backward(body)
            if recognized is not None:
                self._route_relay(recognized, index)
                return
        self._teardown(CircuitError("received an unrecognized relay cell"))

    def _route_relay(self, cell: RelayCell, origin_hop: int) -> None:
        if cell.command == Relay.EXTENDED2:
            self._fire_build(cell.data)
            return
        if cell.command == Relay.SENDME and cell.stream_id == 0:
            self._handle_circuit_sendme(cell)
            return
        with self._registry_lock:
            control_waiter = self._relay_waiters.pop(cell.command, None)
        if control_waiter is not None:
            control_waiter.set_result(cell)
            return
        # Circuit-level deliver accounting must count every DATA cell, even for a
        # stream that has since closed: the relay decremented its window when it
        # sent the cell, so a missed SENDME permanently shrinks the window and
        # eventually wedges the (reused) circuit.
        if cell.command == Relay.DATA and self._deliver.note_received():
            self._emit_circuit_sendme(origin_hop)
        with self._registry_lock:
            stream = self._streams.get(cell.stream_id)
        if stream is not None:
            stream.handle_relay(cell)

    def _handle_circuit_sendme(self, cell: RelayCell) -> None:
        """Authenticate an incoming circuit SENDME before advancing the window.

        A v1 SENDME must carry the running digest of a DATA cell we actually
        sent at a window-increment boundary; otherwise a relay could forge
        SENDMEs to inflate our send window. tor-spec (flow control): "on failure
        to match, the circuit should be torn down".
        """
        try:
            digest = parse_sendme_v1(cell.data)
        except ValueError as exc:
            self._teardown(CircuitError(f"malformed circuit SENDME: {exc}"))
            return
        if not self._sendme_tracker.verify(digest):
            self._teardown(CircuitError("circuit SENDME failed authentication"))
            return
        self._package_window.refill()

    def _emit_circuit_sendme(self, origin_hop: int) -> None:
        digest = self.hops[origin_hop].crypto.backward_digest()[:20]
        # Runs on the receiver thread; a send-after-close must not kill the channel.
        with contextlib.suppress(CircuitError, ChannelError):
            self._send_relay(RelayCell(Relay.SENDME, 0, sendme_v1_body(digest)))

    def emit_stream_sendme(self, stream_id: int) -> None:
        """Emit a stream-level SENDME (unauthenticated, empty body)."""
        with contextlib.suppress(CircuitError, ChannelError):
            self._send_relay(RelayCell(Relay.SENDME, stream_id, b""))

    def _fire_build(self, data: bytes) -> None:
        with self._registry_lock:
            waiter, self._build_waiter = self._build_waiter, None
        if waiter is not None:
            waiter.set_result(data)

    # --- teardown ---------------------------------------------------------- #

    def on_channel_closed(self, error: Exception | None) -> None:
        self._teardown(error or CircuitDestroyed("channel closed"))

    def _teardown(self, error: Exception) -> None:
        with self._registry_lock:
            if self._destroyed:
                return
            self._destroyed = True
            self._error = error
            waiter, self._build_waiter = self._build_waiter, None
            relay_waiters = list(self._relay_waiters.values())
            self._relay_waiters.clear()
            streams = list(self._streams.values())
            self._streams.clear()
        if waiter is not None:
            waiter.set_error(error)
        for relay_waiter in relay_waiters:
            relay_waiter.set_error(error)
        self._package_window.close()
        for stream in streams:
            stream.on_circuit_closed(error)

    @property
    def destroyed(self) -> bool:
        return self._destroyed

    def close(self) -> None:
        """Send a DESTROY, tear down local state, and deregister from the channel."""
        if not self._destroyed:
            with self._tx_lock, contextlib.suppress(ChannelError):
                self.channel.send_cell(DestroyCell(reason=0).to_raw(self.circ_id))
        self._teardown(CircuitDestroyed("circuit closed by client"))
        self.channel.unregister(self.circ_id)


def build_circuit(
    channel: Channel,
    path: list[RelayInfo],
    *,
    timeout: float = _DEFAULT_TIMEOUT,
    close_when_idle: bool = False,
) -> Circuit:
    """Allocate, register, and build a circuit along ``path``."""
    circ_id = channel.new_circuit_id()
    circuit = Circuit(channel, circ_id, timeout=timeout, close_when_idle=close_when_idle)
    channel.register(circ_id, circuit)
    try:
        circuit.create(path[0])
        for relay in path[1:]:
            circuit.extend(relay)
    except BaseException:
        circuit.close()
        raise
    return circuit
